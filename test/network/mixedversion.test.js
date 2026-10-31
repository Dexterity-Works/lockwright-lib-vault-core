import crypto from 'crypto'

import { NetworkGuardError, reset, violations } from './guard.cjs'
import {
  RELEASED,
  converge,
  createNetwork,
  hasRelease,
  reconciled,
  shareVault,
  waitFor
} from './harness.js'
import release from './release.cjs'

// The released vault-core (RELEASED, the build the shipped apps run) beside
// the epoch re-key build, on one private testnet. FINDINGS-mixed-version.md
// sums up what these show. Every expectation below is what the code did
// when this file was written, including the ones that are bad news.
// Without a release tree (DEPS.md, "Mixed-version peers") the file skips.
const suite = hasRelease() ? describe : describe.skip

const login = (updatedAt, title = 'Login', password = 'p1') => ({
  id: 'r1',
  type: 'login',
  updatedAt,
  data: { title, username: 'u', password, websites: ['https://a.test'] }
})

const sealedLogin = {
  id: 's1',
  type: 'login',
  schema: 2,
  updatedAt: 5,
  data: {
    title: 'Sealed',
    password: 'sp',
    websites: ['https://s.test'],
    uris: [{ uri: 'https://s.test', match: 'exact' }]
  }
}

const noteEdit = {
  id: 'r2',
  type: 'note',
  updatedAt: 6,
  data: { title: 'Secure note', note: 'n2 edited on B' }
}

/** What a device holds before anyone starts an epoch: a v1 login with a file, a v2 note, a plain note. */
const fill = async (peer, file) => {
  await peer.add('record/r1', login(1))
  await peer.add('record-v2/r2', {
    id: 'r2',
    type: 'note',
    schema: 2,
    updatedAt: 1,
    data: { title: 'Secure note', note: 'n2' }
  })
  await peer.add('record/r1/file/f1', { name: 'f1.bin' }, file, 'f1.bin')
  await peer.add('note/1', { text: 'first' })
}

/** The items `fill` wrote, read the way this peer's build reads them. */
const readFilled = async (peer) => ({
  r1: await peer.get('record/r1'),
  r2: await peer.get('record-v2/r2'),
  note: await peer.get('note/1'),
  file: Buffer.from((await peer.getFile('record/r1/file/f1')) ?? []),
  fileV2: Buffer.from((await peer.getFile('record-v2/r1/file/f1')) ?? []),
  ids: (await peer.list('record/')).map((r) => r.id).sort()
})

const isSealed = (raw) => '$enc' in JSON.parse(raw.value)

/** Released-build errors from its own logger, which swallows reconcile failures. */
const watchErrors = (peer) => {
  const errors = []
  const { workletLogger } = peer.modules.logger
  const error = workletLogger.error.bind(workletLogger)
  workletLogger.error = (message, ...rest) => {
    errors.push(String(message))
    peer.trace('log.error', { message: String(message) })
    return error(message, ...rest)
  }
  return errors
}

const phase = (net, name) => net.list[0].trace('phase', { name })

/**
 * Hold every Autopass add of `key` on `peer` until release(): a slow device
 * whose append lands later than its neighbours'. Test-side, on the same
 * Autopass instance methods the tracer and ReleasePeer wrap.
 */
const holdAdds = (peer, key) => {
  const instance = peer.instance
  const add = instance.add.bind(instance)
  let open
  let reach
  const gate = new Promise((resolve) => (open = resolve))
  const reached = new Promise((resolve) => (reach = resolve))
  instance.add = async (k, ...rest) => {
    if (k === key) {
      peer.trace('test.hold', { key })
      reach()
      await gate
    }
    return add(k, ...rest)
  }
  return {
    reached,
    release: () => {
      peer.trace('test.release', { key })
      open()
    }
  }
}

/** The raw row under `key` on `peer`, parsed, or null. */
const rawJson = async (peer, key) => {
  const raw = await peer.raw(key)
  return raw ? JSON.parse(raw.value) : null
}

suite(`mixed versions: ${RELEASED} beside the epoch re-key build`, () => {
  let net = null

  afterEach(async () => {
    await net?.destroy()
    net = null
  })

  test("the released build's own hyperdht is behind the guard", () => {
    // jest.isolateModules is not needed: the guard wraps the class itself.
    const HyperDHT = require(release.locateRelease().paths.hyperdht)
    expect(HyperDHT.name).toBe('GuardedHyperDHT')
    expect(() => new HyperDHT()).toThrow(NetworkGuardError)
    expect(violations()).toHaveLength(1)
    reset()
  })

  test('upgrade: a vault the released build filled opens intact on the re-key build', async () => {
    net = await createNetwork({ peers: ['A'], builds: { A: RELEASED } })
    let { A } = net.peers
    expect(A.appDeps.activeVaultEnsureEpoch).toBeUndefined()
    await A.createVault({ id: 'v' })
    const file = crypto.randomBytes(4096)
    await fill(A, file)
    const before = await readFilled(A)
    expect(before.r1).toMatchObject({ data: { password: 'p1' }, schema: 2 })
    expect(before.file.equals(file)).toBe(true)
    expect(before.ids).toEqual(['r1', 'r2'])

    phase(net, 'upgrade A')
    A = await net.swap('A')
    expect(A.appDeps.activeVaultEnsureEpoch).toBeDefined()
    expect(await readFilled(A)).toEqual(before)
    // The released build had already moved the vault to schema 2, so the
    // re-key build's migration has nothing to do and finishes at once.
    expect(A.appDeps.getVaultMigrationStatus()).toMatchObject({
      ready: true,
      inProgress: false,
      deferred: false,
      migratedToSchema: 2,
      error: null,
      lastResult: { alreadyMigrated: true, complete: true }
    })
    expect(await A.epochStatus()).toMatchObject({ legacy: true, canRead: true })

    // The released build wrote A's device row unsigned. On open the re-key
    // build signs it again, after which the row binds.
    const bound = await waitFor(
      async () => {
        const status = await A.epochStatus()
        return status.uncovered.length === 0 ? status : false
      },
      { label: "A's own row binds" }
    )
    expect(bound).toMatchObject({ legacy: true, uncovered: [] })
    expect(JSON.parse((await A.raw('device/device-A')).value)).toMatchObject({
      id: 'device-A',
      sig: expect.any(String)
    })

    const started = await A.ensureEpoch({ start: true })
    expect(started).toMatchObject({ rotated: true, members: ['device-A'] })
    // Starting an epoch seals new writes only. Rows the released build
    // wrote stay plaintext and read as before.
    expect(await readFilled(A)).toEqual(before)
    expect(isSealed(await A.raw('note/1'))).toBe(false)
    await A.add('note/2', { text: 'sealed' })
    expect(isSealed(await A.raw('note/2'))).toBe(true)
    expect(await A.get('note/2')).toEqual({ text: 'sealed' })
  })

  test('upgrade: an epoch start while the open-time re-sign is in flight is refused, then heals', async () => {
    net = await createNetwork({ peers: ['A'], builds: { A: RELEASED } })
    let { A } = net.peers
    await A.createVault({ id: 'v' })
    await A.add('note/1', { text: 'first' })
    A = await net.swap('A')

    // Called right after the vault opens, before the re-signed device row
    // has landed: the roster still holds the released build's unsigned row,
    // so A is not in it. The start is recorded as owed, and a write is
    // refused until the start goes through.
    expect(await A.ensureEpoch({ start: true })).toMatchObject({
      rotated: false,
      reason: 'self-not-in-roster'
    })
    await expect(A.add('note/2', { text: 'x' })).rejects.toThrow(
      'Vault key must rotate first'
    )
    // The re-signed row's own update runs the owed start.
    const healed = await waitFor(
      async () => {
        const status = await A.epochStatus()
        return !status.legacy && status.canRead ? status : false
      },
      { label: 'the owed start runs' }
    )
    expect(healed).toMatchObject({ seq: 1, members: ['device-A'] })
    await A.add('note/2', { text: 'x' })
    expect(await A.get('note/2')).toEqual({ text: 'x' })
    expect(await A.get('note/1')).toEqual({ text: 'first' })
  })

  test('mixed: one of two released devices upgrades; both keep every item and writes cross both ways', async () => {
    net = await createNetwork({
      peers: ['A', 'R'],
      builds: { A: RELEASED, R: RELEASED }
    })
    let { A } = net.peers
    const { R } = net.peers
    const rErrors = watchErrors(R)
    const file = crypto.randomBytes(4096)
    await A.createVault({ id: 'shared' })
    await fill(A, file)
    await R.pair(await A.invite())
    await waitFor(async () => (await R.devices()).length === 2, {
      label: 'R sees both device rows'
    })
    await waitFor(async () => (await R.getFile('record/r1/file/f1')) !== null, {
      label: 'R has the file'
    })
    const before = await readFilled(R)
    expect(before.file.equals(file)).toBe(true)
    const rowBefore = (await R.devices()).find((d) => d.id === 'device-A')

    phase(net, 'upgrade A')
    A = await net.swap('A')
    expect(await readFilled(A)).toEqual(before)
    expect(A.appDeps.getVaultMigrationStatus()).toMatchObject({
      ready: true,
      error: null
    })
    // A signs its own row again on open; R, still on the released build,
    // stays an unsigned row and is listed as uncovered.
    const status = await waitFor(
      async () => {
        const s = await A.epochStatus()
        return JSON.stringify(s.uncovered) === '["device-R"]' ? s : false
      },
      { label: "A's row binds, R's does not" }
    )
    expect(status).toMatchObject({ legacy: true, canRead: true })

    // What R sees of that: A's row with the same identity plus a signature.
    const rowAfter = await waitFor(
      async () => {
        const row = (await R.devices()).find((d) => d.id === 'device-A')
        return row?.sig ? row : false
      },
      { label: "R holds A's re-signed row" }
    )
    expect(rowAfter).toMatchObject({
      id: rowBefore.id,
      writerKey: rowBefore.writerKey,
      masterTopic: rowBefore.masterTopic,
      writerPublicKey: expect.any(String)
    })
    const writes = R.writes.length
    await reconciled(R)
    expect(R.writes.slice(writes)).toEqual([])
    expect(await readFilled(R)).toEqual(before)

    // No epoch yet, so both builds write plaintext and read each other.
    await A.add('note/a', { text: 'from the re-key build' })
    await R.add('note/r', { text: 'from the released build' })
    expect(await converge([A, R], 'note/a')).toEqual({
      text: 'from the re-key build'
    })
    expect(await converge([A, R], 'note/r')).toEqual({
      text: 'from the released build'
    })
    expect(isSealed(await R.raw('note/a'))).toBe(false)
    expect(rErrors).toEqual([])
  })

  test('mixed: an epoch started on the re-key build leaves the released device out until it upgrades', async () => {
    net = await createNetwork({
      peers: ['R', 'B', 'C'],
      builds: { R: RELEASED }
    })
    let { R } = net.peers
    const { B, C } = net.peers
    const rErrors = watchErrors(R)
    const file = crypto.randomBytes(4096)
    await shareVault(net)
    // R is the released code on the testnet, behind the guard.
    expect(R.instance.constructor.name).toBe('ReleasedAutopass')
    expect(R.instance.swarm.constructor.name).toBe('GuardedHyperswarm')
    const hostPort = ({ host, port }) => ({ host, port })
    expect(R.instance.swarm.dht.bootstrapNodes.map(hostPort)).toEqual(
      net.bootstrap.map(hostPort)
    )
    await fill(R, file)
    await converge(net.list, 'note/1')
    for (const peer of [B, C]) {
      await waitFor(
        async () => (await peer.getFile('record/r1/file/f1')) !== null,
        { label: `${peer.id} has the file` }
      )
    }
    const before = await readFilled(R)
    expect(await readFilled(B)).toEqual(before)

    phase(net, 'B starts an epoch')
    // R's row is unsigned (the released build never signs), so the epoch
    // is sealed to B and C only and R is reported as uncovered.
    const first = await B.ensureEpoch({ start: true })
    expect(first).toMatchObject({
      rotated: true,
      members: ['device-B', 'device-C'],
      uncovered: ['device-R']
    })
    await waitFor(
      async () => {
        const s = await C.epochStatus()
        return s.epoch === first.id && s.canRead
      },
      { label: 'C holds the epoch' }
    )

    // B writes the new record and file through their v2 keys and edits the
    // old note through its v1 key. Either way the twin R could read a
    // gap in lands after a row R's reconcile skips, so R has nothing to
    // copy; the next test covers the order where it does.
    const sealedFile = crypto.randomBytes(2048)
    await B.add('record-v2/s1', sealedLogin)
    await B.add(
      'record-v2/s1/file/g1',
      { name: 'g1.bin' },
      sealedFile,
      'g1.bin'
    )
    await B.add('note/s', { text: 'sealed note' })
    await B.add('record/r2', noteEdit)
    // B's last append; B's log reaches R in order.
    await waitFor(async () => isSealed(await R.raw('record-v2/r2')), {
      label: 'R holds the sealed rows'
    })
    const writes = R.writes.length
    await reconciled(R)

    // R's reconcile over the epoch row and the sealed rows wrote nothing.
    expect(R.writes.slice(writes)).toEqual([])
    // R reads what nobody edited since the epoch as before.
    const after = await readFilled(R)
    for (const field of ['r1', 'note', 'file', 'fileV2']) {
      expect(after[field]).toEqual(before[field])
    }
    // R cannot read what B sealed, the old note B edited included. It does
    // not fail either: the released build hands the envelope out as if it
    // were the value, the record list gets an entry with no id for each,
    // and the file comes back as ciphertext.
    const envelope = {
      $enc: 1,
      e: first.id,
      n: expect.any(String),
      c: expect.any(String)
    }
    expect(after.r2).toEqual(envelope)
    expect(await R.get('record/s1')).toEqual(envelope)
    expect(await R.get('note/s')).toEqual(envelope)
    const listed = await R.list('record/')
    expect(listed.map((r) => r.id)).toEqual(['r1', undefined, undefined])
    expect(listed.slice(1)).toEqual([
      expect.objectContaining({ $enc: 1, e: first.id }),
      expect.objectContaining({ $enc: 1, e: first.id })
    ])
    expect(JSON.stringify(listed)).not.toContain('Sealed')
    const cipher = Buffer.from(await R.getFile('record-v2/s1/file/g1'))
    expect(cipher.equals(sealedFile)).toBe(false)
    expect(cipher.includes(sealedFile.subarray(0, 64))).toBe(false)

    phase(net, 'R writes after the epoch')
    // R still writes, in plaintext, and B and C read it.
    await R.add('note/r', { text: 'from the released build' })
    await R.add('record/r1', login(9, 'Edited on R', 'p9'))
    expect(await converge(net.list, 'note/r')).toEqual({
      text: 'from the released build'
    })
    for (const peer of [B, C]) {
      const r1 = await waitFor(
        async () => {
          const record = await peer.get('record/r1')
          return record?.updatedAt === 9 ? record : false
        },
        { label: `${peer.id} sees R's edit` }
      )
      expect(r1).toMatchObject({
        data: { title: 'Edited on R', password: 'p9' }
      })
      // R's own rows are plaintext. The v2 twin of its edit may be B's or
      // C's sealed one instead; the next test covers that.
      expect(isSealed(await peer.raw('note/r'))).toBe(false)
      expect(isSealed(await peer.raw('record/r1'))).toBe(false)
    }

    // Sync between the re-key devices goes on, and the sealed items still
    // read in full there.
    await B.add('note/after', { text: 'after R wrote' })
    expect(await converge([B, C], 'note/after')).toEqual({
      text: 'after R wrote'
    })
    for (const peer of [B, C]) {
      expect(await peer.get('record/s1')).toEqual(sealedLogin)
      expect(await peer.get('record-v2/r2')).toMatchObject(noteEdit)
      expect(await peer.get('note/s')).toEqual({ text: 'sealed note' })
      for (const key of ['record-v2/s1/file/g1', 'record/s1/file/g1']) {
        const bytes = await waitFor(() => peer.getFile(key), {
          label: `${peer.id} has ${key}`
        })
        expect(Buffer.from(bytes).equals(sealedFile)).toBe(true)
      }
      expect(await peer.get('note/1')).toEqual({ text: 'first' })
    }
    expect(rErrors).toEqual([])

    phase(net, 'R upgrades')
    // Once R runs the re-key build its row is signed, B or C rotate to an
    // epoch that includes it, and R reads everything.
    R = await net.swap('R')
    const joined = await waitFor(
      async () => {
        const s = await R.epochStatus()
        return s.canRead && s.members.includes('device-R') ? s : false
      },
      { label: 'R joins the epoch' }
    )
    expect(joined).toMatchObject({
      legacy: false,
      members: ['device-B', 'device-C', 'device-R'],
      uncovered: []
    })
    expect(joined.seq).toBeGreaterThan(first.seq)
    expect(await R.get('record/s1')).toEqual(sealedLogin)
    expect(await R.get('record-v2/r2')).toMatchObject(noteEdit)
    expect(
      Buffer.from(await R.getFile('record-v2/s1/file/g1')).equals(sealedFile)
    ).toBe(true)
    expect(await R.get('note/s')).toEqual({ text: 'sealed note' })
    expect(await R.get('record/r1')).toMatchObject({ updatedAt: 9 })
    expect((await R.list('record/')).map((r) => r.id).sort()).toEqual([
      'r1',
      'r2',
      's1'
    ])
    expect(R.appDeps.getVaultMigrationStatus()).toMatchObject({
      ready: true,
      error: null
    })
  })

  test('mixed: when one twin of a record lands late, the other build writes it', async () => {
    // Two devices only, so the one twin the re-key build writes is B's.
    net = await createNetwork({ peers: ['R', 'B'], builds: { R: RELEASED } })
    const { R, B } = net.peers
    const rErrors = watchErrors(R)
    await shareVault(net)
    await R.add('record/r1', login(1))
    await waitFor(async () => (await B.get('record/r1'))?.schema === 2, {
      label: 'B reads r1'
    })
    const first = await B.ensureEpoch({ start: true })
    expect(first).toMatchObject({ rotated: true, members: ['device-B'] })
    const login1 = { ...login(5, 'Sealed'), id: 's1' }
    const login2 = { ...login(5, 'Sealed too'), id: 's2' }
    // What B reads once R's copy is the v2 row: the v1 row's content,
    // without `schema` and `uris`.
    const asV1 = (record) => ({ ...record, data: { ...record.data } })
    // B's own twin, converted from the v1 row it wrote.
    const asV2 = (record) => ({
      ...record,
      schema: 2,
      data: {
        ...record.data,
        uris: [{ uri: 'https://a.test', match: 'baseDomain' }]
      }
    })
    // R's copy: the v1 envelope, plus what convertV1RecordToV2 adds.
    const copy = {
      $enc: 1,
      e: first.id,
      n: expect.any(String),
      c: expect.any(String),
      schema: 2,
      data: {}
    }

    phase(net, "R's copy lands first")
    // B writes the v1 row, and its v2 twin is slow. R's reconcile meets a
    // v1 record with no v2 twin and writes one: the v1 row's envelope,
    // with `schema: 2` and an empty `data`, as a plaintext row. It holds
    // ciphertext only.
    const slowB = holdAdds(B, 'record-v2/s1')
    const writing = B.add('record/s1', login1)
    await slowB.reached
    await waitFor(() => R.raw('record/s1'), { label: 'R holds record/s1' })
    let writes = R.writes.length
    await reconciled(R)
    expect(R.writes.slice(writes)).toEqual([{ op: 'add', key: 'record-v2/s1' }])
    expect(await rawJson(R, 'record-v2/s1')).toEqual(copy)
    // B reads the copy as the v1 row's content.
    await waitFor(async () => (await rawJson(B, 'record-v2/s1'))?.schema, {
      label: "B holds R's copy"
    })
    expect(await B.get('record/s1')).toEqual(asV1(login1))
    // B's twin, appended after it holds R's copy, is ordered after it and
    // wins: nothing is lost.
    slowB.release()
    await writing
    const healed = await waitFor(
      async () => {
        const record = await R.raw('record-v2/s1')
        return record && isSealed(record) && !JSON.parse(record.value).data
      },
      { label: "R holds B's twin" }
    )
    expect(healed).toBe(true)
    expect(await B.get('record/s1')).toEqual(asV2(login1))

    phase(net, "R's copy lands last")
    // Same start, but R's append is slow too and lands after B's twin, so
    // R's copy is the v2 row on both devices, and B reads the record
    // without `schema` and `uris`. Neither build's reconcile repairs it:
    // both rows carry the same updatedAt, so mergeV1IntoV2 leaves them.
    const slowB2 = holdAdds(B, 'record-v2/s2')
    const slowR = holdAdds(R, 'record-v2/s2')
    const writing2 = B.add('record/s2', login2)
    await slowB2.reached
    await waitFor(() => R.raw('record/s2'), { label: 'R holds record/s2' })
    writes = R.writes.length
    const reconciling = reconciled(R)
    await slowR.reached
    slowB2.release()
    await writing2
    await waitFor(async () => isSealed(await R.raw('record-v2/s2')), {
      label: "R holds B's twin"
    })
    slowR.release()
    await reconciling
    expect(R.writes.slice(writes)).toEqual([{ op: 'add', key: 'record-v2/s2' }])
    for (const peer of [R, B]) {
      await waitFor(async () => (await rawJson(peer, 'record-v2/s2'))?.schema, {
        label: `${peer.id} holds R's copy as the v2 row`
      })
      expect(await rawJson(peer, 'record-v2/s2')).toEqual(copy)
    }
    expect(await B.get('record/s2')).toEqual(asV1(login2))
    expect((await B.list('record/')).find((r) => r.id === 's2')).toEqual(
      asV1(login2)
    )
    // The next save of the record on a re-key build writes a proper v2 row
    // again: its merge sets `schema` and derives `uris`.
    const saved = { ...login2, updatedAt: 6 }
    await B.add('record/s2', saved)
    expect(await B.get('record/s2')).toEqual(asV2(saved))

    phase(net, "B's reconcile seals R's edit")
    // R edits an old record through its v1 key while its v2 twin is slow.
    // B's reconcile meets the newer v1 row and writes the merged v2 twin,
    // sealed. When that lands after R's plaintext twin it is the v2 row,
    // and R cannot read its own edit any more. B can.
    const edit = login(9, 'Edited on R', 'p9')
    const slowR2 = holdAdds(R, 'record-v2/r1')
    const slowB3 = holdAdds(B, 'record-v2/r1')
    const editing = R.add('record/r1', edit)
    await slowR2.reached
    await slowB3.reached
    slowR2.release()
    await editing
    await waitFor(
      async () => (await rawJson(B, 'record-v2/r1'))?.updatedAt === 9,
      { label: "B holds R's plaintext twin" }
    )
    slowB3.release()
    await waitFor(async () => isSealed(await R.raw('record-v2/r1')), {
      label: "R holds B's sealed twin"
    })
    expect(await R.get('record/r1')).toEqual({
      $enc: 1,
      e: first.id,
      n: expect.any(String),
      c: expect.any(String)
    })
    expect(JSON.parse((await R.raw('record/r1')).value)).toEqual(edit)
    expect(await B.get('record/r1')).toMatchObject({
      updatedAt: 9,
      schema: 2,
      data: { title: 'Edited on R', password: 'p9' }
    })
    expect(rErrors).toEqual([])
  })

  test('rollback: the released build reopens a vault the re-key build sealed', async () => {
    net = await createNetwork({ peers: ['A'] })
    let { A } = net.peers
    await A.createVault({ id: 'v' })
    const file = crypto.randomBytes(4096)
    await fill(A, file)
    const before = await readFilled(A)
    const epoch = await A.ensureEpoch({ start: true })
    expect(epoch).toMatchObject({ rotated: true, members: ['device-A'] })
    const sealedFile = crypto.randomBytes(2048)
    await A.add('record/s1', {
      id: 's1',
      type: 'login',
      updatedAt: 5,
      data: { title: 'Sealed', password: 'sp', websites: [] }
    })
    await A.add('record/s1/file/g1', { name: 'g1.bin' }, sealedFile, 'g1.bin')
    await A.add('note/s', { text: 'sealed note' })

    phase(net, 'roll A back')
    A = await net.swap('A', RELEASED)
    const errors = watchErrors(A)
    // The released migration reads vault-ext, which stays plaintext, and
    // finds the vault already at schema 2.
    expect(A.appDeps.getVaultMigrationStatus()).toMatchObject({
      ready: true,
      migratedToSchema: 2,
      error: null,
      lastResult: { alreadyMigrated: true }
    })
    await reconciled(A)
    expect(A.writes).toEqual([])
    // Items from before the epoch read as before; sealed ones come back as
    // their envelopes, and the sealed file as ciphertext.
    const rolled = await readFilled(A)
    expect({ ...rolled, ids: before.ids }).toEqual(before)
    expect(rolled.ids).toEqual(['r1', 'r2', undefined])
    const envelope = {
      $enc: 1,
      e: epoch.id,
      n: expect.any(String),
      c: expect.any(String)
    }
    expect(await A.get('record/s1')).toEqual(envelope)
    expect(await A.get('note/s')).toEqual(envelope)
    const cipher = Buffer.from(await A.getFile('record/s1/file/g1'))
    expect(cipher.equals(sealedFile)).toBe(false)

    // Writes on the released build land in plaintext.
    await A.add('note/rb', { text: 'written after the rollback' })
    await A.add('record/r1', login(9, 'Edited after the rollback', 'p9'))
    expect(isSealed(await A.raw('note/rb'))).toBe(false)
    expect(errors).toEqual([])

    phase(net, 'roll A forward again')
    A = await net.swap('A')
    // Nothing was lost: the epoch is the same, the sealed items read again,
    // and the rollback's plaintext writes read too.
    expect(await A.epochStatus()).toMatchObject({
      epoch: epoch.id,
      canRead: true,
      members: ['device-A']
    })
    expect(await A.get('record/s1')).toMatchObject({
      data: { title: 'Sealed', password: 'sp' }
    })
    expect(
      Buffer.from(await A.getFile('record/s1/file/g1')).equals(sealedFile)
    ).toBe(true)
    expect(await A.get('note/s')).toEqual({ text: 'sealed note' })
    expect(await A.get('note/rb')).toEqual({
      text: 'written after the rollback'
    })
    expect(await A.get('record/r1')).toMatchObject({
      updatedAt: 9,
      data: { title: 'Edited after the rollback', password: 'p9' }
    })
    expect(await A.get('record-v2/r2')).toEqual(before.r2)
    expect(Buffer.from(await A.getFile('record/r1/file/f1')).equals(file)).toBe(
      true
    )
    expect((await A.list('record/')).map((r) => r.id).sort()).toEqual([
      'r1',
      'r2',
      's1'
    ])
  })

  test('revoke: kicking a device on the released build needs no rotation and leaves it read-only', async () => {
    net = await createNetwork({
      peers: ['A', 'B', 'R'],
      builds: { R: RELEASED }
    })
    const { A, B, R } = net.peers
    await shareVault(net)
    await A.add('note/before', { text: 'everyone' })
    await converge(net.list, 'note/before')

    // The README's order: start the epoch, then remove the device.
    const first = await A.ensureEpoch({ start: true })
    expect(first).toMatchObject({
      rotated: true,
      members: ['device-A', 'device-B'],
      uncovered: ['device-R']
    })
    // R never held an epoch key, so the epoch already leaves it out and the
    // kick has nothing to rotate.
    expect(await A.kick('device-R')).toMatchObject({
      rotated: false,
      reason: 'current'
    })
    await A.add('note/after', { text: 'members only' })
    expect(await converge([A, B], 'note/after')).toEqual({
      text: 'members only'
    })

    await waitFor(() => R.instance.base.writable === false, {
      label: 'R learns its writer was removed'
    })
    await waitFor(() => R.raw('note/after'), { label: 'R holds note/after' })
    expect(await R.get('note/after')).toEqual({
      $enc: 1,
      e: first.id,
      n: expect.any(String),
      c: expect.any(String)
    })
    expect(await R.get('note/before')).toEqual({ text: 'everyone' })
    await expect(R.add('note/r', { text: 'after the kick' })).rejects.toThrow(
      'Not writable'
    )
    expect((await R.devices()).map((d) => d.id).sort()).toEqual([
      'device-A',
      'device-B'
    ])
    expect(await B.epochStatus()).toMatchObject({
      epoch: first.id,
      canRead: true,
      uncovered: []
    })
  })

  test('revoke: a device on the released build stays while a re-key device is kicked', async () => {
    net = await createNetwork({
      peers: ['A', 'R', 'C'],
      builds: { R: RELEASED }
    })
    const { A, R, C } = net.peers
    const rErrors = watchErrors(R)
    await shareVault(net)
    const first = await A.ensureEpoch({ start: true })
    expect(first).toMatchObject({
      members: ['device-A', 'device-C'],
      uncovered: ['device-R']
    })
    await waitFor(
      async () => {
        const s = await C.epochStatus()
        return s.epoch === first.id && s.canRead
      },
      { label: 'C holds the epoch' }
    )

    const kicked = await A.kick('device-C')
    expect(kicked).toMatchObject({
      rotated: true,
      members: ['device-A'],
      uncovered: ['device-R']
    })
    await waitFor(
      async () => {
        const s = await C.epochStatus()
        return s.revoked ? s : false
      },
      { label: 'C learns it was revoked' }
    )

    await A.add('note/after', { text: 'members only' })
    await waitFor(() => R.raw('note/after'), { label: 'R holds note/after' })
    expect(await R.get('note/after')).toMatchObject({ $enc: 1, e: kicked.id })

    // R's writes are plaintext, so the kicked device reads them as well as A.
    await R.add('note/r', { text: 'from the released build' })
    expect(await converge([A, R], 'note/r')).toEqual({
      text: 'from the released build'
    })
    const leaked = await waitFor(() => C.get('note/r'), {
      label: 'C holds note/r'
    })
    expect(leaked).toEqual({ text: 'from the released build' })
    expect(await C.get('note/after')).toBeNull()
    expect(rErrors).toEqual([])
  })
})
