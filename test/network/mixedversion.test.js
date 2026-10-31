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

/**
 * A wider vault for the upgrade: folders, a favourite, two files under both
 * file keys, an HOTP item (its code does not move with the clock), a
 * deleted record and a note. Records are saved through their v2 key, the
 * way lib-vault saves them, except r1, which an older app wrote as v1.
 */
const fillWide = async (peer, files) => {
  await peer.add('record/r1', {
    ...login(1),
    folder: 'Work',
    isFavorite: true,
    createdAt: 1
  })
  await peer.add('record/r1/file/f1', { name: 'f1.bin' }, files[0], 'f1.bin')
  await peer.add('record-v2/r1/file/f2', { name: 'f2.bin' }, files[1], 'f2.bin')
  await peer.add('record-v2/r2', {
    id: 'r2',
    type: 'note',
    schema: 2,
    updatedAt: 1,
    folder: 'Personal',
    data: { title: 'Secure note', note: 'n2' }
  })
  await peer.add('record-v2/o1', {
    id: 'o1',
    type: 'login',
    schema: 2,
    updatedAt: 1,
    data: {
      title: 'With OTP',
      username: 'o',
      websites: ['https://o.test'],
      uris: [{ uri: 'https://o.test', match: 'exact' }],
      otp: {
        type: 'HOTP',
        secret: 'JBSWY3DPEHPK3PXP',
        digits: 6,
        counter: 3,
        algorithm: 'SHA1',
        issuer: 'Test',
        label: 'o'
      }
    }
  })
  await peer.add('record-v2/d1', {
    id: 'd1',
    type: 'note',
    schema: 2,
    updatedAt: 1,
    data: { title: 'Deleted', note: 'gone' }
  })
  await peer.remove('record-v2/d1')
  await peer.add('note/1', { text: 'first' })
}

/** `after` equals `before` except `key`, which only gained a signature. */
const expectSameRowsBut = (after, before, key) => {
  const { [key]: rowAfter, ...restAfter } = after
  const { [key]: rowBefore, ...restBefore } = before
  expect(restAfter).toEqual(restBefore)
  const { sig, writerPublicKey, ...unsigned } = JSON.parse(rowAfter.value)
  expect(unsigned).toEqual(JSON.parse(rowBefore.value))
  expect(sig).toEqual(expect.any(String))
  expect(writerPublicKey).toEqual(expect.any(String))
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

/** Hold every `get` of `key` on `peer` until release(), like holdAdds. */
const holdGets = (peer, key) => {
  const instance = peer.instance
  const get = instance.get.bind(instance)
  let open
  const gate = new Promise((resolve) => (open = resolve))
  instance.get = async (k, ...rest) => {
    if (k === key) await gate
    return get(k, ...rest)
  }
  return {
    release: () => {
      peer.trace('test.release', { key })
      open()
    }
  }
}

/**
 * Count a current-build peer's reconciles the way ReleasePeer counts the
 * released build's, so harness reconciled() works on it. The current
 * runIncrementalReconcile also starts by reading `vault-ext` and calls
 * onUpdate when done; createNetwork's onUpdate below counts the end.
 */
const trackReconciles = (peer) => {
  peer.reconcile = { started: 0, done: 0, tracked: true }
  const instance = peer.instance
  const get = instance.get.bind(instance)
  instance.get = (key, ...rest) => {
    if (key === 'vault-ext') peer.reconcile.started++
    return get(key, ...rest)
  }
}
const countReconcile = (peer) => {
  if (peer.reconcile?.tracked) peer.reconcile.done++
}

const sha = (bytes) =>
  bytes ? crypto.createHash('sha256').update(bytes).digest('hex') : null

/** Every row of the active vault's view as stored: key -> value, file hash. */
const rawView = async (peer) => {
  const rows = {}
  for await (const row of peer.instance.base.view.find(
    '@autopass/records',
    {}
  )) {
    rows[row.key] = { value: row.value, file: sha(row.file) }
  }
  return rows
}

/** Every vault row read through this peer's build, as the app reads it. */
const readEverything = async (peer) => {
  const out = {}
  for (const key of Object.keys(await rawView(peer))) {
    if (key.startsWith('device/') || key.startsWith('epoch/')) continue
    out[key] = {
      value: await peer.get(key),
      file: sha(await peer.getFile(key))
    }
  }
  out['list record/'] = (await peer.list('record/')).sort((a, b) =>
    String(a.id).localeCompare(String(b.id))
  )
  out['list note/'] = await peer.list('note/')
  return out
}

/** lib-vault's startLegacyEpoch (src/utils/startLegacyEpoch.js:17-36). */
const startLegacyEpoch = async (peer, caller) => {
  const status = await peer.epochStatus()
  if (status.legacy !== true) return
  const started = await peer.ensureEpoch({ start: true })
  if (started?.rotated === true) return
  if ((await peer.epochStatus()).legacy === false) return
  throw new Error(
    `${caller}: cannot start the vault key: ${started?.reason ?? 'no result'}`
  )
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

  test('upgrade: two vaults the released build filled open intact on the re-key build', async () => {
    net = await createNetwork({ peers: ['A'], builds: { A: RELEASED } })
    let { A } = net.peers
    expect(A.appDeps.activeVaultEnsureEpoch).toBeUndefined()
    await A.createVault({ id: 'v' })
    const files = [crypto.randomBytes(4096), crypto.randomBytes(1024)]
    await fillWide(A, files)
    const v = { id: A.vaultId, encryptionKey: A.encryptionKey }
    const beforeV = { raw: await rawView(A), read: await readEverything(A) }
    expect(beforeV.raw['record-v2/d1']).toBeUndefined()
    expect(beforeV.raw['record/d1']).toBeUndefined()
    expect(beforeV.read['record/r1'].value).toMatchObject({
      folder: 'Work',
      isFavorite: true,
      schema: 2
    })
    expect(beforeV.read['record/r1/file/f1'].file).toBe(sha(files[0]))
    expect(beforeV.read['record-v2/r1/file/f2'].file).toBe(sha(files[1]))
    expect(beforeV.read['record-v2/o1'].value.otpPublic).toMatchObject({
      type: 'HOTP',
      currentCode: expect.any(String)
    })
    // A second vault, left active, as the app leaves whichever was last.
    await A.createVault({ id: 'w' })
    await A.add('record-v2/w1', {
      id: 'w1',
      type: 'login',
      schema: 2,
      updatedAt: 1,
      data: { title: 'Other vault', password: 'pw', websites: [], uris: [] }
    })
    await A.add('note/w', { text: 'second vault' })
    const beforeW = { raw: await rawView(A), read: await readEverything(A) }
    const vaults = await A.appDeps.vaultsList('vault/')
    expect(vaults.map((x) => x.id).sort()).toEqual(['v', 'w'])

    phase(net, 'upgrade A')
    A = await net.swap('A')
    expect(A.appDeps.activeVaultEnsureEpoch).toBeDefined()
    expect(await A.appDeps.vaultsList('vault/')).toEqual(vaults)
    for (const [vault, before] of [
      ['w', beforeW],
      ['v', beforeV]
    ]) {
      if (A.vaultId !== vault) {
        A.vaultId = v.id
        A.encryptionKey = v.encryptionKey
        await A.openVault()
      }
      expect(await readEverything(A)).toEqual(before.read)
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
      expect(await A.epochStatus()).toMatchObject({
        legacy: true,
        canRead: true
      })
      // The released build wrote A's device row unsigned. On open the
      // re-key build signs it again, after which the row binds. That is the
      // only row the upgrade changes.
      await waitFor(
        async () => (await A.epochStatus()).uncovered.length === 0,
        { label: `A's own row binds in ${vault}` }
      )
      expectSameRowsBut(await rawView(A), before.raw, 'device/device-A')
    }

    const started = await A.ensureEpoch({ start: true })
    expect(started).toMatchObject({ rotated: true, members: ['device-A'] })
    // Starting an epoch seals new writes only. Rows the released build
    // wrote stay plaintext and read as before.
    expect(await readEverything(A)).toEqual(beforeV.read)
    expect(isSealed(await A.raw('note/1'))).toBe(false)
    await A.add('note/2', { text: 'sealed' })
    expect(isSealed(await A.raw('note/2'))).toBe(true)
    expect(await A.get('note/2')).toEqual({ text: 'sealed' })
  })

  test('upgrade: a kick right after the upgrade is refused, then the owed start leaves the released device out', async () => {
    net = await createNetwork({
      peers: ['A', 'R'],
      builds: { A: RELEASED, R: RELEASED }
    })
    let { A } = net.peers
    const { R } = net.peers
    await A.createVault({ id: 'v' })
    await A.add('note/1', { text: 'first' })
    await R.pair(await A.invite())
    for (const peer of [A, R]) {
      await waitFor(async () => (await peer.devices()).length === 2, {
        label: `${peer.id} sees both device rows`
      })
    }
    A = await net.swap('A')

    // lib-vault's kickDevice starts with startLegacyEpoch. Called right after
    // the vault opens, before the re-signed device row has landed, the
    // roster still holds the released build's unsigned row for A, so A is
    // not in it: the start is refused and the kick stops before it removes
    // anything. The start stays owed, and a write is refused meanwhile.
    // Cause: resignMyRows (epochStore.js:704) marks the row as re-signed
    // before its add (:706) lands, so the start's own pass skips it.
    await expect(startLegacyEpoch(A, 'kickDevice')).rejects.toThrow(
      'kickDevice: cannot start the vault key: self-not-in-roster'
    )
    expect((await A.devices()).map((d) => d.id).sort()).toEqual([
      'device-A',
      'device-R'
    ])
    await expect(A.add('note/2', { text: 'x' })).rejects.toThrow(
      'Vault key must rotate first'
    )
    // The re-signed row's own update runs the owed start anyway: an epoch
    // with A alone, which leaves the released device out.
    const healed = await waitFor(
      async () => {
        const status = await A.epochStatus()
        return !status.legacy && status.canRead ? status : false
      },
      { label: 'the owed start runs' }
    )
    expect(healed).toMatchObject({
      seq: 1,
      members: ['device-A'],
      uncovered: ['device-R']
    })
    await A.add('note/2', { text: 'x' })
    expect(await A.get('note/2')).toEqual({ text: 'x' })
    await waitFor(() => R.raw('note/2'), { label: 'R holds note/2' })
    expect(await R.get('note/2')).toMatchObject({ $enc: 1, e: healed.epoch })
    expect(await R.get('note/1')).toEqual({ text: 'first' })
  })

  test('upgrade: a leave from a released device makes an upgraded device start an epoch without the other released devices', async () => {
    net = await createNetwork({
      peers: ['A', 'L', 'R'],
      builds: { A: RELEASED, L: RELEASED, R: RELEASED }
    })
    let { A } = net.peers
    const { L, R } = net.peers
    await shareVault(net)
    await A.add('note/1', { text: 'first' })
    await converge(net.list, 'note/1')
    A = await net.swap('A')
    await waitFor(
      async () =>
        JSON.stringify((await A.epochStatus()).uncovered) ===
        '["device-L","device-R"]',
      { label: "A's own row binds" }
    )
    // Updates on a legacy vault start nothing: they only call
    // ensureEpoch({ start: false }) (appDeps.js:632).
    await R.add('note/r', { text: 'an update for A' })
    await converge([A, R], 'note/r')
    expect(await A.epochStatus()).toMatchObject({ legacy: true })

    // L deletes the vault locally. The released lib-vault broadcasts a
    // leave first (deleteVaultLocal.js at 24a94fc). The harness has no
    // lib-vault, so A runs what leaveVaultActionHandler runs when the leave
    // reaches it (leaveVault.js:34-50): startLegacyEpoch, the sweep, then
    // ensureEpoch({ start: true }); Peer.kick is the sweep plus that call.
    await L.closeVault()
    await startLegacyEpoch(A, 'leave-vault')
    const after = await A.kick('device-L')
    expect(await A.epochStatus()).toMatchObject({
      legacy: false,
      members: ['device-A'],
      uncovered: ['device-R']
    })
    expect(after).toMatchObject({ uncovered: ['device-R'] })

    // R stayed, and from now on cannot read what A writes.
    await A.add('note/after', { text: 'after the leave' })
    await waitFor(() => R.raw('note/after'), { label: 'R holds note/after' })
    expect(await R.get('note/after')).toMatchObject({ $enc: 1 })
    expect(await R.get('note/1')).toEqual({ text: 'first' })
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

    // B saves the new record and file through their v2 keys, as lib-vault
    // does (v2 first, then the v1 projection). R's reconcile copies only
    // v1 to v2, so a gap between the two appends gives it nothing to do.
    // Edits of old records are the next tests.
    const sealedFile = crypto.randomBytes(2048)
    await B.add('record-v2/s1', sealedLogin)
    await B.add(
      'record-v2/s1/file/g1',
      { name: 'g1.bin' },
      sealedFile,
      'g1.bin'
    )
    await B.add('note/s', { text: 'sealed note' })
    // B's last append; B's log reaches R in order.
    await waitFor(() => R.raw('note/s'), { label: 'R holds the sealed rows' })
    const writes = R.writes.length
    await reconciled(R)

    // R's reconcile over the epoch row and the sealed rows wrote nothing.
    expect(R.writes.slice(writes)).toEqual([])
    // R reads every item from before the epoch as before.
    const after = await readFilled(R)
    expect({ ...after, ids: before.ids }).toEqual(before)
    // R cannot read what B sealed. It does not fail either: the released
    // build hands the envelope out as if it were the value, the record list
    // gets an entry with no id, and the file comes back as ciphertext.
    const envelope = {
      $enc: 1,
      e: first.id,
      n: expect.any(String),
      c: expect.any(String)
    }
    expect(await R.get('record/s1')).toEqual(envelope)
    expect(await R.get('note/s')).toEqual(envelope)
    const listed = await R.list('record/')
    expect(listed.map((r) => r.id)).toEqual(['r1', 'r2', undefined])
    expect(listed[2]).toEqual(envelope)
    expect(JSON.stringify(listed)).not.toContain('Sealed')
    const cipher = Buffer.from(await R.getFile('record-v2/s1/file/g1'))
    expect(cipher.equals(sealedFile)).toBe(false)
    expect(cipher.includes(sealedFile.subarray(0, 64))).toBe(false)

    phase(net, 'R writes after the epoch')
    // R still writes, in plaintext, and B and C read it. R saves through
    // the v2 key, as its lib-vault does; the gap before its v1 projection
    // gives the re-key reconcile nothing to do either.
    await R.add('note/r', { text: 'from the released build' })
    await R.add('record-v2/r1', { ...login(9, 'Edited on R', 'p9'), schema: 2 })
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
      expect(isSealed(await peer.raw('note/r'))).toBe(false)
      expect(isSealed(await peer.raw('record-v2/r1'))).toBe(false)
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

  test('mixed: a re-key device edits an old record the way the apps save it, v2 then v1', async () => {
    net = await createNetwork({
      peers: ['R', 'B'],
      builds: { R: RELEASED },
      onUpdate: countReconcile
    })
    const { R, B } = net.peers
    const rErrors = watchErrors(R)
    await shareVault(net)
    trackReconciles(B)
    const old = (id) => ({
      id,
      type: 'note',
      schema: 2,
      updatedAt: 1,
      data: { title: `Note ${id}`, note: 'old text' }
    })
    const edited = (id) => ({
      ...old(id),
      updatedAt: 7,
      data: { title: `Note ${id}`, note: 'edited on B' }
    })
    for (const id of ['n1', 'n2', 'n3']) await R.add(`record-v2/${id}`, old(id))
    await waitFor(async () => (await B.get('record/n3'))?.updatedAt === 1, {
      label: 'B reads the old notes'
    })
    const first = await B.ensureEpoch({ start: true })
    expect(first).toMatchObject({ rotated: true, members: ['device-B'] })
    const envelope = {
      $enc: 1,
      e: first.id,
      n: expect.any(String),
      c: expect.any(String)
    }

    phase(net, 'both rows land before R reconciles')
    // B saves n1 through record-v2/ (the core appends v2, then the v1
    // projection). Both reach R before its reconcile lists the vault: R's
    // reconcile writes nothing, and R reads the record as its envelope.
    const listing = holdGets(R, 'vault-ext')
    await B.add('record-v2/n1', edited('n1'))
    await waitFor(async () => isSealed(await R.raw('record/n1')), {
      label: 'R holds both sealed rows'
    })
    listing.release()
    let writes = R.writes.length
    await reconciled(R)
    expect(R.writes.slice(writes)).toEqual([])
    expect(await R.get('record/n1')).toEqual(envelope)
    expect(await B.get('record/n1')).toEqual(edited('n1'))

    // B saves n2 and n3 the same way, but the v1 projection reaches R more
    // than one debounce (100 ms) after v2. R's reconcile then sees its own
    // plaintext v1 (updatedAt 1) against a sealed v2, which the released
    // mergeV1IntoV2 counts as updatedAt 0. v1 wins, and R writes a mixed
    // row: B's new ciphertext with the old plaintext beside it.
    const lagV1 = async (id) => {
      const slowV1 = holdAdds(B, `record/${id}`)
      const saving = B.add(`record-v2/${id}`, edited(id))
      await slowV1.reached
      await waitFor(async () => isSealed(await R.raw(`record-v2/${id}`)), {
        label: `R holds B's sealed v2 of ${id}`
      })
      const sealedV2 = await rawJson(R, `record-v2/${id}`)
      const before = R.writes.length
      await reconciled(R)
      expect(R.writes.slice(before)).toEqual([
        { op: 'add', key: `record-v2/${id}` }
      ])
      // The v1 projection carries `websites: []`, and the merge derives
      // `uris` from it.
      const mixed = {
        ...sealedV2,
        ...old(id),
        data: { ...old(id).data, websites: [], uris: [] }
      }
      expect(await rawJson(R, `record-v2/${id}`)).toEqual(mixed)
      slowV1.release()
      await saving
      await waitFor(async () => isSealed(await R.raw(`record/${id}`)), {
        label: `R holds B's sealed v1 of ${id}`
      })
      await waitFor(
        async () => (await rawJson(B, `record-v2/${id}`))?.data !== undefined,
        { label: `B holds R's mixed row for ${id}` }
      )
      return mixed
    }

    phase(net, 'v1 lands late: n2')
    const mixed2 = await lagV1('n2')
    phase(net, 'v1 lands late: n3')
    const mixed3 = await lagV1('n3')
    // Neither reconcile repairs it: the mixed row's updatedAt (1) is not
    // below the sealed v1's on R (0), nor below B's edit (7) on B, where the
    // mixed row decrypts to B's edit.
    writes = R.writes.length
    await reconciled(R)
    await reconciled(B)
    expect(R.writes.slice(writes)).toEqual([])
    for (const [id, mixed] of [
      ['n2', mixed2],
      ['n3', mixed3]
    ]) {
      expect(await rawJson(B, `record-v2/${id}`)).toEqual(mixed)
      // R reads the OLD record; B reads its edit.
      expect(await R.get(`record/${id}`)).toEqual(mixed)
      expect(await R.get(`record/${id}`)).toMatchObject(old(id))
      expect(await B.get(`record/${id}`)).toEqual(edited(id))
    }
    expect((await R.list('record/')).map((r) => r.id)).toEqual([
      undefined,
      'n2',
      'n3'
    ])

    phase(net, 'R edits the stale records')
    // An edit on R starts from the old content R shows. Saved as fields the
    // app rebuilt (no envelope fields), it replaces B's edit everywhere.
    const fromR = (id) => ({
      ...old(id),
      updatedAt: 9,
      data: { title: `Note ${id}`, note: 'old text, edited on R' }
    })
    await R.add('record-v2/n2', fromR('n2'))
    // Saved as the listed record spread with new fields, it keeps B's
    // envelope: B decrypts that and never sees R's edit, while R reads it.
    await R.add('record-v2/n3', { ...mixed3, ...fromR('n3') })
    await waitFor(
      async () => (await rawJson(B, 'record/n3'))?.updatedAt === 9,
      {
        label: "B holds R's edits"
      }
    )
    await reconciled(R)
    await reconciled(B)
    expect(await B.get('record/n2')).toEqual(fromR('n2'))
    expect(await R.get('record/n2')).toEqual(fromR('n2'))
    expect(await B.get('record/n3')).toEqual(edited('n3'))
    expect(await R.get('record/n3')).toMatchObject(fromR('n3'))
    expect(rErrors).toEqual([])
  })

  test('mixed: a client that saves record/ first races the other build for the v2 twin', async () => {
    // No current app saves this way: lib-vault saves record-v2/ first (the
    // test above). These orders need a client that writes record/ directly.
    // Two devices only, so the one twin the re-key build writes is B's.
    net = await createNetwork({
      peers: ['R', 'B'],
      builds: { R: RELEASED },
      onUpdate: countReconcile
    })
    const { R, B } = net.peers
    const rErrors = watchErrors(R)
    await shareVault(net)
    trackReconciles(B)
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
    // both rows decrypt to the same updatedAt on B, and on R the envelope
    // counts as 0 against R's own copy, so mergeV1IntoV2 leaves them.
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
    writes = R.writes.length
    await reconciled(R)
    await reconciled(B)
    expect(R.writes.slice(writes)).toEqual([])
    expect(await rawJson(B, 'record-v2/s2')).toEqual(copy)
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
    // sealed, and it lands after R's plaintext twin. Until R reconciles
    // (one debounce) R reads its own edit as an envelope. Then the
    // envelope counts as updatedAt 0 against R's v1, R writes a mixed
    // row, and both sides read R's edit.
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
    const sealedTwin = await rawJson(R, 'record-v2/r1')
    writes = R.writes.length
    await reconciled(R)
    expect(R.writes.slice(writes)).toEqual([{ op: 'add', key: 'record-v2/r1' }])
    const editAsV2 = asV2(edit)
    const mixedRow = { ...sealedTwin, ...editAsV2 }
    expect(await rawJson(R, 'record-v2/r1')).toEqual(mixedRow)
    expect(await R.get('record/r1')).toEqual(mixedRow)
    expect(await R.get('record/r1')).toMatchObject(editAsV2)
    await waitFor(
      async () => (await rawJson(B, 'record-v2/r1'))?.data !== undefined,
      { label: "B holds R's mixed row" }
    )
    await reconciled(B)
    expect(await B.get('record/r1')).toEqual(editAsV2)
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
    // C holds A's later row, sealed, and reads nothing from it.
    await waitFor(() => C.raw('note/after'), { label: 'C holds note/after' })
    expect(isSealed(await C.raw('note/after'))).toBe(true)
    expect(await C.get('note/after')).toBeNull()
    expect(rErrors).toEqual([])
  })
})
