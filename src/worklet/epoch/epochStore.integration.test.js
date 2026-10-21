import fs from 'fs'
import os from 'os'
import path from 'path'

import Autopass from 'autopass'
import Corestore from 'corestore'
import Hypercore from 'hypercore'
import sodium from 'sodium-native'

import { buildEpochRecord } from './epochRecord.js'
import { createEpochStore } from './epochStore.js'
import {
  EpochKeyUnavailableError,
  EpochRecordWriteError,
  EpochRotationPendingError,
  generateEpochKey,
  openRing,
  sealCheck,
  sealRing,
  signDeviceRow,
  verifyDeviceRow
} from './keyring.js'

jest.setTimeout(60000)

const peers = []

const makeKeyPair = () => {
  const publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

const rowFor = (id, keyPair, writerKey) => ({
  id,
  name: id,
  writerKey: writerKey ? writerKey.toString('hex') : undefined,
  masterTopic: keyPair.publicKey.toString('hex'),
  createdAt: Date.now()
})

// The row as its writer signs it: `writer` is that writer's Hypercore key
// pair, `vaultKey` the vault's Autobase key.
const signRow = (row, writer, vaultKey) => ({
  ...row,
  writerPublicKey: writer.publicKey.toString('hex'),
  sig: signDeviceRow({
    secretKey: writer.secretKey,
    vaultKeyHex: vaultKey.toString('hex'),
    id: row.id,
    masterTopic: row.masterTopic,
    writerKey: row.writerKey
  })
})

// A row signed by the peer's own writer, as the store's add path signs it.
const ownRow = (peer, id, keyPair = peer.keyPair) =>
  signRow(
    rowFor(id, keyPair, peer.instance.writerKey),
    peer.instance.base.local.keyPair,
    peer.instance.base.key
  )

// A current writer no peer here runs. A roster row binds only while its
// writer is a current writer, so a device that is not a peer needs one.
const strayWriter = async (host) => {
  const keyPair = makeKeyPair()
  const key = Hypercore.key(keyPair.publicKey)
  await host.instance.addWriter(key)
  return { key, keyPair }
}

// A bound row for a device no peer here runs.
const strayRow = async (host, id, keyPair = makeKeyPair()) => {
  const writer = await strayWriter(host)
  return signRow(
    rowFor(id, keyPair, writer.key),
    writer.keyPair,
    host.instance.base.key
  )
}

const makePeer = async (id, host, keyPair = makeKeyPair(), storeOpts) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'epoch-store-'))
  const corestore = new Corestore(dir, storeOpts)
  const instance = new Autopass(
    corestore,
    host
      ? {
          key: host.instance.key,
          encryptionKey: host.instance.encryptionKey,
          replicate: false
        }
      : { replicate: false }
  )
  await instance.ready()
  const logger = { warn: jest.fn() }
  const store = createEpochStore({
    instance,
    getPersonalKeyPair: async () => keyPair,
    logger
  })
  const peer = { id, dir, corestore, instance, keyPair, logger, store }
  peer.row = ownRow(peer, id)
  peers.push(peer)
  return peer
}

// Heads alone can match while a peer is still linearizing what it fetched,
// so the applied length is part of the state.
const applied = (peer) =>
  JSON.stringify({
    heads: peer.instance.base
      .heads()
      .map((h) => `${h.key.toString('hex')}:${h.length}`)
      .sort(),
    length: peer.instance.base.length
  })

// Replicates every pair over in-memory streams until all peers applied the same state.
const sync = async (...group) => {
  const streams = []
  for (let i = 0; i < group.length; i++) {
    for (let j = i + 1; j < group.length; j++) {
      const s1 = group[i].instance.base.replicate(true)
      const s2 = group[j].instance.base.replicate(false)
      s1.pipe(s2).pipe(s1)
      streams.push(s1, s2)
    }
  }
  try {
    for (let round = 0; round < 100; round++) {
      await Promise.all(group.map((p) => p.instance.base.update()))
      if (new Set(group.map(applied)).size === 1 && round > 0) return
      await new Promise((resolve) => setTimeout(resolve, 20))
    }
    throw new Error('sync: peers did not converge')
  } finally {
    for (const stream of streams) stream.destroy()
  }
}

// Acks from the given indexers until everything appended so far is signed.
const indexed = async (...group) => {
  await sync(...group)
  const target = group[0].instance.base.length
  for (let round = 0; round < 20; round++) {
    for (const peer of group) await peer.instance.base.ack()
    await sync(...group)
    if (group.every((p) => p.instance.base.signedLength >= target)) return
  }
  throw new Error('indexed: removal was not signed')
}

const addDevice = (peer, row) =>
  peer.instance.add(`device/${row.id}`, JSON.stringify(row))

// Host with joined members, every roster row written and synced.
const setup = async (ids = ['A', 'B', 'C']) => {
  const [hostId, ...rest] = ids
  const host = await makePeer(hostId)
  const members = []
  for (const id of rest) {
    const member = await makePeer(id, host)
    await host.instance.addWriter(member.instance.writerKey)
    members.push(member)
  }
  for (const peer of [host, ...members]) await addDevice(host, peer.row)
  await sync(host, ...members)
  return [host, ...members]
}

const kick = async (host, target) => {
  await host.store.remove(`device/${target.id}`)
  const result = await host.store.ensureEpoch({ start: true })
  await host.instance.removeWriter(target.instance.writerKey)
  return result
}

// An envelope under an epoch nobody holds.
const UNREADABLE = JSON.stringify({
  $enc: 1,
  e: 'ff'.repeat(16),
  n: 'AA==',
  c: 'AA=='
})

const value = async (peer, key) => (await peer.store.get(key))?.value ?? null

const rawEnvelope = async (peer, key) =>
  JSON.parse((await peer.instance.get(key)).value)

// An epoch record by `author`, sealing `ring` to each [deviceId, keyPair].
// `ring[id]` is the epoch's own key.
const epochBy = (author, { id, seq, prev = null, ring, to }) => {
  const rows = to.map(([deviceId, kp]) => ({
    id: deviceId,
    masterTopic: kp.publicKey.toString('hex')
  }))
  const boxes = sealRing(ring, rows)
  const members = Object.fromEntries(
    rows.map(({ id: deviceId, masterTopic }) => [
      deviceId,
      { topic: masterTopic, box: boxes[deviceId] }
    ])
  )
  return buildEpochRecord({
    id,
    seq,
    prev,
    members,
    check: sealCheck(ring[id]),
    personalKeyPair: author
  })
}

// X once held epoch 1 from author O, then O rotated to epoch 2 without X.
// Every option flips one clause of the revoked rule.
const revokedFor = async ({
  authorInRoster = true,
  heldKey = true,
  wrote = true,
  inLatest = false,
  myRow = null
} = {}) => {
  const X = await makePeer('X')
  const O = makeKeyPair()
  const e1 = '01'.repeat(16)
  const e2 = '02'.repeat(16)
  const k1 = generateEpochKey()
  if (authorInRoster) await addDevice(X, await strayRow(X, 'O', O))
  if (myRow) await addDevice(X, await myRow(X))
  const records = [
    epochBy(O, {
      id: e1,
      seq: 1,
      ring: { [e1]: k1 },
      to: heldKey
        ? [
            ['O', O],
            ['X', X.keyPair]
          ]
        : [['O', O]]
    }),
    epochBy(O, {
      id: e2,
      seq: 2,
      prev: e1,
      ring: { [e1]: k1, [e2]: generateEpochKey() },
      to: inLatest
        ? [
            ['O', O],
            ['X', X.keyPair]
          ]
        : [['O', O]]
    })
  ]
  for (const record of records) {
    await X.instance.add(`epoch/${record.id}`, JSON.stringify(record))
  }
  if (!wrote) {
    Object.defineProperty(X.instance.base.local, 'length', {
      value: 0,
      configurable: true
    })
  }
  return (await X.store.status()).revoked
}

// C is offline for its kick and appends the rows `plant` writes. Autobase
// orders a removed writer's concurrent node before or after the removal by
// key bytes, so the rows survive in some runs only; runs go on until two
// did. A writes once right after the sync, before any ensureEpoch, under
// its kick epoch. Returns how many runs kept them.
const plantDuringKick = async (plant) => {
  let survived = 0
  for (let run = 0; run < 20 && survived < 2; run++) {
    const [A, B, C] = await setup()
    await indexed(A, B, C)
    await A.instance.removeWriter(C.instance.writerKey)
    await A.store.remove('device/C')
    const { id: kickEpoch } = await A.store.ensureEpoch({ start: true })
    const planted = await plant(A, B, C)
    await sync(A, B, C)
    for (let round = 0; round < 5; round++) {
      for (const peer of [A, B, C]) await peer.instance.base.ack()
      await sync(A, B, C)
    }
    if (await A.instance.get(`device/${planted[0]}`)) survived++
    await A.store.add('record/early', 'secret')
    expect((await rawEnvelope(A, 'record/early')).e).toBe(kickEpoch)

    for (const peer of [A, B, C]) {
      await peer.store.ensureEpoch({ start: false })
    }
    await A.store.add('record/after', 'secret')
    await sync(A, B, C)

    expect(await value(B, 'record/after')).toBe('secret')
    expect(await C.store.get('record/after')).toBeNull()
    const { members, uncovered } = await A.store.status()
    expect(members).toEqual(['A', 'B'])
    // A planted row shares a member's writer key or names C's removed one.
    expect(uncovered).toEqual([])
    for (const peer of peers.splice(0)) {
      await peer.instance.close()
      await peer.corestore.close()
      fs.rmSync(peer.dir, { recursive: true, force: true })
    }
  }
  return survived
}

afterEach(async () => {
  for (const peer of peers.splice(0)) {
    await peer.instance.close()
    await peer.corestore.close()
    fs.rmSync(peer.dir, { recursive: true, force: true })
  }
})

describe('epochStore over real Autopass', () => {
  it('locks a revoked writer out of new entries only', async () => {
    const [A, B, C] = await setup()
    await A.store.add('record/legacy', '{"title":"legacy"}')
    await sync(A, B, C)
    for (const peer of [A, B, C]) {
      expect(await value(peer, 'record/legacy')).toBe('{"title":"legacy"}')
    }

    const result = await kick(A, C)
    expect(result).toMatchObject({ rotated: true, seq: 1, members: ['A', 'B'] })
    await A.store.add('record/x', '{"title":"x"}')
    await sync(A, B, C)

    expect(await value(B, 'record/x')).toBe('{"title":"x"}')
    expect((await rawEnvelope(C, 'record/x')).$enc).toBe(1)
    expect(await C.store.get('record/x')).toBeNull()
    // C never held an epoch key, so it cannot tell a kick from a pending join.
    expect(await C.store.status()).toMatchObject({
      revoked: false,
      canRead: false
    })
    expect(await value(C, 'record/legacy')).toBe('{"title":"legacy"}')
    const roster = await C.store.find({
      gte: { key: 'device/' },
      lt: { key: 'device0' }
    })
    expect(roster.map((r) => r.key)).toEqual(['device/A', 'device/B'])
  })

  it('keeps the remaining members reading and writing', async () => {
    const [A, B, C] = await setup()
    const { id } = await kick(A, C)
    await sync(A, B, C)

    await B.store.add('record/y', '{"title":"y"}')
    expect((await rawEnvelope(B, 'record/y')).e).toBe(id)
    await sync(A, B, C)

    expect(await value(A, 'record/y')).toBe('{"title":"y"}')
    expect(await C.store.get('record/y')).toBeNull()
    expect((await B.store.status()).canRead).toBe(true)
    expect((await A.store.status()).members).toEqual(['A', 'B'])
  })

  it('lets an offline member catch up across rotations', async () => {
    const [A, B, C] = await setup()
    await kick(A, C)
    for (const n of [1, 2, 3]) await A.store.add(`record/${n}`, `v${n}`)

    await sync(A, B)
    for (const n of [1, 2, 3])
      expect(await value(B, `record/${n}`)).toBe(`v${n}`)
    expect((await B.store.status()).canRead).toBe(true)

    await addDevice(A, await strayRow(A, 'D'))
    expect(await A.store.ensureEpoch({ start: false })).toMatchObject({
      rotated: true,
      seq: 2,
      members: ['A', 'B', 'D']
    })
    await A.store.add('record/4', 'v4')
    await sync(A, B)

    for (const n of [1, 2, 3, 4])
      expect(await value(B, `record/${n}`)).toBe(`v${n}`)
    expect(await B.store.status()).toMatchObject({ seq: 2, canRead: true })
  })

  it('drops appends from a removed writer once the removal is indexed', async () => {
    const [A, B, C] = await setup()
    // Autobase only drops a removed writer's node when it is linearized
    // after the removal, so the removal must be signed before C appends.
    await indexed(A, B, C)
    await kick(A, C)
    await indexed(A, B)
    // C has not seen its removal, so its own base still accepts the append.
    expect(C.instance.writable).toBe(true)
    await C.instance.add('record/late', '{"title":"late"}')
    await sync(A, B, C)

    expect(await A.instance.get('record/late')).toBeNull()
    expect(
      await A.store.find({ gte: { key: 'record/' }, lt: { key: 'record0' } })
    ).toEqual([])
    expect(C.instance.writable).toBe(false)
    await expect(C.store.add('record/later', '{}')).rejects.toThrow(
      EpochKeyUnavailableError
    )
  })

  it('ignores misplaced, forged, and broken epoch records', async () => {
    const [A, B, C] = await setup()
    const first = await kick(A, C)
    const firstRecord = (await A.instance.get(`epoch/${first.id}`)).value
    await addDevice(A, await strayRow(A, 'D'))
    const second = await A.store.ensureEpoch({ start: false })
    expect(second.seq).toBe(2)

    await A.instance.add('epoch/replayed-copy', firstRecord)
    const forged = buildEpochRecord({
      seq: 99,
      prev: second.id,
      members: {},
      check: sealCheck(generateEpochKey()),
      personalKeyPair: makeKeyPair()
    })
    await A.instance.add(`epoch/${forged.id}`, JSON.stringify(forged))
    const broken = {
      ...buildEpochRecord({
        seq: 3,
        prev: second.id,
        members: {},
        check: sealCheck(generateEpochKey()),
        personalKeyPair: A.keyPair
      }),
      seq: 100
    }
    await A.instance.add(`epoch/${broken.id}`, JSON.stringify(broken))
    await sync(A, B)

    await A.store.add('record/z', '{"title":"z"}')
    expect((await rawEnvelope(A, 'record/z')).e).toBe(second.id)
    expect((await A.store.status()).seq).toBe(2)
    expect((await B.store.status()).epoch).toBe(second.id)
  })

  it('drops a key a foreign box offers for a real epoch', async () => {
    const [A, B] = await setup(['A', 'B'])
    const real = await A.store.ensureEpoch({ start: true })
    await A.store.add('record/x', 'v')

    // A throwaway key signs a valid record of its own, sorted first so its
    // box is opened first, mapping the real epoch to a key it chose.
    const planted = '00'.repeat(16)
    const record = epochBy(makeKeyPair(), {
      id: planted,
      seq: 1,
      ring: { [planted]: generateEpochKey(), [real.id]: generateEpochKey() },
      to: [['B', B.keyPair]]
    })
    await A.instance.add(`epoch/${planted}`, JSON.stringify(record))
    await sync(A, B)

    expect(await value(B, 'record/x')).toBe('v')
    await B.store.add('record/y', 'w')
    expect((await rawEnvelope(B, 'record/y')).e).toBe(real.id)
    await sync(A, B)
    expect(await value(A, 'record/y')).toBe('w')
  })

  it.each([
    ['before', 'itself'],
    ['before', 'the rest'],
    ['after', 'itself'],
    ['after', 'the rest']
  ])(
    'never writes under an epoch a kicked device signed %s its kick, sealed to %s',
    async (when, sealedTo) => {
      const [A, B, C] = await setup()
      const start = await A.store.ensureEpoch({ start: true })
      await sync(A, B, C)
      const plant = (prev) => {
        const id = 'ee'.repeat(16)
        return epochBy(C.keyPair, {
          id,
          seq: prev.seq + 1,
          prev: prev.id,
          ring: { [id]: generateEpochKey() },
          to:
            sealedTo === 'itself'
              ? [['C', C.keyPair]]
              : [
                  ['A', A.keyPair],
                  ['B', B.keyPair]
                ]
        })
      }

      if (when === 'before') {
        const planted = plant(start)
        await C.instance.add(`epoch/${planted.id}`, JSON.stringify(planted))
        await sync(A, B, C)
      }
      const kicked = await kick(A, C)
      if (when === 'after') {
        // C signed it before it saw its removal; it lands behind the kick.
        const planted = plant(kicked)
        await A.instance.add(`epoch/${planted.id}`, JSON.stringify(planted))
      }
      await sync(A, B)

      expect(kicked).toMatchObject({ rotated: true, members: ['A', 'B'] })
      // A key C sealed to the rest after the kick is one the kick's ring
      // lacks, which costs one rotation by a current member.
      const healed = await A.store.ensureEpoch({ start: false })
      expect(healed.rotated).toBe(when === 'after' && sealedTo === 'the rest')
      const latest = healed.rotated ? healed.id : kicked.id
      await sync(A, B)
      for (const peer of [A, B]) {
        expect(await peer.store.ensureEpoch({ start: false })).toMatchObject({
          rotated: false,
          reason: 'current'
        })
        expect((await peer.store.status()).epoch).toBe(latest)
      }
      await B.store.add('record/after', 'v')
      expect((await rawEnvelope(B, 'record/after')).e).toBe(latest)
    }
  )

  it('ignores an unchained top seq planted by a current member', async () => {
    const [A, B] = await setup(['A', 'B'])
    const start = await A.store.ensureEpoch({ start: true })
    // B stays in the roster, so only the chain turns this record away.
    const id = '0f'.repeat(16)
    const planted = epochBy(B.keyPair, {
      id,
      seq: Number.MAX_SAFE_INTEGER,
      ring: { [id]: generateEpochKey() },
      to: [['B', B.keyPair]]
    })
    await B.instance.add(`epoch/${id}`, JSON.stringify(planted))
    await sync(A, B)

    for (const peer of [A, B]) {
      expect(await peer.store.status()).toMatchObject({
        epoch: start.id,
        seq: 1
      })
    }
    await addDevice(A, await strayRow(A, 'D'))
    expect(await A.store.ensureEpoch({ start: false })).toMatchObject({
      rotated: true,
      seq: 2
    })
  })

  it('reports no rotation when another epoch resolves above the new one', async () => {
    const [A, B] = await setup(['A', 'B'])
    const add = A.instance.add.bind(A.instance)
    let rival = null
    // B's epoch with the same seq and a higher id lands right behind A's,
    // sealing the keys B opened from A's.
    A.instance.add = async (key, record, file) => {
      await add(key, record, file)
      if (rival || !key.startsWith('epoch/')) return
      const { seq, prev, members } = JSON.parse(record)
      const id = 'ff'.repeat(16)
      rival = epochBy(B.keyPair, {
        id,
        seq,
        prev,
        ring: {
          ...openRing(members.B.box, B.keyPair),
          [id]: generateEpochKey()
        },
        to: [
          ['A', A.keyPair],
          ['B', B.keyPair]
        ]
      })
      await add(`epoch/${id}`, JSON.stringify(rival))
    }

    expect(await A.store.ensureEpoch({ start: true })).toMatchObject({
      rotated: false,
      reason: 'current'
    })
    expect((await A.store.status()).epoch).toBe(rival.id)
  })

  // After each of A's next `count` epoch appends, B's epoch with the same
  // seq and a higher id lands right behind it, sealed to `to`.
  const rivalEach = (A, B, count, to) => {
    const add = A.instance.add.bind(A.instance)
    const rivals = []
    A.instance.add = async (key, record, file) => {
      await add(key, record, file)
      if (rivals.length >= count || !key.startsWith('epoch/')) return
      const { seq, prev } = JSON.parse(record)
      const id = `${'ff'.repeat(15)}0${rivals.length}`
      const rival = epochBy(B.keyPair, {
        id,
        seq,
        prev,
        ring: { [id]: generateEpochKey() },
        to
      })
      rivals.push(rival)
      await add(`epoch/${id}`, JSON.stringify(rival))
    }
    return rivals
  }

  it('reports pending when the epoch above the new one is not sealed to it', async () => {
    const [A, B] = await setup(['A', 'B'])
    const rivals = rivalEach(A, B, 1, [['B', B.keyPair]])

    expect(await A.store.ensureEpoch({ start: true })).toMatchObject({
      rotated: false,
      reason: 'pending'
    })
    expect((await A.store.status()).epoch).toBe(rivals[0].id)
  })

  it('throws when the rotation after a lost race is overtaken too', async () => {
    const [A, B] = await setup(['A', 'B'])
    // Each rival lists a device outside the roster, so A rotates past it.
    const to = [
      ['A', A.keyPair],
      ['B', B.keyPair],
      ['X', makeKeyPair()]
    ]
    const rivals = rivalEach(A, B, 2, to)

    await expect(A.store.ensureEpoch({ start: true })).rejects.toThrow(
      'Epoch rotation did not resolve as latest'
    )
    expect(rivals).toHaveLength(2)
  })

  it('rejects a write as pending when its rotation is overtaken twice', async () => {
    const [A, B] = await setup()
    await A.store.ensureEpoch({ start: true })
    await A.store.remove('device/C')
    // Each rival seals to X, outside the roster, so latest stays stale.
    const rivals = rivalEach(A, B, 2, [
      ['A', A.keyPair],
      ['B', B.keyPair],
      ['X', makeKeyPair()]
    ])

    await expect(A.store.add('record/r', 'v')).rejects.toThrow(
      EpochRotationPendingError
    )
    expect(rivals).toHaveLength(2)
    expect(await A.instance.get('record/r')).toBeNull()
  })

  it('writes under the winner when its rotation is overtaken twice', async () => {
    const [A, B] = await setup()
    await A.store.ensureEpoch({ start: true })
    await A.store.remove('device/C')
    // Each rival seals to the roster alone, so the last one is current.
    const rivals = rivalEach(A, B, 2, [
      ['A', A.keyPair],
      ['B', B.keyPair]
    ])

    await A.store.add('record/r', 'v')
    expect(rivals).toHaveLength(2)
    expect((await rawEnvelope(A, 'record/r')).e).toBe(rivals[1].id)
    expect(await value(A, 'record/r')).toBe('v')
  })

  it('rejects a write with the error its rotation append threw', async () => {
    const [A] = await setup()
    await A.store.ensureEpoch({ start: true })
    await A.store.remove('device/C')
    const add = A.instance.add.bind(A.instance)
    const failure = new Error('append failed')
    A.instance.add = async (key, ...rest) => {
      if (key.startsWith('epoch/')) throw failure
      return add(key, ...rest)
    }

    await expect(A.store.add('record/r', 'v')).rejects.toBe(failure)
    expect(await A.instance.get('record/r')).toBeNull()
  })

  it('omits an envelope whose epoch id was edited', async () => {
    const [A, , C] = await setup()
    const first = await kick(A, C)
    await addDevice(A, await strayRow(A, 'D'))
    await A.store.ensureEpoch({ start: false })
    await A.store.add('record/z', '{"title":"z"}')

    const edited = { ...(await rawEnvelope(A, 'record/z')), e: first.id }
    await A.instance.add('record/tampered', JSON.stringify(edited))

    expect(await A.store.get('record/tampered')).toBeNull()
    expect(await A.store.get('record/tampered')).toBeNull()
    const found = await A.store.find({
      gte: { key: 'record/' },
      lt: { key: 'record0' }
    })
    expect(found.map((r) => r.key)).toEqual(['record/z'])
    const tamperedLogs = A.logger.warn.mock.calls.filter(
      ([, details]) => details.key === 'record/tampered'
    )
    expect(tamperedLogs).toHaveLength(1)
  })

  it('carries the history to a device paired after epochs exist', async () => {
    const [A, B, C] = await setup()
    await A.store.add('record/legacy', 'v0')
    await kick(A, C)
    await A.store.add('record/1', 'v1')
    await addDevice(A, await strayRow(A, 'E'))
    await A.store.ensureEpoch({ start: false })
    await A.store.add('record/2', 'v2')

    const D = await makePeer('D', A)
    await A.instance.addWriter(D.instance.writerKey)
    await addDevice(A, D.row)
    await sync(A, B, D)

    expect(await D.store.ensureEpoch({ start: false })).toMatchObject({
      rotated: false,
      reason: 'pending'
    })
    expect(await D.store.status()).toMatchObject({
      canRead: false,
      revoked: false
    })

    expect(await A.store.ensureEpoch({ start: false })).toMatchObject({
      rotated: true,
      seq: 3,
      members: ['A', 'B', 'D', 'E']
    })
    await A.store.add('record/3', 'v3')
    await sync(A, B, D)

    expect(await D.store.status()).toMatchObject({ canRead: true, seq: 3 })
    for (const [key, v] of [
      ['legacy', 'v0'],
      ['1', 'v1'],
      ['2', 'v2'],
      ['3', 'v3']
    ]) {
      expect(await value(D, `record/${key}`)).toBe(v)
    }
  })

  it('stays plaintext in a legacy vault and reports uncovered rows', async () => {
    const [A] = await setup(['A'])
    await addDevice(A, { id: 'L', name: 'legacy device', createdAt: 1 })
    // A stale row of A from before it had a masterTopic is not uncovered.
    await addDevice(A, { id: 'A-old', writerKey: A.row.writerKey })
    await A.store.add('record/a', '{"title":"a"}')

    expect((await A.instance.get('record/a')).value).toBe('{"title":"a"}')
    expect(await A.store.ensureEpoch({ start: false })).toEqual({
      rotated: false,
      reason: 'legacy',
      uncovered: ['L']
    })
    expect(await A.store.status()).toMatchObject({
      legacy: true,
      epoch: null,
      seq: 0,
      uncovered: ['L']
    })

    const [one, two] = await Promise.all([
      A.store.ensureEpoch({ start: true }),
      A.store.ensureEpoch({ start: true })
    ])
    expect(one).toMatchObject({
      rotated: true,
      members: ['A'],
      uncovered: ['L']
    })
    expect(two).toMatchObject({ rotated: false, reason: 'current' })
    const epochs = await A.store.find({
      gte: { key: 'epoch/' },
      lt: { key: 'epoch0' }
    })
    expect(epochs).toHaveLength(1)
  })

  it('runs a start:true call that lands during a start:false run', async () => {
    const [A] = await setup(['A'])

    const background = A.store.ensureEpoch({ start: false })
    const kickCall = A.store.ensureEpoch({ start: true })
    const waiter = A.store.ensureEpoch({ start: false })

    expect(await background).toMatchObject({ rotated: false, reason: 'legacy' })
    expect(await kickCall).toMatchObject({ rotated: true, seq: 1 })
    expect(await waiter).toBe(await kickCall)
    expect((await A.store.status()).legacy).toBe(false)
  })

  it('reports revoked for a kicked device that held a key', async () => {
    const [A, B, C] = await setup()
    // Like the app, C writes its own row.
    await addDevice(C, C.row)
    await sync(A, B, C)
    await A.store.ensureEpoch({ start: true })
    await sync(A, B, C)
    expect((await C.store.status()).canRead).toBe(true)

    await kick(A, C)
    await A.store.add('record/x', '{}')
    await sync(A, B, C)

    expect(await C.store.status()).toMatchObject({
      canRead: false,
      revoked: true
    })
    expect((await B.store.status()).revoked).toBe(false)
  })

  it('reports revoked for a kicked device whose row was left behind', async () => {
    const [A, B, C] = await setup()
    await addDevice(C, C.row)
    await sync(A, B, C)
    await A.store.ensureEpoch({ start: true })
    await sync(A, B, C)

    // A concurrent append ordered before the removal, or a missed sweep.
    await A.instance.removeWriter(C.instance.writerKey)
    expect(await A.store.ensureEpoch({ start: true })).toMatchObject({
      rotated: true,
      members: ['A', 'B']
    })
    await A.store.add('record/x', '{}')
    await sync(A, B, C)

    expect(await C.instance.get('device/C')).toBeTruthy()
    expect(await C.store.status()).toMatchObject({
      canRead: false,
      revoked: true
    })
  })

  it('does not report revoked for a legacy row or a joiner without a row', async () => {
    const A = await makePeer('A')
    const L = await makePeer('L', A)
    const D = await makePeer('D', A)
    await A.instance.addWriter(L.instance.writerKey)
    await A.instance.addWriter(D.instance.writerKey)
    await addDevice(A, A.row)
    await addDevice(A, { id: 'L', writerKey: L.row.writerKey })
    expect(await A.store.ensureEpoch({ start: true })).toMatchObject({
      rotated: true,
      members: ['A'],
      uncovered: ['L']
    })
    await sync(A, L, D)

    for (const peer of [L, D]) {
      expect(await peer.store.status()).toMatchObject({
        legacy: false,
        canRead: false,
        revoked: false
      })
    }
  })

  it('owes a failed start and runs it on a later start:false', async () => {
    const [A] = await setup(['A'])
    Object.defineProperty(A.instance.base, 'writable', {
      value: false,
      configurable: true
    })

    expect(await A.store.ensureEpoch({ start: true })).toMatchObject({
      rotated: false,
      reason: 'not-writable'
    })
    expect(await A.store.ensureEpoch({ start: false })).toMatchObject({
      rotated: false,
      reason: 'not-writable'
    })

    delete A.instance.base.writable
    expect(await A.store.ensureEpoch({ start: false })).toMatchObject({
      rotated: true,
      seq: 1
    })
    expect(await A.store.ensureEpoch({ start: false })).toMatchObject({
      rotated: false,
      reason: 'current'
    })
  })

  it('does not report revoked for a kicked device that pairs again', async () => {
    const [A, B, L] = await setup(['A', 'B', 'L'])
    await A.store.ensureEpoch({ start: true })
    await sync(A, B, L)
    await kick(A, L)
    await sync(A, B)

    // Fresh per-vault store, same personal key: it opens its old boxes.
    const L2 = await makePeer('L', A, L.keyPair)
    await A.instance.addWriter(L2.instance.writerKey)
    await sync(A, B, L2)
    expect(await L2.store.status()).toMatchObject({
      canRead: false,
      revoked: false
    })

    await addDevice(L2, L2.row)
    await sync(A, B, L2)
    expect(await A.store.ensureEpoch({ start: false })).toMatchObject({
      rotated: true,
      members: ['A', 'B', 'L']
    })
    await A.store.add('record/back', 'v')
    await sync(A, B, L2)
    expect(await value(L2, 'record/back')).toBe('v')
    expect((await L2.store.status()).canRead).toBe(true)
  })

  it('rotates past rows whose masterTopic is not a usable key', async () => {
    const [A] = await setup(['A'])
    await addDevice(A, {
      ...(await strayRow(A, 'Y')),
      masterTopic: '00'.repeat(32)
    })
    await addDevice(A, {
      ...(await strayRow(A, 'Z')),
      masterTopic: '01' + '00'.repeat(31)
    })

    expect(await A.store.ensureEpoch({ start: true })).toMatchObject({
      rotated: true,
      members: ['A'],
      uncovered: ['Y', 'Z']
    })
    expect(await A.store.ensureEpoch({ start: false })).toMatchObject({
      rotated: false,
      reason: 'current'
    })
  })

  it('keeps working with a roster row whose masterTopic is a number', async () => {
    const [A] = await setup(['A'])
    // device/0 sorts before device/A, so every roster scan meets it first.
    await addDevice(A, { ...(await strayRow(A, '0')), masterTopic: 12345 })
    await A.store.ensureEpoch({ start: true })
    await A.store.add('record/n', 'v')

    expect(await value(A, 'record/n')).toBe('v')
    expect(
      await A.store.find({ gte: { key: 'record/' }, lt: { key: 'record0' } })
    ).toHaveLength(1)
    expect(await A.store.status()).toMatchObject({
      canRead: true,
      revoked: false,
      uncovered: ['0']
    })
  })

  it('rotates before writing when the roster shrank but the epoch did not', async () => {
    const [A, B, C] = await setup()
    await A.store.ensureEpoch({ start: true })
    await sync(A, B, C)

    // The roster shrink reaches B before any rotation does.
    await A.store.remove('device/C')
    await sync(A, B)
    await B.store.add('record/s', 'secret')
    expect((await rawEnvelope(B, 'record/s')).$enc).toBe(1)
    await sync(A, B, C)

    expect(await value(A, 'record/s')).toBe('secret')
    expect(await C.store.get('record/s')).toBeNull()
    expect((await B.store.status()).members).toEqual(['A', 'B'])
  })

  it('keeps an epoch whose author left and never falls back to plaintext', async () => {
    const [A, B, C] = await setup()
    await C.store.ensureEpoch({ start: true })
    await C.store.add('record/c', 'from C')
    await sync(A, B, C)

    await A.store.remove('device/C')
    await sync(A, B)
    expect((await B.store.status()).legacy).toBe(false)
    await B.store.add('record/b', 'from B')
    expect((await rawEnvelope(B, 'record/b')).$enc).toBe(1)
    await sync(A, B, C)

    expect(await value(B, 'record/c')).toBe('from C')
    expect(await value(A, 'record/b')).toBe('from B')
    expect(await C.store.get('record/b')).toBeNull()
    // No epoch has an author in the roster, so B starts the chain again.
    expect(await B.store.status()).toMatchObject({
      legacy: false,
      canRead: true,
      seq: 1
    })
  })

  it('resolves a vault whose first author left after a later rotation', async () => {
    const [A, B, C] = await setup()
    await C.store.ensureEpoch({ start: true })
    await C.store.add('record/c', 'from C')
    await sync(A, B, C)

    const result = await kick(A, C)
    expect(result).toMatchObject({ rotated: true, seq: 1 })
    await sync(A, B)

    expect(await B.store.status()).toMatchObject({
      epoch: result.id,
      seq: 1,
      canRead: true
    })
    expect(await value(B, 'record/c')).toBe('from C')
  })

  it('keeps the epoch mode and later keys when a member deletes the genesis', async () => {
    const [A, B, C] = await setup()
    const first = await A.store.ensureEpoch({ start: true })
    await addDevice(A, await strayRow(A, 'D'))
    expect(await A.store.ensureEpoch({ start: false })).toMatchObject({
      rotated: true,
      seq: 2
    })
    await A.store.add('record/r2', 'v2')
    await sync(A, B, C)

    // A current member removes the genesis row behind the store's back.
    await C.instance.remove(`epoch/${first.id}`)
    await sync(A, B, C)

    expect(await B.store.status()).toMatchObject({
      legacy: false,
      epoch: null
    })
    await B.store.add('record/b', 'from B')
    expect((await rawEnvelope(B, 'record/b')).$enc).toBe(1)
    expect(await B.store.status()).toMatchObject({ legacy: false, seq: 1 })
    expect(await value(B, 'record/r2')).toBe('v2')
    await sync(A, B)
    expect(await value(A, 'record/b')).toBe('from B')
  })

  it('names a roster row by its key, ignoring a row that claims another id', async () => {
    const [A, B] = await setup(['A', 'B'])
    const attacker = makeKeyPair()
    // device/0 sorts before device/B, so a first-row-wins scan meets it first.
    await A.instance.add(
      'device/0',
      JSON.stringify({ ...rowFor('0', attacker), id: 'B' })
    )
    const first = await A.store.ensureEpoch({ start: true })
    expect(first).toMatchObject({ members: ['A', 'B'], uncovered: [] })
    await A.store.add('record/x', 'v')
    await sync(A, B)
    expect(await value(B, 'record/x')).toBe('v')

    // Nor does the row make its key an author.
    const id = 'ff'.repeat(16)
    const planted = epochBy(attacker, {
      id,
      seq: 2,
      prev: first.id,
      ring: { [id]: generateEpochKey() },
      to: [['0', attacker]]
    })
    await A.instance.add(`epoch/${id}`, JSON.stringify(planted))
    expect(await A.store.status()).toMatchObject({
      epoch: first.id,
      members: ['A', 'B'],
      uncovered: []
    })
  })

  it('never seals to a roster row without an id', async () => {
    const [A, B, C] = await setup()
    // lib-vault lists and sweeps rows by value.id, so a kick of C leaves
    // this row in place.
    await C.instance.add(
      'device/Z',
      JSON.stringify({
        masterTopic: C.keyPair.publicKey.toString('hex'),
        writerKey: C.instance.writerKey.toString('hex')
      })
    )
    await sync(A, B, C)

    expect(await kick(A, C)).toMatchObject({
      rotated: true,
      members: ['A', 'B'],
      uncovered: []
    })
    await A.store.add('record/after', 'v')
    await sync(A, B, C)
    expect(await value(B, 'record/after')).toBe('v')
    expect(await C.store.get('record/after')).toBeNull()
  })

  it('neither seals to nor reports a roster row with an empty id', async () => {
    const [A] = await setup(['A'])
    const stray = rowFor('', makeKeyPair())
    await addDevice(A, stray)

    expect(await A.store.ensureEpoch({ start: true })).toMatchObject({
      rotated: true,
      members: ['A'],
      uncovered: []
    })
    expect(await A.store.ensureEpoch({ start: false })).toMatchObject({
      rotated: false,
      reason: 'current'
    })
    await addDevice(A, { ...stray, masterTopic: undefined })
    expect((await A.store.status()).uncovered).toEqual([])
  })

  it('never seals to a row a kicked writer appended concurrently with its removal', async () => {
    // C adds itself again under a fresh id.
    const survived = await plantDuringKick(async (A, B, C) => {
      await addDevice(C, ownRow(C, 'C2'))
      return ['C2']
    })
    expect(survived).toBe(2)
  })

  it('never writes under an epoch chain a kicked writer appended with its row', async () => {
    // C's chain outranks the kick epoch and is sealed to A and B, so only
    // the author check on bound rows keeps A from writing under X2.
    const survived = await plantDuringKick(async (A, B, C) => {
      await addDevice(C, ownRow(C, 'C2'))
      const x1 = 'a1'.repeat(16)
      const x2 = 'a2'.repeat(16)
      const ring = { [x1]: generateEpochKey() }
      const to = [
        ['A', A.keyPair],
        ['B', B.keyPair]
      ]
      const records = [
        epochBy(C.keyPair, { id: x1, seq: 1, ring, to }),
        epochBy(C.keyPair, {
          id: x2,
          seq: 2,
          prev: x1,
          ring: { ...ring, [x2]: generateEpochKey() },
          to
        })
      ]
      for (const record of records) {
        await C.instance.add(`epoch/${record.id}`, JSON.stringify(record))
      }
      return ['C2']
    })
    expect(survived).toBe(2)
  })

  it('never seals to a row a kicked writer planted under a member writer key', async () => {
    // device/! sorts before every real row.
    const survived = await plantDuringKick(async (A, B, C) => {
      await addDevice(C, rowFor('!', C.keyPair, A.instance.writerKey))
      return ['!']
    })
    expect(survived).toBe(2)
  })

  it('never seals to rows a kicked writer planted under every member writer key', async () => {
    const survived = await plantDuringKick(async (A, B, C) => {
      await addDevice(C, rowFor('!', C.keyPair, A.instance.writerKey))
      await addDevice(C, rowFor('!!', C.keyPair, B.instance.writerKey))
      return ['!', '!!']
    })
    expect(survived).toBe(2)
  })

  it('seals to a device that heals its own row under the same id', async () => {
    const [A, B] = await setup(['A', 'B'])
    await addDevice(B, { ...B.row, masterTopic: undefined })
    await sync(A, B)
    expect(await A.store.ensureEpoch({ start: true })).toMatchObject({
      rotated: true,
      members: ['A'],
      uncovered: ['B']
    })

    // The heal goes through the store, which signs it.
    await B.store.add(
      'device/B',
      JSON.stringify(rowFor('B', B.keyPair, B.instance.writerKey))
    )
    await sync(A, B)
    expect(await A.store.ensureEpoch({ start: false })).toMatchObject({
      rotated: true,
      members: ['A', 'B'],
      uncovered: []
    })
    await A.store.add('record/x', 'v')
    await sync(A, B)
    expect(await value(B, 'record/x')).toBe('v')
  })

  it('seals to every row a writer signed, without knocking out another member', async () => {
    const [A, B] = await setup(['A', 'B'])
    // device/0 sorts before device/A and names B's other device key.
    await addDevice(B, ownRow(B, '0', makeKeyPair()))
    await sync(A, B)

    expect(await A.store.ensureEpoch({ start: true })).toMatchObject({
      rotated: true,
      members: ['0', 'A', 'B'],
      uncovered: []
    })
    // Without its masterTopic a row of B's writer is a stale copy, not a
    // device.
    await addDevice(B, {
      ...rowFor('B3', B.keyPair, B.instance.writerKey),
      masterTopic: undefined
    })
    await sync(A, B)
    expect((await A.store.status()).uncovered).toEqual([])
  })

  it('reports rows without a writer binding as uncovered and never seals to them', async () => {
    const [A] = await setup(['A'])
    const stranger = Buffer.alloc(32, 7)
    // A writer the vault does not know, with and without a masterTopic.
    await addDevice(A, rowFor('U', makeKeyPair(), stranger))
    await addDevice(A, { id: 'V', writerKey: stranger.toString('hex') })
    // No writerKey at all.
    await addDevice(A, { ...rowFor('W', makeKeyPair()), writerKey: undefined })
    // A current writer, but no signature.
    const { sig, writerPublicKey, ...unsigned } = await strayRow(A, 'N')
    expect(sig && writerPublicKey).toBeTruthy()
    await addDevice(A, unsigned)

    expect(await A.store.ensureEpoch({ start: true })).toMatchObject({
      rotated: true,
      members: ['A'],
      uncovered: ['N', 'U', 'V', 'W']
    })
    expect(await A.store.status()).toMatchObject({
      members: ['A'],
      uncovered: ['N', 'U', 'V', 'W']
    })
  })

  it('binds a row my writer signs, its core key hashing from its key pair', async () => {
    const A = await makePeer('A')
    const { local } = A.instance.base
    expect(Hypercore.key(local.keyPair.publicKey)).toEqual(local.key)
    expect(verifyDeviceRow(A.row, A.instance.base.key.toString('hex'))).toBe(
      true
    )
  })

  it('binds my row when my writer core uses manifest version 2', async () => {
    const A = await makePeer('A', null, undefined, { manifestVersion: 2 })
    const { local } = A.instance.base
    expect(Hypercore.key(local.keyPair.publicKey, { version: 2 })).toEqual(
      local.key
    )
    expect(Hypercore.key(local.keyPair.publicKey)).not.toEqual(local.key)
    await A.store.add(
      'device/A',
      JSON.stringify(rowFor('A', A.keyPair, A.instance.writerKey))
    )

    expect(await A.store.ensureEpoch({ start: true })).toMatchObject({
      rotated: true,
      members: ['A'],
      uncovered: []
    })
  })

  it('does not bind a row signed for another vault', async () => {
    const [A] = await setup(['A'])
    const writer = await strayWriter(A)
    await addDevice(
      A,
      signRow(
        rowFor('R', makeKeyPair(), writer.key),
        writer.keyPair,
        Buffer.alloc(32, 9)
      )
    )

    expect(await A.store.ensureEpoch({ start: true })).toMatchObject({
      rotated: true,
      members: ['A'],
      uncovered: ['R']
    })
  })

  it('re-signs my unsigned row when my store opens, and is sealed to next', async () => {
    const [A, B] = await setup(['A', 'B'])
    // An older build wrote B's row without a signature.
    await addDevice(B, rowFor('B', B.keyPair, B.instance.writerKey))
    await sync(A, B)
    expect(await A.store.ensureEpoch({ start: true })).toMatchObject({
      members: ['A'],
      uncovered: ['B']
    })
    await sync(A, B)

    createEpochStore({
      instance: B.instance,
      getPersonalKeyPair: async () => B.keyPair
    })
    for (let i = 0; i < 100; i++) {
      if (JSON.parse((await B.instance.get('device/B')).value).sig) break
      await new Promise((resolve) => setTimeout(resolve, 10))
    }
    await sync(A, B)
    expect(await A.store.ensureEpoch({ start: false })).toMatchObject({
      rotated: true,
      members: ['A', 'B'],
      uncovered: []
    })
    await A.store.add('record/x', 'v')
    await sync(A, B)
    expect(await value(B, 'record/x')).toBe('v')
  })

  it('re-signs my unsigned row in an ensureEpoch run, once per row state', async () => {
    const [A, B] = await setup(['A', 'B'])
    await addDevice(B, rowFor('B', B.keyPair, B.instance.writerKey))
    await sync(A, B)
    await A.store.ensureEpoch({ start: true })
    await sync(A, B)

    const add = jest.spyOn(B.instance, 'add')
    expect(await B.store.ensureEpoch({ start: false })).toMatchObject({
      rotated: false,
      reason: 'pending',
      uncovered: []
    })
    expect(add.mock.calls.map(([key]) => key)).toEqual(['device/B'])
    await B.store.ensureEpoch({ start: false })
    expect(add).toHaveBeenCalledTimes(1)

    await sync(A, B)
    expect(await A.store.ensureEpoch({ start: false })).toMatchObject({
      rotated: true,
      members: ['A', 'B']
    })
  })

  it('leaves a row written between refresh and re-sign for the next run', async () => {
    const [A, B] = await setup(['A', 'B'])
    // The second key pair lookup of a run is resignMyRows', after the
    // refresh read the roster.
    let healAt = 0
    const store = createEpochStore({
      instance: B.instance,
      getPersonalKeyPair: async () => {
        if (healAt > 0 && --healAt === 0) {
          await addDevice(B, {
            ...rowFor('B', B.keyPair, B.instance.writerKey),
            name: 'healed'
          })
        }
        return B.keyPair
      }
    })
    await store.refresh()
    await addDevice(B, rowFor('B', B.keyPair, B.instance.writerKey))

    healAt = 2
    await store.ensureEpoch({ start: false })
    const row = async () => JSON.parse((await B.instance.get('device/B')).value)
    expect(await row()).toMatchObject({ name: 'healed' })

    await store.ensureEpoch({ start: false })
    expect(await row()).toMatchObject({
      name: 'healed',
      sig: expect.any(String)
    })
    await sync(A, B)
    expect(await A.store.ensureEpoch({ start: true })).toMatchObject({
      members: ['A', 'B'],
      uncovered: []
    })
  })

  it('re-signs my row again on the next run after the write failed', async () => {
    const [, B] = await setup(['A', 'B'])
    await addDevice(B, rowFor('B', B.keyPair, B.instance.writerKey))
    jest
      .spyOn(B.instance, 'add')
      .mockRejectedValueOnce(new Error('append failed'))

    const sig = async () =>
      JSON.parse((await B.instance.get('device/B')).value).sig
    await B.store.ensureEpoch({ start: false })
    expect(await sig()).toBeUndefined()
    await B.store.ensureEpoch({ start: false })
    expect(await sig()).toBeTruthy()
  })

  it('rotates while a re-sign of my other row keeps failing', async () => {
    const [, B] = await setup(['A', 'B'])
    await addDevice(B, rowFor('B2', B.keyPair, B.instance.writerKey))
    const add = B.instance.add.bind(B.instance)
    jest
      .spyOn(B.instance, 'add')
      .mockImplementation((key, ...rest) =>
        key === 'device/B2'
          ? Promise.reject(new Error('append failed'))
          : add(key, ...rest)
      )

    expect(await B.store.ensureEpoch({ start: true })).toMatchObject({
      rotated: true,
      members: ['A', 'B']
    })
    expect(B.logger.warn).toHaveBeenCalledWith(
      'epochStore: could not re-sign my roster row',
      { error: 'Error' }
    )
  })

  it('writes my unsigned row once per state when it cannot sign it', async () => {
    const [, B] = await setup(['A', 'B'])
    await addDevice(B, rowFor('B', B.keyPair, B.instance.writerKey))
    // Without the vault key no row signs or verifies.
    const { key } = B.instance.base
    B.instance.base.key = null
    const add = jest.spyOn(B.instance, 'add')
    try {
      await B.store.ensureEpoch({ start: false })
      await B.store.ensureEpoch({ start: false })
    } finally {
      B.instance.base.key = key
    }
    expect(add.mock.calls.map(([k]) => k)).toEqual(['device/B'])
  })

  it('stores my own row unsigned while the base is not writable', async () => {
    const [, B] = await setup(['A', 'B'])
    // Appends still go through; only the store's writable check says no.
    Object.defineProperty(B.instance.base, 'writable', {
      value: false,
      configurable: true
    })
    try {
      await B.store.add(
        'device/B',
        JSON.stringify(rowFor('B', B.keyPair, B.instance.writerKey))
      )
    } finally {
      delete B.instance.base.writable
    }
    const row = JSON.parse((await B.instance.get('device/B')).value)
    expect(row.sig).toBeUndefined()
    expect(row.writerPublicKey).toBeUndefined()
  })

  it('never re-signs a row with my masterTopic under another writer key', async () => {
    const [A, B] = await setup(['A', 'B'])
    await addDevice(B, rowFor('B2', B.keyPair, A.instance.writerKey))
    const add = jest.spyOn(B.instance, 'add')
    await B.store.ensureEpoch({ start: false })
    expect(add).not.toHaveBeenCalled()
  })

  it('rotates for a key whose author has only an unbound row', async () => {
    const [A] = await setup(['A'])
    const O = makeKeyPair()
    await addDevice(A, { ...rowFor('O', O), writerKey: undefined })
    // O's epoch gave A a key; A's latest box lacks it and seals to no device
    // O's did not, so only O's unbound row makes the key A's to carry.
    const e1 = '01'.repeat(16)
    const e2 = '02'.repeat(16)
    const records = [
      epochBy(O, {
        id: e1,
        seq: 1,
        ring: { [e1]: generateEpochKey() },
        to: [
          ['A', A.keyPair],
          ['O', O]
        ]
      }),
      epochBy(A.keyPair, {
        id: e2,
        seq: 2,
        prev: e1,
        ring: { [e2]: generateEpochKey() },
        to: [['A', A.keyPair]]
      })
    ]
    for (const record of records) {
      await A.instance.add(`epoch/${record.id}`, JSON.stringify(record))
    }

    expect(await A.store.ensureEpoch({ start: false })).toMatchObject({
      rotated: true,
      seq: 3,
      members: ['A'],
      uncovered: ['O']
    })
  })

  it('seals to a device whose id is __proto__ and then stays current', async () => {
    const [A] = await setup(['A'])
    const proto = makeKeyPair()
    await addDevice(A, await strayRow(A, '__proto__', proto))

    expect(await A.store.ensureEpoch({ start: true })).toMatchObject({
      rotated: true,
      members: ['A', '__proto__'],
      uncovered: []
    })
    expect(await A.store.ensureEpoch({ start: false })).toMatchObject({
      rotated: false,
      reason: 'current'
    })
    await A.store.add('record/x', 'v')
    const asProto = createEpochStore({
      instance: A.instance,
      getPersonalKeyPair: async () => proto
    })
    expect(await value({ store: asProto }, 'record/x')).toBe('v')
  })

  it('rotates again when a chain restart sealed a partial ring', async () => {
    const [A, B, C] = await setup()
    await C.store.ensureEpoch({ start: true })
    await C.store.add('record/c', 'from C')
    const D = await makePeer('D', A)
    await A.instance.addWriter(D.instance.writerKey)
    await addDevice(A, D.row)
    await sync(A, B, C, D)
    expect(await D.store.ensureEpoch({ start: false })).toMatchObject({
      reason: 'pending'
    })

    // C leaves, and the pending joiner restarts the chain with its empty ring.
    await A.store.remove('device/C')
    await sync(A, B, D)
    expect(await D.store.ensureEpoch({ start: false })).toMatchObject({
      rotated: true,
      seq: 1,
      members: ['A', 'B', 'D']
    })
    await sync(A, B, D)

    // Same members, but A holds C's key and D's epoch did not seal it.
    expect(await A.store.ensureEpoch({ start: false })).toMatchObject({
      rotated: true,
      seq: 2,
      members: ['A', 'B', 'D']
    })
    await sync(A, B, D)
    expect(await value(D, 'record/c')).toBe('from C')
    for (const peer of [A, B, D]) {
      expect(await peer.store.ensureEpoch({ start: false })).toMatchObject({
        rotated: false,
        reason: 'current'
      })
    }
  })

  it('carries a losing epoch key to a member that joined during the race', async () => {
    const [A, B] = await setup(['A', 'B'])
    const M = await makePeer('M', A)
    await A.instance.addWriter(M.instance.writerKey)
    await addDevice(A, M.row)

    // B starts an epoch before it sees M. Its id is all zeros, so A's wins.
    const random = sodium.randombytes_buf
    const lowId = jest
      .spyOn(sodium, 'randombytes_buf')
      .mockImplementation((buf) =>
        buf.length === 16 ? buf.fill(0) : random.call(sodium, buf)
      )
    let fromB
    try {
      fromB = await B.store.ensureEpoch({ start: true })
    } finally {
      lowId.mockRestore()
    }
    const fromA = await A.store.ensureEpoch({ start: true })
    expect(fromB).toMatchObject({ rotated: true, seq: 1, members: ['A', 'B'] })
    expect(fromA).toMatchObject({
      rotated: true,
      seq: 1,
      members: ['A', 'B', 'M']
    })
    await B.store.add('record/b', 'from B')
    expect((await rawEnvelope(B, 'record/b')).e).toBe(fromB.id)
    await sync(A, B, M)
    expect((await A.store.status()).epoch).toBe(fromA.id)

    // B goes offline. A holds B's key, and latest seals to M, which B's
    // epoch did not.
    expect(await A.store.ensureEpoch({ start: false })).toMatchObject({
      rotated: true,
      seq: 2,
      members: ['A', 'B', 'M']
    })
    await sync(A, M)
    expect(await value(M, 'record/b')).toBe('from B')
    for (const peer of [A, M]) {
      expect(await peer.store.ensureEpoch({ start: false })).toMatchObject({
        rotated: false,
        reason: 'current'
      })
    }
  })

  it('reads while a rotation is owed only when it holds every epoch key', async () => {
    const [A, B, C] = await setup()
    await C.store.ensureEpoch({ start: true })
    await sync(A, B, C)
    const D = await makePeer('D', A)
    await A.instance.addWriter(D.instance.writerKey)
    await A.store.remove('device/C')
    await sync(A, B, D)

    expect(await B.store.status()).toMatchObject({
      epoch: null,
      legacy: false,
      canRead: true
    })
    expect(await D.store.status()).toMatchObject({
      epoch: null,
      canRead: false
    })
  })

  it('leaves plaintext mode for an unparsable epoch row alone', async () => {
    const [A] = await setup(['A'])
    await A.instance.add('epoch/x', 'not json')

    expect(await A.store.status()).toMatchObject({ legacy: false, epoch: null })
    await A.store.add('record/r', 'v')
    expect((await rawEnvelope(A, 'record/r')).$enc).toBe(1)
    expect(await value(A, 'record/r')).toBe('v')
  })

  it('refuses add and remove on epoch keys', async () => {
    const [A] = await setup(['A'])
    const { id } = await A.store.ensureEpoch({ start: true })

    await expect(A.store.add(`epoch/${id}`, '{}')).rejects.toThrow(
      EpochRecordWriteError
    )
    await expect(A.store.add('epoch/new', '{}')).rejects.toThrow(
      EpochRecordWriteError
    )
    await expect(A.store.remove(`epoch/${id}`)).rejects.toThrow(
      EpochRecordWriteError
    )
    expect(await A.instance.get(`epoch/${id}`)).not.toBeNull()
    expect(await A.instance.get('epoch/new')).toBeNull()
    expect((await A.store.status()).epoch).toBe(id)
  })

  it('retries a refresh that failed instead of replaying the failure', async () => {
    const [A] = await setup(['A'])
    await A.store.ensureEpoch({ start: true })
    await A.store.add('record/r', 'v')
    let fail = false
    const store = createEpochStore({
      instance: A.instance,
      getPersonalKeyPair: async () => {
        if (!fail) return A.keyPair
        fail = false
        throw new Error('key store busy')
      }
    })
    expect((await store.get('record/r')).value).toBe('v')

    fail = true
    await expect(store.refresh()).rejects.toThrow('key store busy')
    expect((await store.get('record/r')).value).toBe('v')
    expect((await store.status()).canRead).toBe(true)
  })

  it('reads from a fresh store while another refresh fails', async () => {
    const [A] = await setup(['A'])
    await A.store.ensureEpoch({ start: true })
    await A.store.add('record/r', 'v')
    let fail = false
    const store = createEpochStore({
      instance: A.instance,
      getPersonalKeyPair: async () => {
        if (!fail) return A.keyPair
        fail = false
        throw new Error('key store busy')
      }
    })
    expect((await store.get('record/r')).value).toBe('v')

    fail = true
    const failing = store.refresh()
    const read = store.get('record/r')
    await expect(failing).rejects.toThrow('key store busy')
    expect((await read).value).toBe('v')
  })

  it('reports revoked only when every clause of the rule holds', async () => {
    expect(await revokedFor()).toBe(true)
    // No accepted epoch: its only author left the roster.
    expect(await revokedFor({ authorInRoster: false })).toBe(false)
    expect(await revokedFor({ heldKey: false })).toBe(false)
    expect(await revokedFor({ wrote: false })).toBe(false)
    expect(await revokedFor({ inLatest: true })).toBe(false)
    expect(
      await revokedFor({ myRow: (X) => strayRow(X, 'X', X.keyPair) })
    ).toBe(false)
    // My row without a masterTopic still names me by its writer key.
    expect(
      await revokedFor({
        myRow: (X) => ({ id: 'X', writerKey: X.row.writerKey })
      })
    ).toBe(false)
  })

  it('fills a find limit with readable rows, forwards and in reverse', async () => {
    const [A] = await setup(['A'])
    await A.store.ensureEpoch({ start: true })
    for (const n of [1, 3, 5]) await A.store.add(`record/${n}`, `v${n}`)
    for (const n of [2, 4]) await A.instance.add(`record/${n}`, UNREADABLE)
    const range = { gte: { key: 'record/' }, lt: { key: 'record0' } }
    const keys = async (opts) =>
      (await A.store.find({ ...range, ...opts })).map((r) => r.key)

    expect(await keys({ limit: 2 })).toEqual(['record/1', 'record/3'])
    expect(await keys({ limit: 2, reverse: true })).toEqual([
      'record/5',
      'record/3'
    ])
    expect(await keys({ limit: 0 })).toEqual([])
    expect(await keys({})).toEqual(['record/1', 'record/3', 'record/5'])
  })

  it('refreshes at most once per find while updates keep landing', async () => {
    const [A] = await setup(['A'])
    await A.store.ensureEpoch({ start: true })
    for (const n of [1, 2, 3]) await A.instance.add(`record/${n}`, UNREADABLE)
    let refreshes = 0
    // Every refresh sees a new update land, so the view always looks stale.
    const store = createEpochStore({
      instance: A.instance,
      getPersonalKeyPair: async () => {
        refreshes++
        A.instance.emit('update')
        return A.keyPair
      }
    })
    await store.status()

    refreshes = 0
    expect(
      await store.find({ gte: { key: 'record/' }, lt: { key: 'record0' } })
    ).toEqual([])
    // One to catch up on entry, one retry for the unreadable rows.
    expect(refreshes).toBeLessThanOrEqual(2)
  })

  it('keeps a failed start owed across a store restart', async () => {
    const [A] = await setup(['A'])
    Object.defineProperty(A.instance.base, 'writable', {
      value: false,
      configurable: true
    })
    expect(await A.store.ensureEpoch({ start: true })).toMatchObject({
      rotated: false,
      reason: 'not-writable'
    })

    delete A.instance.base.writable
    const restart = () =>
      createEpochStore({
        instance: A.instance,
        getPersonalKeyPair: async () => A.keyPair
      })
    expect(await restart().ensureEpoch({ start: false })).toMatchObject({
      rotated: true,
      seq: 1
    })
    expect(await restart().ensureEpoch({ start: false })).toMatchObject({
      rotated: false,
      reason: 'current'
    })
  })

  it('writes an owed start again after its write failed', async () => {
    const [A] = await setup(['A'])
    Object.defineProperty(A.instance.base, 'writable', {
      value: false,
      configurable: true
    })
    const { local } = A.instance.base
    local.setUserData = async () => {
      delete local.setUserData
      throw new Error('disk full')
    }
    expect(await A.store.ensureEpoch({ start: true })).toMatchObject({
      reason: 'not-writable'
    })
    // A later run, still unable to rotate, writes the owed start.
    expect(await A.store.ensureEpoch({ start: false })).toMatchObject({
      reason: 'not-writable'
    })

    delete A.instance.base.writable
    const restarted = createEpochStore({
      instance: A.instance,
      getPersonalKeyPair: async () => A.keyPair
    })
    expect(await restarted.ensureEpoch({ start: false })).toMatchObject({
      rotated: true,
      seq: 1
    })
  })

  it('leaves an owed start in place when a run cannot read it', async () => {
    const [A] = await setup(['A'])
    Object.defineProperty(A.instance.base, 'writable', {
      value: false,
      configurable: true
    })
    await A.store.ensureEpoch({ start: true })
    delete A.instance.base.writable

    // Only the store's read fails: setUserData reads through getUserData.
    const { local } = A.instance.base
    local.getUserData = async () => {
      delete local.getUserData
      throw new Error('disk busy')
    }
    const restart = () =>
      createEpochStore({
        instance: A.instance,
        getPersonalKeyPair: async () => A.keyPair
      })
    expect(await restart().ensureEpoch({ start: false })).toMatchObject({
      rotated: false,
      reason: 'legacy'
    })

    expect(await restart().ensureEpoch({ start: false })).toMatchObject({
      rotated: true,
      seq: 1
    })
  })

  it('keeps a start owed when the run throws', async () => {
    const [A] = await setup(['A'])
    let fail = true
    const failing = createEpochStore({
      instance: A.instance,
      getPersonalKeyPair: async () => {
        if (!fail) return A.keyPair
        throw new Error('key store busy')
      }
    })
    await expect(failing.ensureEpoch({ start: true })).rejects.toThrow(
      'key store busy'
    )
    fail = false

    const restarted = createEpochStore({
      instance: A.instance,
      getPersonalKeyPair: async () => A.keyPair
    })
    expect(await restarted.ensureEpoch({ start: false })).toMatchObject({
      rotated: true,
      seq: 1
    })
  })

  it('refuses a write it cannot rotate for while the epoch lists a removed device', async () => {
    const [A, B, C] = await setup()
    await A.store.ensureEpoch({ start: true })
    await sync(A, B, C)
    await A.store.remove('device/C')
    await sync(A, B)
    Object.defineProperty(B.instance.base, 'writable', {
      value: false,
      configurable: true
    })

    await expect(B.store.add('record/s', 'secret')).rejects.toThrow(
      EpochRotationPendingError
    )
    expect(await B.instance.get('record/s')).toBeNull()
  })

  it('reports each row find cannot read to onUnreadable', async () => {
    const [A] = await setup(['A'])
    await A.store.ensureEpoch({ start: true })
    await A.store.add('record/1', 'v1')
    await A.instance.add('record/2', UNREADABLE)
    const unreadable = []

    const found = await A.store.find({
      gte: { key: 'record/' },
      lt: { key: 'record0' },
      onUnreadable: (key) => unreadable.push(key)
    })
    expect(found.map((r) => r.key)).toEqual(['record/1'])
    expect(unreadable).toEqual(['record/2'])
  })

  it('verifies an epoch row once, and again once it changes', async () => {
    const [A] = await setup(['A'])
    const { id } = await A.store.ensureEpoch({ start: true })
    const store = createEpochStore({
      instance: A.instance,
      getPersonalKeyPair: async () => A.keyPair
    })
    const verify = jest.spyOn(sodium, 'crypto_sign_verify_detached')
    // Hypercore verifies its blocks too; count only A's epoch signatures.
    const epochVerifies = () =>
      verify.mock.calls.filter(([, , key]) => key.equals(A.keyPair.publicKey))
        .length
    try {
      await store.refresh()
      expect(epochVerifies()).toBe(1)
      await store.refresh()
      expect(epochVerifies()).toBe(1)

      // Same key and sig over other bytes: verified again, and refused.
      const record = JSON.parse((await A.instance.get(`epoch/${id}`)).value)
      await A.instance.add(
        `epoch/${id}`,
        JSON.stringify({ ...record, createdAt: record.createdAt + 1 })
      )
      await store.refresh()
      expect(epochVerifies()).toBe(2)
      // Refused, but the row still ends plaintext mode.
      expect(await store.status()).toMatchObject({ legacy: false, epoch: null })
    } finally {
      verify.mockRestore()
    }
  })

  it('opens each epoch check once per key', async () => {
    const [A] = await setup(['A'])
    const { id } = await A.store.ensureEpoch({ start: true })
    const { check } = JSON.parse((await A.instance.get(`epoch/${id}`)).value)
    const store = createEpochStore({
      instance: A.instance,
      getPersonalKeyPair: async () => A.keyPair
    })
    const open = jest.spyOn(sodium, 'crypto_secretbox_open_easy')
    const checkOpens = () =>
      open.mock.calls.filter(([, c]) => c.toString('base64') === check.c).length
    try {
      await store.refresh()
      expect(checkOpens()).toBe(1)
      await store.refresh()
      expect(checkOpens()).toBe(1)
      expect((await store.status()).canRead).toBe(true)
    } finally {
      open.mockRestore()
    }
  })

  it('drops the old key once the author rewrites its epoch with a new one', async () => {
    const [A] = await setup(['A'])
    const { id } = await A.store.ensureEpoch({ start: true })
    await A.store.add('record/old', 'v')

    // Same id, a new key and check, signed again.
    const rewritten = epochBy(A.keyPair, {
      id,
      seq: 1,
      ring: { [id]: generateEpochKey() },
      to: [['A', A.keyPair]]
    })
    await A.instance.add(`epoch/${id}`, JSON.stringify(rewritten))
    await A.store.refresh()

    expect(await A.store.get('record/old')).toBeNull()
    await A.store.add('record/new', 'w')
    const fresh = createEpochStore({
      instance: A.instance,
      getPersonalKeyPair: async () => A.keyPair
    })
    expect(await value({ store: fresh }, 'record/new')).toBe('w')
  })

  it('does not move latest back when an older epoch is appended again', async () => {
    const [A, B] = await setup(['A', 'B'])
    // The older epoch sorts last by key and is appended last, so only seq
    // can tell the two apart.
    const older = 'ff'.repeat(16)
    const newer = '00'.repeat(16)
    const keys = { [older]: generateEpochKey(), [newer]: generateEpochKey() }
    const to = [
      ['A', A.keyPair],
      ['B', B.keyPair]
    ]
    const olderRecord = JSON.stringify(
      epochBy(A.keyPair, {
        id: older,
        seq: 1,
        ring: { [older]: keys[older] },
        to
      })
    )
    const newerRecord = epochBy(A.keyPair, {
      id: newer,
      seq: 2,
      prev: older,
      ring: keys,
      to
    })
    await A.instance.add(`epoch/${older}`, olderRecord)
    await A.instance.add(`epoch/${newer}`, JSON.stringify(newerRecord))
    await A.instance.remove(`epoch/${older}`)
    await A.instance.add(`epoch/${older}`, olderRecord)
    await sync(A, B)

    for (const peer of [A, B]) {
      expect(await peer.store.status()).toMatchObject({
        epoch: newer,
        seq: 2
      })
    }
    await B.store.add('record/r', 'v')
    expect((await rawEnvelope(B, 'record/r')).e).toBe(newer)

    await addDevice(A, await strayRow(A, 'D'))
    expect(await A.store.ensureEpoch({ start: false })).toMatchObject({
      rotated: true,
      seq: 3
    })
  })

  it('settles two rotations made at once by different members', async () => {
    const [A, B, C, D] = await setup(['A', 'B', 'C', 'D'])
    await A.store.ensureEpoch({ start: true })
    await sync(A, B, C, D)

    // A drops C and B drops D before either sees the other's rotation.
    await A.store.remove('device/C')
    await B.store.remove('device/D')
    const [fromA, fromB] = await Promise.all([
      A.store.ensureEpoch({ start: true }),
      B.store.ensureEpoch({ start: true })
    ])
    expect(fromA).toMatchObject({ rotated: true, seq: 2 })
    expect(fromB).toMatchObject({ rotated: true, seq: 2 })
    expect(fromA.members).toEqual(['A', 'B', 'D'])
    expect(fromB.members).toEqual(['A', 'B', 'C'])
    await sync(A, B)

    // Either seq-2 epoch still lists a removed device, so the next run
    // rotates past both; the other member then finds it current.
    expect(await A.store.ensureEpoch({ start: false })).toMatchObject({
      rotated: true,
      seq: 3,
      members: ['A', 'B']
    })
    await sync(A, B)
    expect(await B.store.ensureEpoch({ start: false })).toMatchObject({
      rotated: false,
      reason: 'current'
    })

    await B.store.add('record/after', 'v')
    await sync(A, B, C, D)
    expect(await value(A, 'record/after')).toBe('v')
    expect(await C.store.get('record/after')).toBeNull()
    expect(await D.store.get('record/after')).toBeNull()
  })

  it('settles members that keep rotating at once after a removal', async () => {
    const [A, B, C] = await setup()
    await A.store.ensureEpoch({ start: true })
    await sync(A, B, C)
    await A.store.remove('device/C')
    await sync(A, B)

    // Each round both run before either sees the other's epoch. After the
    // first, each writes under its own epoch.
    const rounds = []
    for (let round = 0; round < 5; round++) {
      const results = await Promise.all([
        A.store.ensureEpoch({ start: false }),
        B.store.ensureEpoch({ start: false })
      ])
      if (round === 0) {
        for (const [peer, result] of [
          [A, results[0]],
          [B, results[1]]
        ]) {
          await peer.store.add(`record/${peer.id}`, peer.id)
          expect((await rawEnvelope(peer, `record/${peer.id}`)).e).toBe(
            result.id
          )
        }
      }
      await sync(A, B)
      rounds.push({
        reasons: results.map((result) => result.reason ?? 'rotated'),
        seq: (await A.store.status()).seq
      })
    }
    expect(rounds[0].reasons).toEqual(['rotated', 'rotated'])
    // The winner's author is current; the loser carries its own key once.
    expect(rounds[1].reasons).toContain('rotated')
    const settled = rounds.findIndex(({ reasons }) =>
      reasons.every((reason) => reason === 'current')
    )
    expect(settled).toBe(2)
    for (const { reasons, seq } of rounds.slice(settled)) {
      expect(reasons).toEqual(['current', 'current'])
      expect(seq).toBe(rounds[settled].seq)
    }
    for (const peer of [A, B]) {
      for (const writer of [A, B]) {
        expect(await value(peer, `record/${writer.id}`)).toBe(writer.id)
      }
    }
  })

  it('settles three members that keep rotating at once', async () => {
    const [A, B, C, D] = await setup(['A', 'B', 'C', 'D'])
    await A.store.ensureEpoch({ start: true })
    await sync(A, B, C, D)
    await A.store.remove('device/D')
    await sync(A, B, C)
    const group = [A, B, C]

    // Each round all three run before any sees the others' epochs. After
    // the first, each writes under its own epoch.
    const rounds = []
    for (let round = 0; round < 6; round++) {
      const results = await Promise.all(
        group.map((peer) => peer.store.ensureEpoch({ start: false }))
      )
      if (round === 0) {
        for (const peer of group) {
          await peer.store.add(`record/${peer.id}`, peer.id)
        }
      }
      await sync(...group)
      rounds.push({
        reasons: results.map((result) => result.reason ?? 'rotated'),
        seq: (await A.store.status()).seq
      })
    }
    expect(rounds[0].reasons).toEqual(['rotated', 'rotated', 'rotated'])
    // Each round drops its winner: two losers, then one.
    const rotations = rounds.map(
      ({ reasons }) => reasons.filter((reason) => reason === 'rotated').length
    )
    expect(rotations).toEqual([3, 2, 1, 0, 0, 0])
    expect(new Set(rounds.slice(3).map(({ seq }) => seq)).size).toBe(1)
    for (const peer of group) {
      for (const writer of group) {
        expect(await value(peer, `record/${writer.id}`)).toBe(writer.id)
      }
    }
  })

  it('keeps vault-ext plaintext once an epoch exists', async () => {
    const [A, B, C] = await setup()
    await kick(A, C)
    await A.store.add('vault-ext', '{"migratedToSchema":2}')
    await A.store.add('vault-extra', 'x')
    await sync(A, B, C)

    expect((await A.instance.get('vault-ext')).value).toBe(
      '{"migratedToSchema":2}'
    )
    // A device without the key still sees the migration state.
    expect(await value(C, 'vault-ext')).toBe('{"migratedToSchema":2}')
    expect((await rawEnvelope(A, 'vault-extra')).$enc).toBe(1)
  })

  it('leaves a record readable to the kicked device when its writer had not seen the kick', async () => {
    const [A, B, C] = await setup()
    const first = await A.store.ensureEpoch({ start: true })
    await sync(A, B, C)

    // B does not sync the kick before it writes.
    await kick(A, C)
    await B.store.add('record/stale', 'from B')
    await A.store.add('record/fresh', 'from A')
    await sync(A, B, C)

    // B's roster still listed C, so B wrote under the epoch C holds.
    expect((await rawEnvelope(C, 'record/stale')).e).toBe(first.id)
    expect(await value(C, 'record/stale')).toBe('from B')
    expect(await value(C, 'record/fresh')).toBeNull()
    expect(await value(B, 'record/fresh')).toBe('from A')
  })

  it('keeps a puppet writer the kicked device added as a member until it is kicked too', async () => {
    const [A, B, C] = await setup()
    // Before its removal lands, C adds writer P and P's bound row.
    const P = await makePeer('P', A)
    await C.instance.addWriter(P.instance.writerKey)
    await addDevice(C, P.row)
    await sync(A, B, C, P)

    expect(await kick(A, C)).toMatchObject({
      rotated: true,
      members: ['A', 'B', 'P']
    })
    await A.store.add('record/1', 'v1')
    await sync(A, B, C, P)
    expect((await A.store.status()).members).toEqual(['A', 'B', 'P'])
    expect(await value(P, 'record/1')).toBe('v1')

    expect(await kick(A, P)).toMatchObject({
      rotated: true,
      members: ['A', 'B']
    })
    await A.store.add('record/2', 'v2')
    await sync(A, B, C, P)
    expect((await A.store.status()).members).toEqual(['A', 'B'])
    expect(await value(B, 'record/2')).toBe('v2')
    expect(await value(P, 'record/2')).toBeNull()
  })
})
