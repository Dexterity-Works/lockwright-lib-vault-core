import fs from 'fs'
import os from 'os'
import path from 'path'

import Autopass from 'autopass'
import Corestore from 'corestore'
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
  sealRing
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

const makePeer = async (id, host, keyPair = makeKeyPair()) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'epoch-store-'))
  const corestore = new Corestore(dir)
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
  peer.row = rowFor(id, keyPair, instance.writerKey)
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
  if (authorInRoster) await addDevice(X, rowFor('O', O))
  if (myRow) await addDevice(X, myRow(X))
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

    await addDevice(A, rowFor('D', makeKeyPair()))
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
    await addDevice(A, rowFor('D', makeKeyPair()))
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
    await addDevice(A, rowFor('D', makeKeyPair()))
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

  it('omits an envelope whose epoch id was edited', async () => {
    const [A, , C] = await setup()
    const first = await kick(A, C)
    await addDevice(A, rowFor('D', makeKeyPair()))
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
    await addDevice(A, rowFor('E', makeKeyPair()))
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
    await addDevice(A, { id: 'Y', masterTopic: '00'.repeat(32) })
    await addDevice(A, { id: 'Z', masterTopic: '01' + '00'.repeat(31) })

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
    await addDevice(A, { id: '0', masterTopic: 12345 })
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
    await addDevice(A, rowFor('D', makeKeyPair()))
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
    expect(await revokedFor({ myRow: (X) => rowFor('X', X.keyPair) })).toBe(
      false
    )
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
        fail = false
        throw new Error('key store busy')
      }
    })
    await expect(failing.ensureEpoch({ start: true })).rejects.toThrow(
      'key store busy'
    )

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

    await addDevice(A, rowFor('D', makeKeyPair()))
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
})
