import fs from 'fs'
import os from 'os'
import path from 'path'

import Autopass from 'autopass'
import Corestore from 'corestore'
import sodium from 'sodium-native'

import { buildEpochRecord } from './epochRecord.js'
import { createEpochStore } from './epochStore.js'

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

const makePeer = async (id, host) => {
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
  const keyPair = makeKeyPair()
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

const value = async (peer, key) => (await peer.store.get(key))?.value ?? null

const rawEnvelope = async (peer, key) =>
  JSON.parse((await peer.instance.get(key)).value)

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
    expect(await C.store.status()).toMatchObject({
      revoked: true,
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
    await expect(C.store.add('record/later', '{}')).rejects.toThrow()
  })

  it('ignores replayed, forged, and broken epoch records', async () => {
    const [A, B, C] = await setup()
    const first = await kick(A, C)
    const firstRecord = (await A.instance.get(`epoch/${first.id}`)).value
    await addDevice(A, rowFor('D', makeKeyPair()))
    const second = await A.store.ensureEpoch({ start: false })
    expect(second.seq).toBe(2)

    await A.instance.add(`epoch/${first.id}`, firstRecord)
    await A.instance.add('epoch/replayed-copy', firstRecord)
    const forged = buildEpochRecord({
      seq: 99,
      prev: second.id,
      members: {},
      personalKeyPair: makeKeyPair()
    })
    await A.instance.add(`epoch/${forged.id}`, JSON.stringify(forged))
    const broken = {
      ...buildEpochRecord({
        seq: 3,
        prev: second.id,
        members: {},
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
    expect(one).toBe(two)
    expect(one).toMatchObject({
      rotated: true,
      members: ['A'],
      uncovered: ['L']
    })
    const epochs = await A.store.find({
      gte: { key: 'epoch/' },
      lt: { key: 'epoch0' }
    })
    expect(epochs).toHaveLength(1)
  })
})
