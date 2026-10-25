import crypto from 'crypto'

import {
  converge,
  createNetwork,
  epochRows,
  holdsEpoch,
  holdsMembers,
  indexOf,
  noKeyAfter,
  revokedStatus,
  sealedFrom,
  settledUnaided,
  shareVault,
  waitFor
} from './harness.js'
import { short } from './tracer.js'
import {
  buildEpochRecord,
  generateEpochId
} from '../../src/worklet/epoch/epochRecord.js'
import {
  generateEpochKey,
  sealCheck,
  sealRing
} from '../../src/worklet/epoch/keyring.js'

/* global jest */

const INVALID = 'epochStore: ignoring invalid epoch record'

const summary = async (peer) => {
  const { epoch, seq, members, canRead } = await peer.epochStatus()
  return { epoch, seq, members, canRead }
}

// The first record with its id swapped for `id`, stored under epoch/<id>:
// the key check passes, so only the signature check can reject it.
const reId = (raw, id) => JSON.stringify({ ...JSON.parse(raw), id })

// A record `peer` signs with its own personal key, sealed to itself only,
// one above `latest`: valid, chained, and rejected only because its author
// is not a roster device.
const selfSigned = async (peer, latest) => {
  const id = generateEpochId()
  const key = generateEpochKey()
  const ring = Object.assign(Object.create(null), { [id]: key })
  const box = sealRing(ring, [
    { id: peer.deviceId, masterTopic: peer.masterTopic }
  ])[peer.deviceId]
  return buildEpochRecord({
    vault: peer.instance.base.key.toString('hex'),
    id,
    seq: latest.seq + 1,
    prev: latest.epoch,
    members: { [peer.deviceId]: { topic: peer.masterTopic, box } },
    check: sealCheck(key),
    personalKeyPair: await peer.appDeps.getPersonalKeyPair()
  })
}

// ADR 0014: an epoch record "chains to the previous one by sequence number"
// and is signed by its author over its id, so "a planted record cannot
// jump the sequence ahead". A replayed old record is either the same row
// (under its own key) or invalid (its id rewritten: the signature fails);
// a record the kicked device signs itself stops counting once its removal
// lands. The latest epoch does not move and the removed device gets no key.
describe('replay of an old epoch record (ADR 0014)', () => {
  let net = null

  afterEach(async () => {
    jest.restoreAllMocks()
    await net?.destroy()
    net = null
  })

  test('a member and the kicked device replant the first record; the latest epoch and its members do not move', async () => {
    net = await createNetwork({ peers: ['A', 'B', 'C'] })
    const { A, B, C } = net.peers
    await shareVault(net)
    const warn = Object.fromEntries(
      net.list.map((peer) => [
        peer.id,
        jest.spyOn(peer.modules.logger.workletLogger, 'warn')
      ])
    )

    const first = await A.ensureEpoch({ start: true })
    expect(first).toMatchObject({
      rotated: true,
      members: ['device-A', 'device-B', 'device-C']
    })
    for (const peer of [B, C]) await holdsEpoch(peer, first.id)
    await A.add('note/before', { text: 'everyone' })
    expect(await converge(net.list, 'note/before')).toMatchObject({
      text: 'everyone'
    })
    // The first record as stored: the JSON string the rotation appended.
    const old = (await A.instance.get(`epoch/${first.id}`)).value
    expect(JSON.parse(old)).toMatchObject({ id: first.id, seq: 1 })

    // C is offline for the kick, so its own Autobase still lets it append.
    await C.goOffline()
    const kicked = await A.kick('device-C')
    expect(kicked).toMatchObject({
      rotated: true,
      members: ['device-A', 'device-B']
    })
    // B may rotate for the same removal too, so the baseline is the epoch
    // A and B settle on, not the kick's own.
    await holdsMembers(B, ['device-A', 'device-B'], { besides: first.id })
    await A.add('note/after', { text: 'members only' })
    expect(await converge([A, B], 'note/after')).toMatchObject({
      text: 'members only'
    })
    await settledUnaided(net, [A, B], ['device-A', 'device-B'])
    const before = { A: await summary(A), B: await summary(B) }
    expect(before.B).toEqual(before.A)
    expect(before.A).toMatchObject({
      members: ['device-A', 'device-B'],
      canRead: true
    })
    expect(before.A.seq).toBeGreaterThanOrEqual(2)

    // A member replays: under the old key (the same row again) and under a
    // fresh key with the id rewritten to match (the signature no longer
    // covers it).
    const plantedByA = crypto.randomBytes(16).toString('hex')
    const forgedByA = reId(old, plantedByA)
    A.trace('test.replay')
    await A.instance.add(`epoch/${first.id}`, old)
    await A.instance.add(`epoch/${plantedByA}`, forgedByA)
    await A.add('marker/a', { done: true })
    expect(await converge([A, B], 'marker/a')).toEqual({ done: true })
    expect(await summary(A)).toEqual(before.A)
    expect(await summary(B)).toEqual(before.B)
    for (const peer of [A, B]) {
      expect(await peer.raw(`epoch/${plantedByA}`)).toMatchObject({
        value: forgedByA
      })
      expect(warn[peer.id]).toHaveBeenCalledWith(
        INVALID,
        expect.objectContaining({ key: `epoch/${plantedByA}` })
      )
    }

    // The kicked device replays both ways while its removal has not reached
    // it and writes a marker of its own.
    expect(C.instance.base.writable).toBe(true)
    const plantedByC = crypto.randomBytes(16).toString('hex')
    await C.instance.add(`epoch/${first.id}`, old)
    await C.instance.add(`epoch/${plantedByC}`, reId(old, plantedByC))
    await C.add('marker/c', { done: true })
    expect(await C.epochStatus()).toMatchObject({
      epoch: first.id,
      canRead: true,
      revoked: false
    })
    expect(warn.C).toHaveBeenCalledWith(
      INVALID,
      expect.objectContaining({ key: `epoch/${plantedByC}` })
    )
    // Last, still apart, C signs a record of its own one above the latest A
    // and B agreed on, and heals. C still counts itself a member and holds a
    // key above its latest, so it may rotate for it (skippedAhead): more
    // epochs by C, holding only keys C has.
    const byC = await selfSigned(C, before.A)
    await C.instance.add(`epoch/${byC.id}`, JSON.stringify(byC))
    await C.goOnline()

    expect(
      await revokedStatus(C, (s) => s.epoch === before.A.epoch)
    ).toMatchObject({ canRead: false })
    await sealedFrom(C, 'note/after', 'members only')
    expect(await C.get('note/before')).toMatchObject({ text: 'everyone' })
    // Above the first, only records C signed itself list C.
    const authoredByC = new Set(
      (await epochRows(C))
        .filter(({ record }) => record.by === C.masterTopic)
        .map(({ record }) => short(record.id))
    )
    await noKeyAfter(C, {
      lastHeldSeq: first.seq,
      allow: (record) => record.by === C.masterTopic
    })
    // One more round trip after the heal, then judge A and B.
    await A.add('marker/healed', { done: true })
    expect(await converge([A, B], 'marker/healed')).toEqual({ done: true })
    await waitFor(() => C.raw('marker/healed'), {
      label: 'C holds the healed marker'
    })
    expect(await summary(A)).toEqual(before.A)
    expect(await summary(B)).toEqual(before.B)
    for (const peer of [A, B]) {
      expect(await peer.get('note/before')).toMatchObject({ text: 'everyone' })
      expect(await peer.get('note/after')).toMatchObject({
        text: 'members only'
      })
      expect(await peer.get('marker/a')).toEqual({ done: true })
    }
    // Whether Autobase ordered C's concurrent appends before its removal is
    // its own call (C's own record landed in 2 to 4 of 10 runs; otherwise the
    // view drops it, C's included). Where the rewritten record lands it is
    // invalid; where C's own record lands it verifies and chains, so the
    // author check is what keeps it from being latest.
    await A.instance.base.update()
    const landed = await A.raw(`epoch/${plantedByC}`)
    const landedByC = await A.raw(`epoch/${byC.id}`)
    // eslint-disable-next-line no-console
    console.log(
      `C's planted records reached A: rewritten ${landed !== null}, ` +
        `self-signed ${landedByC !== null}; epochs by C on C: ${authoredByC.size}`
    )
    if (landed) {
      expect(warn.A).toHaveBeenCalledWith(
        INVALID,
        expect.objectContaining({ key: `epoch/${plantedByC}` })
      )
    }
    for (const peer of [A, B]) {
      expect(warn[peer.id]).not.toHaveBeenCalledWith(
        INVALID,
        expect.objectContaining({ key: `epoch/${byC.id}` })
      )
    }

    // Traces: a status is pushed only when it changed. The last one A and
    // B each pushed is the settled epoch with its two members, and none
    // pushed from the first replay on names anything else.
    const { events } = net
    const replay = indexOf(events, 'A', 'test.replay')
    expect(replay).toBeGreaterThan(indexOf(events, 'A', 'peer.kick'))
    const baseline = {
      epoch: short(before.A.epoch),
      canRead: true,
      members: ['device-A', 'device-B']
    }
    for (const peer of [A, B]) {
      const pushed = net.tracers[peer.id].events.filter(
        (e) => e.event === 'epoch.status'
      )
      expect(pushed.at(-1)).toMatchObject(baseline)
    }
    const later = events
      .slice(replay)
      .filter((e) => ['A', 'B'].includes(e.peer) && e.event === 'epoch.status')
    for (const status of later) expect(status).toMatchObject(baseline)
    expect(
      net.tracers.C.events.filter(
        (e) =>
          e.event === 'epoch.status' &&
          e.epoch !== null &&
          e.epoch !== short(first.id) &&
          !authoredByC.has(e.epoch) &&
          e.canRead
      )
    ).toEqual([])
  })
})
