import crypto from 'crypto'

import {
  converge,
  createNetwork,
  holdsEpoch,
  holdsMembers,
  indexOf,
  revokedStatus,
  sealedFrom,
  settledEpoch,
  shareVault,
  waitFor
} from './harness.js'
import { short } from './tracer.js'

/* global jest */

const INVALID = 'epochStore: ignoring invalid epoch record'

const summary = async (peer) => {
  const { epoch, seq, members, canRead } = await peer.epochStatus()
  return { epoch, seq, members, canRead }
}

// ADR 0014: an epoch record "chains to the previous one by sequence number"
// and is signed by its author over its id, so "a planted record cannot
// jump the sequence ahead". A replayed old record is either the same row
// (under its own key) or invalid (under any other key); the latest epoch
// does not move and the removed device gets no key.
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
    await settledEpoch([A, B], ['device-A', 'device-B'])
    const before = { A: await summary(A), B: await summary(B) }
    expect(before.B).toEqual(before.A)
    expect(before.A).toMatchObject({
      members: ['device-A', 'device-B'],
      canRead: true
    })
    expect(before.A.seq).toBeGreaterThanOrEqual(2)

    // A member replays: under the old key (the same row again) and under a
    // fresh key (a record whose signed id is not its key).
    const plantedByA = crypto.randomBytes(16).toString('hex')
    A.trace('test.replay')
    await A.instance.add(`epoch/${first.id}`, old)
    await A.instance.add(`epoch/${plantedByA}`, old)
    await A.add('marker/a', { done: true })
    expect(await converge([A, B], 'marker/a')).toEqual({ done: true })
    expect(await summary(A)).toEqual(before.A)
    expect(await summary(B)).toEqual(before.B)
    for (const peer of [A, B]) {
      expect(await peer.raw(`epoch/${plantedByA}`)).toMatchObject({
        value: old
      })
      expect(warn[peer.id]).toHaveBeenCalledWith(
        INVALID,
        expect.objectContaining({ key: `epoch/${plantedByA}` })
      )
    }

    // The kicked device replays both ways while its removal has not reached
    // it, then writes a marker of its own and heals.
    expect(C.instance.base.writable).toBe(true)
    const plantedByC = crypto.randomBytes(16).toString('hex')
    await C.instance.add(`epoch/${first.id}`, old)
    await C.instance.add(`epoch/${plantedByC}`, old)
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
    await C.goOnline()

    expect(
      await revokedStatus(C, (s) => s.epoch === before.A.epoch)
    ).toMatchObject({ canRead: false })
    await sealedFrom(C, 'note/after', 'members only')
    expect(await C.get('note/before')).toMatchObject({ text: 'everyone' })
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
    // its own call; either way the planted record is invalid where it lands.
    const landed = await A.raw(`epoch/${plantedByC}`)
    // eslint-disable-next-line no-console
    console.log(`C's planted record reached A: ${landed !== null}`)
    if (landed) {
      expect(warn.A).toHaveBeenCalledWith(
        INVALID,
        expect.objectContaining({ key: `epoch/${plantedByC}` })
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
          e.canRead
      )
    ).toEqual([])
  })
})
