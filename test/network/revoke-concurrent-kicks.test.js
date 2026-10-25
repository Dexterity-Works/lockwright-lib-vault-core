import {
  converge,
  createNetwork,
  holdsEpoch,
  revokedStatus,
  sealedFrom,
  settledEpoch,
  shareVault
} from './harness.js'
import { short } from './tracer.js'

// ADR 0014: "two concurrent rotations both exclude the removed device". Two
// kicks at once must settle on one epoch sealed to the two who stay.
describe('two devices kicked at the same time (ADR 0014)', () => {
  let net = null

  afterEach(async () => {
    await net?.destroy()
    net = null
  })

  test('A kicks C while B kicks D; one epoch for A and B, C and D read nothing newer', async () => {
    net = await createNetwork({ peers: ['A', 'B', 'C', 'D'] })
    const { A, B, C, D } = net.peers
    await shareVault(net)

    const first = await A.ensureEpoch({ start: true })
    expect(first).toMatchObject({
      rotated: true,
      members: ['device-A', 'device-B', 'device-C', 'device-D']
    })
    for (const peer of [B, C, D]) await holdsEpoch(peer, first.id)
    await A.add('note/before', { text: 'everyone' })
    expect(await converge(net.list, 'note/before')).toMatchObject({
      text: 'everyone'
    })

    // Each kick rotates; or finds the latest epoch already current, when a
    // rotation for both removals (the other kick's, or its own update-driven
    // one) landed first; or, when the other kick's epoch resolved above its
    // own twice, gives up with RotationOvertakenError. The next ensure then
    // judges the epoch that won.
    const kicks = await Promise.allSettled([
      A.kick('device-C'),
      B.kick('device-D')
    ])
    const outcomes = kicks.map((k) =>
      k.status === 'rejected'
        ? k.reason.name
        : k.value.rotated
          ? `rotated seq ${k.value.seq}`
          : k.value.reason
    )
    // "two concurrent rotations both exclude the removed device"
    for (const [kick, target] of [
      [kicks[0], 'device-C'],
      [kicks[1], 'device-D']
    ]) {
      if (kick.status === 'rejected') {
        expect(kick.reason.name).toBe('RotationOvertakenError')
      } else if (kick.value.rotated) {
        expect(kick.value.members).not.toContain(target)
      } else {
        expect(kick.value.reason).toBe('current')
      }
    }
    expect(kicks.some((k) => k.value?.rotated)).toBe(true)
    const settled = await settledEpoch([A, B], ['device-A', 'device-B'])
    expect(settled.epoch).not.toBe(first.id)

    await A.add('note/after-a', { text: 'from A, members only' })
    await B.add('note/after-b', { text: 'from B, members only' })
    for (const key of ['note/after-a', 'note/after-b']) {
      expect(await converge([A, B], key)).toMatchObject({
        text: expect.stringContaining('members only')
      })
    }
    // A kicker that had not yet seen the other kick seals its epoch to that
    // other device (ADR 0014's honest limit), so a kicked device may read an
    // epoch that lists it. It never reads one that leaves it out.
    const sealedToKicked = []
    for (const peer of [C, D]) {
      expect(
        await revokedStatus(peer, (s) => s.epoch === settled.epoch)
      ).toMatchObject({ canRead: false })
      await sealedFrom(peer, 'note/after-a', 'members only')
      await sealedFrom(peer, 'note/after-b', 'members only')
      expect(await peer.get('note/before')).toMatchObject({ text: 'everyone' })
      const readable = net.tracers[peer.id].events.filter(
        (e) =>
          e.event === 'epoch.status' &&
          e.epoch !== null &&
          e.epoch !== short(first.id) &&
          e.canRead
      )
      expect(
        readable.filter((e) => !e.members.includes(peer.deviceId))
      ).toEqual([])
      sealedToKicked.push(
        `${peer.id}:${new Set(readable.map((e) => e.epoch)).size}`
      )
    }
    expect((await A.devices()).map((d) => d.id).sort()).toEqual([
      'device-A',
      'device-B'
    ])

    // The first epoch plus at least one per kick; extra records are the
    // same-seq race resolving. Reported per run.
    const records = await A.list('epoch/')
    // eslint-disable-next-line no-console
    console.log(
      `epoch records: ${records.length} (kicks: ${outcomes.join(', ')}; ` +
        `later epochs a kicked device read: ${sealedToKicked.join(' ')})`
    )
    expect(records.length).toBeGreaterThanOrEqual(3)
  })
})
