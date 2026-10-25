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

const ABC = ['device-A', 'device-B', 'device-C']
const sameList = (a, b) => JSON.stringify(a) === JSON.stringify(b)

// ADR 0014: a removed device "can read a record written by a member whose
// copy of the roster had not yet shown the removal when it wrote" (the
// honest limit) and nothing written once that member has caught up.
describe('revoke while a member is partitioned (ADR 0014)', () => {
  let net = null

  afterEach(async () => {
    await net?.destroy()
    net = null
  })

  test('B is apart while A kicks D; B heals, joins the new epoch, and D reads nothing newer', async () => {
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

    await B.goOffline()
    const kicked = await A.kick('device-D')
    expect(kicked).toMatchObject({ rotated: true, members: ABC })
    // C may rotate for the same removal too; either way D is left out.
    await holdsMembers(C, ABC, { besides: first.id })
    await A.add('note/a-after', { text: 'after the kick' })
    expect(await converge([A, C], 'note/a-after')).toMatchObject({
      text: 'after the kick'
    })
    expect(
      await revokedStatus(
        D,
        (s) => s.epoch !== first.id && sameList(s.members, ABC)
      )
    ).toMatchObject({ canRead: false })
    await sealedFrom(D, 'note/a-after', 'after the kick')

    // Apart, B still has the first epoch and all four rows, so its write is
    // sealed under a key D holds.
    expect(await B.epochStatus()).toMatchObject({
      epoch: first.id,
      canRead: true,
      members: ['device-A', 'device-B', 'device-C', 'device-D']
    })
    expect((await B.devices()).map((d) => d.id).sort()).toEqual([
      'device-A',
      'device-B',
      'device-C',
      'device-D'
    ])
    await B.add('note/b-during', { text: 'written apart' })

    await B.goOnline()
    expect(await converge([A, B, C], 'note/b-during')).toMatchObject({
      text: 'written apart'
    })
    // The ADR's honest limit: D reads b-during.
    expect(
      await waitFor(() => D.get('note/b-during'), { label: 'D reads b-during' })
    ).toMatchObject({ text: 'written apart' })

    // A, B and C may each rotate once B's view shows the kick.
    const agreed = await settledEpoch([A, B, C], ABC)
    expect(agreed.epoch).not.toBe(first.id)

    // B's next write is sealed under the agreed epoch: D cannot read it.
    await B.add('note/b-after', { text: 'after the heal' })
    expect(await converge([A, B, C], 'note/b-after')).toMatchObject({
      text: 'after the heal'
    })
    await sealedFrom(D, 'note/b-after', 'after the heal')
    await sealedFrom(D, 'note/a-after', 'after the kick')
    await waitFor(async () => (await D.epochStatus()).epoch === agreed.epoch, {
      label: 'D sees the agreed epoch'
    })
    expect(await D.epochStatus()).toMatchObject({
      revoked: true,
      canRead: false
    })

    // Traces: B reported only the first epoch while apart; D never reported
    // any later epoch as readable (its legacy status before the first epoch
    // has no epoch).
    const { events } = net
    const offline = indexOf(events, 'B', 'peer.offline')
    const kick = indexOf(events, 'A', 'peer.kick')
    const online = indexOf(events, 'B', 'peer.online')
    expect(offline).toBeGreaterThan(-1)
    expect(kick).toBeGreaterThan(offline)
    expect(online).toBeGreaterThan(kick)
    const apart = events
      .slice(offline, online)
      .filter((e) => e.peer === 'B' && e.event === 'epoch.status')
    expect(apart.map((e) => e.epoch)).toEqual(apart.map(() => short(first.id)))
    const healed = indexOf(
      events,
      'B',
      'epoch.status',
      (e) => e.epoch === short(agreed.epoch) && e.canRead
    )
    expect(healed).toBeGreaterThan(online)
    const leaked = net.tracers.D.events.filter(
      (e) =>
        e.event === 'epoch.status' &&
        e.epoch !== null &&
        e.epoch !== short(first.id) &&
        e.canRead
    )
    expect(leaked).toEqual([])
  })
})
