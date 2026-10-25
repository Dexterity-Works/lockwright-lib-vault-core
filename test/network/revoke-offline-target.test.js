import {
  converge,
  createNetwork,
  holdsEpoch,
  holdsMembers,
  indexOf,
  noKeyAfter,
  revokedStatus,
  sameList,
  sealedFrom,
  shareVault,
  statusPushed
} from './harness.js'
import { short } from './tracer.js'

const AB = ['device-A', 'device-B']

// ADR 0014: "the removed device keeps what it already synced"; the epoch
// key it never held does not reach it, offline at the kick or not.
describe('revoke of a device that is offline when kicked (ADR 0014)', () => {
  let net = null

  afterEach(async () => {
    await net?.destroy()
    net = null
  })

  test('C is offline while A kicks it; back online C is revoked and never reads the new epoch', async () => {
    net = await createNetwork({ peers: ['A', 'B', 'C'] })
    const { A, B, C } = net.peers
    await shareVault(net)

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

    await C.goOffline()
    const kicked = await A.kick('device-C')
    expect(kicked).toMatchObject({ rotated: true, members: AB })
    expect(kicked.id).not.toBe(first.id)
    // B may rotate for the same removal too; either way C is left out.
    await holdsMembers(B, AB, { besides: first.id })
    await A.add('note/after', { text: 'members only' })
    expect(await converge([A, B], 'note/after')).toMatchObject({
      text: 'members only'
    })
    // Apart, C still believes in the first epoch and has no copy of the row.
    expect(await C.epochStatus()).toMatchObject({
      epoch: first.id,
      canRead: true,
      revoked: false
    })
    expect(await C.raw('note/after')).toBeNull()

    await C.goOnline()
    const status = await revokedStatus(
      C,
      (s) => s.epoch !== first.id && sameList(s.members, AB)
    )
    expect(status).toMatchObject({ canRead: false, members: AB })
    // Every epoch above the first, as C's own store holds them: no box for C.
    await noKeyAfter(C, { lastHeldSeq: first.seq })
    await sealedFrom(C, 'note/after', 'members only')
    expect(await C.get('note/before')).toMatchObject({ text: 'everyone' })
    expect((await A.devices()).map((d) => d.id).sort()).toEqual(AB)

    // Order across peers: offline, kick, online, then C learns it is out.
    const learned = await statusPushed(net, C, (e) => e.revoked)
    const { events } = net
    const offline = indexOf(events, 'C', 'peer.offline')
    const kick = indexOf(events, 'A', 'peer.kick')
    const online = indexOf(events, 'C', 'peer.online')
    expect(offline).toBeGreaterThan(-1)
    expect(kick).toBeGreaterThan(offline)
    expect(online).toBeGreaterThan(kick)
    expect(learned).toBeGreaterThan(online)
    // C never once reported an epoch after the first as readable.
    const leaked = net.tracers.C.events.filter(
      (e) =>
        e.event === 'epoch.status' &&
        e.epoch !== null &&
        e.epoch !== short(first.id) &&
        e.canRead
    )
    expect(leaked).toEqual([])
  })
})
