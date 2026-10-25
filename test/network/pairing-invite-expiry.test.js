import { createNetwork, pairOrCancel, waitFor } from './harness.js'
import { short } from './tracer.js'

// An invite never expires at the protocol level (blind-pairing createInvite
// uses expires = 0); in Lockwright it is gone once the inviter deletes it,
// which autopass does itself after the first join. A joiner whose invite is
// gone is never answered: autopass member onadd returns early and the
// candidate polls forever, so lib-vault cancels it after 30 s.

const of = (net, peer, event, where = {}) =>
  net.tracers[peer].events.filter(
    (e) =>
      e.event === event && Object.entries(where).every(([k, v]) => e[k] === v)
  )

const members = (peer) => peer.instance.base.system.members

const pairingTimeout = 8000

describe('invite deleted while a joiner is mid-pairing', () => {
  let net = null

  afterEach(async () => {
    await net?.destroy()
    net = null
  })

  test('deleted before B starts: B never joins, then a fresh invite pairs', async () => {
    net = await createNetwork({ peers: ['A', 'B'] })
    const { A, B } = net.peers
    await A.createVault({ id: 'shared' })
    const stale = await A.invite()
    await A.appDeps.deleteInvite()
    const aVault = short(A.instance.swarm.keyPair.publicKey)

    const result = await pairOrCancel(B, stale, { timeout: pairingTimeout })
    expect(result.paired).toBe(false)
    expect(result.error.message).toMatch(/Pairing closed/)

    // B's pairer did reach A over the pairing topic and was left unanswered.
    expect(of(net, 'B', 'pairing.start')).toHaveLength(1)
    expect(of(net, 'B', 'topic.join', { label: 'pairer' })).not.toHaveLength(0)
    expect(
      of(net, 'B', 'conn.open', { label: 'pairer', remote: aVault })
    ).toHaveLength(1)
    expect(of(net, 'B', 'peer.paired')).toHaveLength(0)
    expect(of(net, 'B', 'autobase.writable')).toHaveLength(0)
    expect(of(net, 'B', 'autobase.open', { label: 'vault' })).toHaveLength(0)
    expect(of(net, 'B', 'error', { where: 'peer.pair' })).toHaveLength(1)
    expect(of(net, 'A', 'peer.invite')).toHaveLength(1)
    expect((await A.devices()).map((d) => d.id)).toEqual(['device-A'])
    expect(members(A)).toBe(1)
    // The cancel closed B's pairer swarm: A saw the connection go.
    await waitFor(
      () => of(net, 'A', 'conn.close', { label: 'vault' }).length === 1,
      { label: 'A saw the cancelled pairer leave' }
    )
    expect(of(net, 'B', 'swarm.destroy', { label: 'pairer' })).toHaveLength(1)

    // Recovery: a fresh invite pairs.
    await B.pair(await A.invite())
    expect(B.vaultId).toBe('shared')
    for (const peer of [A, B]) {
      await waitFor(async () => (await peer.devices()).length === 2, {
        label: `${peer.id} sees both device rows`
      })
    }
    expect(of(net, 'B', 'peer.paired')).toHaveLength(1)
    expect(of(net, 'A', 'peer.invite')).toHaveLength(2)
    await waitFor(() => members(A) === 2, { label: 'A counts two writers' })
  })

  test('deleted on B first connection: at most one join, roster matches', async () => {
    let deleted = null
    net = await createNetwork({
      peers: ['A', 'B'],
      onEvent: (e) => {
        if (e.peer === 'B' && e.event === 'conn.open' && e.label === 'pairer') {
          deleted ??= net.peers.A.appDeps.deleteInvite()
        }
      }
    })
    const { A, B } = net.peers
    await A.createVault({ id: 'shared' })
    const code = await A.invite()

    const result = await pairOrCancel(B, code, { timeout: pairingTimeout })
    expect(deleted).not.toBeNull()
    await deleted
    const outcome = result.paired ? 'joined' : 'left out'
    // eslint-disable-next-line no-console
    console.log(`invite deleted on first connection: B ${outcome}`)

    expect(of(net, 'A', 'peer.invite')).toHaveLength(1)
    expect(of(net, 'B', 'conn.open', { label: 'pairer' })).not.toHaveLength(0)
    if (result.paired) {
      expect(of(net, 'B', 'peer.paired')).toHaveLength(1)
      for (const peer of [A, B]) {
        await waitFor(async () => (await peer.devices()).length === 2, {
          label: `${peer.id} sees both device rows`
        })
      }
      await waitFor(() => members(A) === 2, { label: 'A counts two writers' })
    } else {
      expect(result.error.message).toMatch(/Pairing closed/)
      expect(of(net, 'B', 'peer.paired')).toHaveLength(0)
      expect(of(net, 'B', 'autobase.writable')).toHaveLength(0)
      expect((await A.devices()).map((d) => d.id)).toEqual(['device-A'])
      expect(members(A)).toBe(1)
      // Recovery.
      await B.pair(await A.invite())
      for (const peer of [A, B]) {
        await waitFor(async () => (await peer.devices()).length === 2, {
          label: `${peer.id} sees both device rows`
        })
      }
      expect(of(net, 'B', 'peer.paired')).toHaveLength(1)
      await waitFor(() => members(A) === 2, { label: 'A counts two writers' })
    }
    expect((await A.devices()).map((d) => d.id).sort()).toEqual([
      'device-A',
      'device-B'
    ])
  })
})
