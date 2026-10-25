import {
  createNetwork,
  indexOf,
  pairOrCancel,
  sleep,
  waitFor
} from './harness.js'
import { short } from './tracer.js'

// The invite lives in the active vault, so suspending its swarm takes the
// inviter off the pairing topic. A joiner that starts while the inviter is
// away cannot be answered; it completes once the inviter is back.

const of = (net, peer, event, where = {}) =>
  net.tracers[peer].events.filter(
    (e) =>
      e.event === event && Object.entries(where).every(([k, v]) => e[k] === v)
  )

const offlineFor = 3000

describe('inviter offline while the joiner starts', () => {
  let net = null

  afterEach(async () => {
    await net?.destroy()
    net = null
  })

  test('B waits while A is suspended and pairs once A resumes', async () => {
    net = await createNetwork({ peers: ['A', 'B'] })
    const { A, B } = net.peers
    await A.createVault({ id: 'shared' })
    const code = await A.invite()
    const aVault = short(A.instance.swarm.keyPair.publicKey)

    await A.goOffline()
    expect(A.instance.swarm.suspended).toBe(true)
    expect(of(net, 'A', 'swarm.suspend', { label: 'vault' })).toHaveLength(1)

    const pairing = pairOrCancel(B, code, { timeout: 30000 })
    await waitFor(
      () => of(net, 'B', 'topic.join', { label: 'pairer' }).length,
      {
        label: 'B pairer joined the pairing topic'
      }
    )
    await sleep(offlineFor)
    // Still waiting: no answer, no live connection to A.
    expect(of(net, 'B', 'peer.paired')).toHaveLength(0)
    expect(of(net, 'B', 'error', { where: 'peer.pair' })).toHaveLength(0)
    const early = of(net, 'B', 'conn.open', { label: 'pairer', remote: aVault })
    const closed = of(net, 'B', 'conn.close', {
      label: 'pairer',
      remote: aVault
    })
    expect(early.length - closed.length).toBe(0)
    expect(B.vaultId).toBeNull()

    await A.goOnline()
    expect(A.instance.swarm.suspended).toBe(false)
    const result = await pairing
    expect(result).toMatchObject({ paired: true, vaultId: 'shared' })

    // net.events is every peer's events in the order they were recorded.
    const start = indexOf(net.events, 'B', 'pairing.start')
    const resume = indexOf(
      net.events,
      'A',
      'swarm.resume',
      (e) => e.label === 'vault'
    )
    const paired = indexOf(net.events, 'B', 'peer.paired')
    const connected = indexOf(
      net.events,
      'B',
      'conn.open',
      (e) => e.label === 'pairer' && e.remote === aVault
    )
    expect(start).toBeGreaterThanOrEqual(0)
    expect(start).toBeLessThan(resume)
    expect(resume).toBeLessThan(connected)
    expect(connected).toBeLessThan(paired)
    expect(of(net, 'B', 'peer.paired')).toHaveLength(1)
    expect(of(net, 'B', 'peer.pairTimeout')).toHaveLength(0)

    for (const peer of [A, B]) {
      await waitFor(async () => (await peer.devices()).length === 2, {
        label: `${peer.id} sees both device rows`
      })
    }
    expect((await A.devices()).map((d) => d.id).sort()).toEqual([
      'device-A',
      'device-B'
    ])
  })
})
