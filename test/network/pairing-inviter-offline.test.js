import {
  createNetwork,
  indexOf,
  of,
  pairOrCancel,
  sleep,
  waitFor
} from './harness.js'
import { short } from './tracer.js'

// The invite lives in the active vault, so suspending it takes the inviter
// off the pairing topic. A joiner that starts while the inviter is away
// cannot be answered; it completes once the inviter is back.

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

    // The production offline path (the app going to the background):
    // appDeps suspends every Autopass (appDeps.js:209-223), and autopass
    // suspends blind-pairing, the swarm and the store (autopass
    // index.js:392-398).
    A.trace('peer.offline')
    await A.appDeps.suspendAllInstances()
    expect(A.instance.swarm.suspended).toBe(true)
    expect(A.instance.pairing.suspended).toBe(true)
    expect(of(net, 'A', 'swarm.suspend', { label: 'vault' })).toHaveLength(1)

    const pairing = pairOrCancel(B, code, { timeout: 30000 })
    // B's candidate has polled: it looked for a reply, found none, and
    // announced its request, after which it joins the pairing topic as a
    // server too (blind-pairing index.js:590-602). The late topic.join the
    // tracer lists when the pairer swarm is created proves nothing.
    await waitFor(
      () =>
        of(net, 'B', 'topic.join', { label: 'pairer', server: true }).some(
          (e) => !e.late
        ),
      { label: 'B announced its pairing request' }
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

    A.trace('peer.online')
    await A.appDeps.resumeAllInstances()
    expect(A.instance.swarm.suspended).toBe(false)
    const result = await pairing
    expect(result).toMatchObject({ paired: true, vaultId: 'shared' })

    // net.events is every peer's events in the order they were recorded.
    // A took no connection from B's pairer while suspended, and B was
    // answered only after A came back.
    const online = indexOf(net.events, 'A', 'peer.online')
    const bPairer = of(net, 'B', 'swarm.create', { label: 'pairer' })[0].key
    const fromPairer = net.events
      .map((e, i) => ({ e, i }))
      .filter(
        ({ e }) =>
          e.peer === 'A' && e.event === 'conn.open' && e.remote === bPairer
      )
    expect(fromPairer).not.toHaveLength(0)
    for (const { i } of fromPairer) expect(i).toBeGreaterThan(online)
    expect(indexOf(net.events, 'B', 'peer.paired')).toBeGreaterThan(online)
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
