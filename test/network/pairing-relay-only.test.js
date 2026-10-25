import { createNetwork, of, waitFor } from './harness.js'
import { short } from './tracer.js'

// Every peer relays through a local blind relay unconditionally (a
// function-valued relayThrough, hyperswarm/index.js:683-687). The harness
// override replaces relayThrough outright (utils/swarm.js:53-55), so
// Lockwright's own relay plumbing (conf.current.blindRelays,
// appDeps.js:810, :868) is not under test here. hyperdht runs the relay in
// parallel with the direct path (connect.js:534-536) and on the loopback
// the direct path wins at once (FIREWALL.OPEN or the LAN shortcut,
// connect.js:227-275), so the relay never carries the stream: Layer 1 can
// show that the relay is dialled and that pairing works with it in force,
// not that pairing works over the relay alone. "Relay only" is the lab's:
// run-lab.sh pairing-relay-only --block-udp --relay (superproject
// test/network/scenarios).

describe('pairing with a blind relay in force', () => {
  let net = null

  afterEach(async () => {
    await net?.destroy()
    net = null
  })

  test('a blind relay in force: A invites, B pairs, and the relay is dialled', async () => {
    net = await createNetwork({ peers: ['A', 'B'], relay: true })
    const { A, B } = net.peers
    const relayed = net.relay.server.stats

    await A.createVault({ id: 'shared' })
    const aVault = short(A.instance.swarm.keyPair.publicKey)
    const code = await A.invite()
    const before = {
      accepted: relayed.sessions.accepted,
      requested: relayed.pairings.requested
    }
    await B.pair(code)
    // B's pairer and vault swarms share the Corestore's 'hyperswarm' key pair.
    const bSwarm = short(B.instance.swarm.keyPair.publicKey)
    expect(of(net, 'B', 'swarm.create', { label: 'pairer' })[0].key).toBe(
      bSwarm
    )

    for (const peer of [A, B]) {
      await waitFor(async () => (await peer.devices()).length === 2, {
        label: `${peer.id} sees both device rows`
      })
    }
    expect((await A.devices()).map((d) => d.id).sort()).toEqual([
      'device-A',
      'device-B'
    ])

    expect(
      of(net, 'B', 'conn.open', { label: 'pairer', remote: aVault }).length
    ).toBeGreaterThanOrEqual(1)
    expect(
      of(net, 'B', 'conn.open', { label: 'vault', remote: aVault }).length
    ).toBeGreaterThanOrEqual(1)
    // At least one from B's pairer and one from B's vault.
    expect(
      of(net, 'A', 'conn.open', { label: 'vault', remote: bSwarm }).length
    ).toBeGreaterThanOrEqual(2)

    // eslint-disable-next-line no-console
    console.log(
      `relay in force: ${JSON.stringify(relayed)}; paths ${net.list
        .flatMap((peer) =>
          of(net, peer.id, 'conn.open').map(
            (e) => `${peer.id}:${e.label}:${e.path}`
          )
        )
        .join(' ')}`
    )
    // The pairing dialled the relay: hyperdht opened a relay session and
    // asked it to link the two ends (blind-relay index.js:32, :172), and a
    // DHT server counted the relay attempt (hyperdht lib/server.js:647). It
    // need not carry the stream: the direct path wins on the loopback.
    expect(relayed.sessions.accepted).toBeGreaterThan(before.accepted)
    expect(relayed.pairings.requested).toBeGreaterThan(before.requested)
    const attempts = net.list.flatMap((peer) =>
      of(net, peer.id, 'conn.open')
        .filter((e) => e.stats)
        .map((e) => e.stats.relaying.attempts)
    )
    expect(Math.max(0, ...attempts)).toBeGreaterThan(0)
  })
})
