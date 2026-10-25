import { createNetwork, waitFor } from './harness.js'
import { short } from './tracer.js'

// Every peer relays through a local blind relay unconditionally (a
// function-valued relayThrough, hyperswarm/index.js:683-687). hyperdht runs
// the relay in parallel with the direct path (connect.js:534-536) and on
// the loopback the direct path wins at once (FIREWALL.OPEN or the LAN
// shortcut, connect.js:227-275), so Layer 1 can show that the relay is
// dialled and that pairing works with it in force, not that direct is
// impossible. "Never direct" is the lab's: run-lab.sh pairing-relay-only
// --block-udp --relay (superproject test/network/scenarios).

const of = (net, peer, event, where = {}) =>
  net.tracers[peer].events.filter(
    (e) =>
      e.event === event && Object.entries(where).every(([k, v]) => e[k] === v)
  )

describe('pairing with a blind relay in force', () => {
  let net = null

  afterEach(async () => {
    await net?.destroy()
    net = null
  })

  test('A invites, B pairs; the relay is dialled and every path is accounted for', async () => {
    net = await createNetwork({ peers: ['A', 'B'], relay: true })
    const { A, B } = net.peers
    const relayAddress = [...net.relay.addresses][0]

    await A.createVault({ id: 'shared' })
    const aVault = short(A.instance.swarm.keyPair.publicKey)
    await B.pair(await A.invite())
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

    // Every A<->B stream, both sides, pairer and vault swarms.
    const streams = net.list.flatMap((peer) =>
      peer.tracer.events.filter(
        (e) =>
          (e.event === 'conn.open' || e.event === 'conn.upgrade') &&
          e.remote === (peer.id === 'B' ? aVault : bSwarm)
      )
    )
    expect(
      of(net, 'B', 'conn.open', { label: 'pairer', remote: aVault })
    ).toHaveLength(1)
    expect(
      of(net, 'B', 'conn.open', { label: 'vault', remote: aVault })
    ).toHaveLength(1)
    // One from B's pairer, one from B's vault.
    expect(
      of(net, 'A', 'conn.open', { label: 'vault', remote: bSwarm })
    ).toHaveLength(2)
    // eslint-disable-next-line no-console
    console.log(
      `paths with the relay in force:\n  ${streams
        .map(
          (e) => `${e.peer} ${e.label} ${e.event} ${e.path} ${e.remoteAddress}`
        )
        .join('\n  ')}`
    )
    for (const e of streams) {
      expect(['direct', 'relayed']).toContain(e.path)
      expect(e.remoteAddress === relayAddress).toBe(e.path === 'relayed')
    }

    // The relay was in force: hyperdht dialled it for the pairing handshake
    // and the relay accepted the session.
    const relaying = net.list.map((peer) =>
      Math.max(
        0,
        ...peer.tracer.events
          .filter((e) => e.event === 'conn.open' && e.stats)
          .map((e) => e.stats.relaying.attempts)
      )
    )
    expect(Math.max(...relaying)).toBeGreaterThan(0)
    expect(net.relay.server.stats.sessions.accepted).toBeGreaterThan(0)
  })
})
