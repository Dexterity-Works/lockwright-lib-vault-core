import { createNetwork, shareVault, waitFor } from './harness.js'
import { short } from './tracer.js'

// hyperswarm/lib/retry-timer.js picks a BulkTimer per failed attempt: a
// proven peer (A dialled it once) gets S, M, L; one A only ever accepted
// from gets M, L, L. After the third failure `attempts` passes 3, no timer
// is picked and `_maybeDeletePeer` drops the PeerInfo (hyperswarm/index.js
// `_connect` close handler). Each timer is BACKOFF_x plus up to 500 ms of
// jitter, and a BulkTimer ticks every 0.66 × that and fires an entry on
// its second tick, so a wait lands in (0.66 × min, 1.32 × max].
const TIMERS = {
  S: { min: 1000, max: 1500 + 500 },
  M: { min: 5000, max: 6000 + 500 },
  L: { min: 15000, max: 17000 + 500 }
}
const SCHEDULE = { proven: ['S', 'M', 'L'], unproven: ['M', 'L', 'L'] }
const bounds = (tier) => [
  Math.floor(TIMERS[tier].min * 0.66),
  Math.ceil(TIMERS[tier].max * 1.32)
]
// A timer fires on a setInterval tick, and the tick runs late when the event
// loop is busy (three DHTs, replication, jest). At the long tier's maximum
// jitter that lag has reached past 500 ms.
const TICK_SLACK = 1000
// Not covered: the relay path's fast redial. When a dial fails with a
// HOLEPUNCH_* code and the swarm has relayThrough, `onerror` in `_connect`
// sets forceRelaying and resets `attempts` to 0 (hyperswarm/index.js
// ~224-229), so the schedule starts over and the relayed redial comes
// fast. Without a relay that branch never runs.

const hex = (key) => Buffer.from(key).toString('hex')

const connEvents = (tracer, event, remote, since = 0) =>
  tracer.events.filter(
    (e) =>
      e.event === event &&
      e.label === 'vault' &&
      e.remote === remote &&
      e.t >= since
  )

describe('a peer that went away is redialled with backoff', () => {
  let net = null

  afterEach(async () => {
    await net?.destroy()
    net = null
  })

  test('A backs off from a closed B, drops it, and reconnects when B is back', async () => {
    net = await createNetwork({ peers: ['A', 'B'] })
    const { A, B } = net.peers
    // B owns the vault so A, the joiner, is the side that dialled. Only the
    // dialler redials: a swarm that accepted a connection has no discovery
    // topic on that PeerInfo (`_shouldRequeue` is false) and its server
    // close handler never arms the retry timer; it waits for the other side
    // to come back (hyperswarm/index.js, the close handlers in _connect and
    // _handleServerConnection).
    await shareVault(net, { owner: 'B' })

    const swarmA = A.instance.swarm
    const keyB = B.instance.swarm.keyPair.publicKey
    const remoteB = short(keyB)
    await waitFor(() => swarmA.connections.size === 1, {
      label: 'A holds one connection, to B'
    })
    const infoB = swarmA.peers.get(hex(keyB))
    expect(infoB).toBeDefined()
    expect(infoB.proven).toBe(true)
    const schedule = SCHEDULE[infoB.proven ? 'proven' : 'unproven']

    // Every dial A makes to B, with the PeerInfo's attempt counter and how
    // the dial ended. Only dials that open become `conn.open`, so record
    // them here: `_connect` is where the retry timer lands.
    const dials = []
    const connect = swarmA._connect.bind(swarmA)
    swarmA._connect = (peerInfo, queued) => {
      if (hex(peerInfo.publicKey) === hex(keyB)) {
        dials.push({ at: Date.now(), attempts: peerInfo.attempts })
        A.trace('conn.attempt', {
          label: 'vault',
          remote: remoteB,
          attempts: peerInfo.attempts,
          queued
        })
      }
      return connect(peerInfo, queued)
    }
    const dhtConnect = swarmA.dht.connect.bind(swarmA.dht)
    swarmA.dht.connect = (publicKey, opts) => {
      const conn = dhtConnect(publicKey, opts)
      if (hex(publicKey) === hex(keyB)) {
        const dial = dials.at(-1)
        conn.on('error', (error) => {
          dial.code = error.code ?? error.message
        })
        conn.on('close', () => {
          dial.closedAt = Date.now()
          A.trace('conn.failed', {
            label: 'vault',
            remote: remoteB,
            code: dial.code ?? null,
            ms: dial.closedAt - dial.at
          })
        })
      }
      return conn
    }
    let mostConnections = 0
    swarmA.on('update', () => {
      mostConnections = Math.max(mostConnections, swarmA.connections.size)
    })
    // The first retry timer starts when A's side of the connection closes.
    let closedAt = 0
    for (const conn of swarmA.connections) {
      conn.on('close', () => {
        closedAt = Date.now()
      })
    }

    const closedT = A.tracer.events.at(-1)?.t ?? 0
    await B.closeVault()
    await waitFor(() => connEvents(A.tracer, 'conn.close', remoteB).length, {
      label: 'A saw its connection to B close'
    })
    expect(closedAt).toBeGreaterThan(0)
    mostConnections = 0

    await waitFor(() => dials.length >= 3 && !swarmA.peers.has(hex(keyB)), {
      timeout: 90000,
      interval: 250,
      label: 'A dialled B three times and then forgot it'
    })
    // Timer wait = dial start minus when the previous dial failed.
    const waits = dials
      .slice(0, 3)
      .map((d, i) => d.at - (i ? dials[i - 1].closedAt : closedAt))
    A.trace('hygiene.backoff', {
      remote: remoteB,
      schedule,
      waits,
      dialMs: dials.map((d) => (d.closedAt ?? Date.now()) - d.at),
      attempts: dials.map((d) => d.attempts),
      final: infoB.attempts
    })

    // The counter rose by one per failed dial and ended past the retry
    // schedule, which is what evicted the PeerInfo.
    expect(dials.slice(0, 3).map((d) => d.attempts)).toEqual([1, 2, 3])
    expect(dials.slice(0, 3).every((d) => d.closedAt)).toBe(true)
    expect(infoB.attempts).toBeGreaterThan(3)
    // Each wait sits inside its timer's window; a longer tier waits longer.
    for (const [i, wait] of waits.entries()) {
      const [min, max] = bounds(schedule[i])
      expect(wait).toBeGreaterThanOrEqual(min)
      expect(wait).toBeLessThanOrEqual(max + TICK_SLACK)
      if (i && schedule[i] !== schedule[i - 1]) {
        expect(wait).toBeGreaterThan(waits[i - 1])
      }
    }
    // No dial opened and nothing half-open piled up in the connection set.
    expect(connEvents(A.tracer, 'conn.open', remoteB, closedT)).toEqual([])
    expect(mostConnections).toBe(0)
    expect(swarmA.connections.size).toBe(0)
    expect(swarmA._allConnections.size).toBe(0)
    expect(swarmA.peers.size).toBe(0)

    // B is back: it announces and finds A, so A gets a connection again
    // and a fresh PeerInfo with no failed attempts on it.
    const reopenedT = A.tracer.events.at(-1).t
    await B.openVault()
    await waitFor(
      () => connEvents(A.tracer, 'conn.open', remoteB, reopenedT).length,
      { label: 'A is connected to B again' }
    )
    const infoB2 = swarmA.peers.get(hex(keyB))
    expect(infoB2).toBeDefined()
    expect(infoB2).not.toBe(infoB)
    expect(infoB2.attempts).toBe(0)
    expect(swarmA.connections.size).toBe(1)
    await A.add('note/after', { ok: true })
    await waitFor(async () => (await B.get('note/after')) !== null, {
      label: 'B reads what A wrote after the reconnect'
    })
  }, 180000)
})
