import path from 'path'
import v8 from 'v8'
import vm from 'vm'

import guard from './guard.cjs'
import { createNetwork, shareVault, sleep, waitFor } from './harness.js'

// Three peers on one vault for LOCKWRIGHT_NET_SOAK_MS (default 60 s): a
// write every 1-2 s, a fault every ~10 s (suspend/resume, close/reopen, or
// a vault restart), a `hygiene.sample` per peer every 5 s. The fault list
// (kind, victim, gap, outage) is drawn from LOCKWRIGHT_NET_SOAK_SEED before
// the run, so a seed replays the same faults; writes draw from a second
// stream, so how many land between faults cannot shift them. The samples
// bound what a swarm may hold while peers come and go, every heal must
// bring each peer's UDX sockets back to the baseline, and the app's lock on
// every peer at the end must leave only the testnet's sockets.
//
// LOCKWRIGHT_NET_SOAK_HEAP=<dir> (off by default) drops the trace buffers
// at each heal and writes a heap snapshot into <dir> at the first and the
// last steady sample.
const SOAK_MS = Number(process.env.LOCKWRIGHT_NET_SOAK_MS || 60000)
const SEED = Number(process.env.LOCKWRIGHT_NET_SOAK_SEED || Date.now() % 1e6)
const HEAP_DIR = process.env.LOCKWRIGHT_NET_SOAK_HEAP || null
const PEERS = ['A', 'B', 'C']
const N = PEERS.length
const SAMPLE_MS = 5000
const TICK_MS = 200
// PeerInfos a swarm may keep beyond its live peers: one per peer that is
// mid-backoff after a close, plus a restarted swarm's fresh entry.
const PEER_SLACK = 2
const HEAL_TIMEOUT = 60000
// Sessions on the vault topic's PeerDiscovery: Autopass's own join and its
// BlindPairing member's (autopass/index.js _replicate). A second join of
// the topic adds a session, not a topic (hyperswarm/index.js join).
const SESSIONS = 2
// Timers swing with sync work; the last third of the steady samples may
// peak this far above the first third's peak.
const TIMER_SLACK = 10

// A heap figure after a full collection, so steady samples show what is
// retained rather than what the collector has not reached yet.
v8.setFlagsFromString('--expose-gc')
const gc = vm.runInNewContext('gc')

// mulberry32, as in soak.test.js
const rng = (s) => () => {
  s = (s + 0x6d2b79f5) | 0
  let t = Math.imul(s ^ (s >>> 15), 1 | s)
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296
}

// Every fault the run could reach, in order. Gaps alone sum past SOAK_MS,
// so the list outlasts the run; heals only add time.
const planFaults = (seed) => {
  const random = rng(seed)
  const between = (min, max) => min + Math.floor(random() * (max - min))
  const faults = []
  for (let index = 0, at = 0; at < SOAK_MS; index++) {
    const gap = between(8000, 12000)
    at += gap
    const victim = PEERS[Math.floor(random() * N)]
    const roll = random()
    const kind = roll < 0.45 ? 'suspend' : roll < 0.8 ? 'close' : 'restart'
    faults.push({ index, kind, victim, gap, outage: between(2000, 4000) })
  }
  return faults
}

// Active handles by type, keys sorted so two counts compare as JSON.
const handleCounts = () => {
  const types = process.getActiveResourcesInfo().sort()
  const byType = {}
  for (const type of types) byType[type] = (byType[type] ?? 0) + 1
  const { Timeout = 0, Immediate = 0, ...untimed } = byType
  return { total: types.length, timers: Timeout + Immediate, untimed }
}

const fail = (message, detail) => {
  throw new Error(`${message}: ${JSON.stringify(detail)}`)
}

describe('connection hygiene under churn', () => {
  let net = null

  afterEach(async () => {
    await net?.destroy()
    net = null
  })

  test(
    `bounded swarms for ${SOAK_MS} ms of churn (seed ${SEED})`,
    async () => {
      const plan = planFaults(SEED)
      const writeRandom = rng(SEED ^ 0x9e3779b9)
      const between = (min, max) =>
        min + Math.floor(writeRandom() * (max - min))
      const pick = (list) => list[Math.floor(writeRandom() * list.length)]
      // eslint-disable-next-line no-console
      console.log(`hygiene soak seed ${SEED}, ${SOAK_MS} ms`)

      // Which peer owns each UDX instance, so a live socket can be counted
      // against its peer and a leftover named with its address. Weak, so a
      // destroyed swarm's UDX is not kept alive by the test.
      const udxOwner = new WeakMap()
      net = await createNetwork({
        peers: PEERS,
        name: 'hygiene-soak',
        onCreate: (label, instance, peer) => {
          instance
            .ready?.()
            .then(() => {
              if (instance.swarm) udxOwner.set(instance.swarm.dht.udx, peer.id)
            })
            .catch(() => {})
        }
      })
      for (const node of net.testnet.nodes) udxOwner.set(node.udx, 'testnet')
      // redact() hides any field named like `seed`; `replay` survives.
      net.list[0].trace('hygiene.seed', { replay: SEED, ms: SOAK_MS })
      await shareVault(net)

      const state = Object.fromEntries(PEERS.map((id) => [id, 'open']))
      const swarmOf = (peer) =>
        state[peer.id] === 'closed' ? null : (peer.instance?.swarm ?? null)
      const socketsOf = (id) =>
        guard.liveSockets().filter((s) => udxOwner.get(s.udx) === id)
      const describeSocket = (socket) => {
        const address = socket.address()
        return {
          owner: udxOwner.get(socket.udx) ?? 'unknown',
          address: address ? `${address.host}:${address.port}` : 'unbound',
          streams: socket.streams.size
        }
      }
      const connectionCounts = () =>
        Object.fromEntries(
          net.list.map((p) => [
            p.id,
            {
              state: state[p.id],
              connections: swarmOf(p)?.connections.size ?? null
            }
          ])
        )
      const connected = () =>
        net.list.every(
          (p) =>
            state[p.id] === 'open' && swarmOf(p)?.connections.size === N - 1
        )
      const reconnected = (label) =>
        waitFor(connected, {
          timeout: HEAL_TIMEOUT,
          interval: TICK_MS,
          label
        }).catch((error) => fail(error.message, connectionCounts()))

      await reconnected('every peer holds a connection to each other peer')
      const baseline = Object.fromEntries(
        PEERS.map((id) => [id, socketsOf(id).length])
      )
      net.list[0].trace('hygiene.baseline', { sockets: baseline })

      const series = []
      // Process-wide, one entry per steady sample. Non-timer handles must
      // match the first steady sample's; the post-sync peak before it is
      // not a baseline.
      const steadyHandles = []
      let samples = 0
      const sample = (phase) => {
        samples++
        const handles = handleCounts()
        if (phase === 'steady') gc()
        const heap = process.memoryUsage().heapUsed
        const other = guard
          .liveSockets()
          .filter((s) => !udxOwner.has(s.udx))
          .map(describeSocket)
        if (other.length) fail('live UDX sockets no peer owns', other)
        for (const peer of net.list) {
          const swarm = swarmOf(peer)
          const discoveries = swarm ? [...swarm.topics()] : []
          const row = {
            n: samples,
            phase,
            state: state[peer.id],
            connections: swarm?.connections.size ?? 0,
            pending: swarm
              ? swarm._allConnections.size - swarm.connections.size
              : 0,
            peers: swarm?.peers.size ?? 0,
            topics: discoveries.length,
            sessions: discoveries.map((d) => d._sessions.length),
            sockets: socketsOf(peer.id).length,
            handles: handles.total,
            timers: handles.timers,
            heap
          }
          peer.trace('hygiene.sample', row)
          series.push({ peer: peer.id, at: Date.now(), ...row })
          const where = { peer: peer.id, ...row }
          if (row.connections > 2 * (N - 1)) {
            fail(`more than ${2 * (N - 1)} connections`, where)
          }
          if (row.pending > 2 * (N - 1)) {
            fail(`more than ${2 * (N - 1)} unopened connections`, where)
          }
          if (swarm && row.topics !== 1)
            fail('not one topic on the swarm', where)
          if (swarm && row.sessions.some((n) => n !== SESSIONS)) {
            fail(`not ${SESSIONS} sessions on the vault topic`, where)
          }
          if (row.peers > N - 1 + PEER_SLACK) {
            fail(`peers map past ${N - 1 + PEER_SLACK}`, where)
          }
          if (phase === 'steady' && row.connections !== N - 1) {
            fail(`not ${N - 1} connections at steady state`, where)
          }
        }
        if (phase !== 'steady') return
        steadyHandles.push({ n: samples, heap, ...handles })
        const first = steadyHandles[0]
        if (first.n === samples) {
          net.list[0].trace('hygiene.handles', { untimed: first.untimed })
        } else if (
          JSON.stringify(handles.untimed) !== JSON.stringify(first.untimed)
        ) {
          fail('non-timer handles moved off the first steady sample', {
            first: first.untimed,
            now: handles.untimed,
            n: samples
          })
        }
      }

      const snapshot = (name) => {
        const file = path.join(HEAP_DIR, `soak-${SEED}-${name}.heapsnapshot`)
        v8.writeHeapSnapshot(file)
        // eslint-disable-next-line no-console
        console.log(`heap snapshot: ${file}`)
      }

      // Steady state after a heal: every peer back to one connection per
      // other peer, then its sockets back to the baseline.
      const steady = async (label) => {
        await reconnected(`${label}: every peer reconnected`)
        await waitFor(
          () => PEERS.every((id) => socketsOf(id).length === baseline[id]),
          {
            timeout: 15000,
            interval: TICK_MS,
            label: `${label}: sockets back to ${JSON.stringify(baseline)}`
          }
        ).catch((error) => {
          fail(error.message, guard.liveSockets().map(describeSocket))
        })
        // Peer keeps every instance it built so stop() can close a failed
        // init; drop the closed ones or the soak measures its own retention.
        for (const peer of net.list) peer.pruneClosed()
        if (HEAP_DIR) {
          for (const tracer of Object.values(net.tracers)) {
            tracer.events.length = 0
          }
          net.events.length = 0
        }
        sample('steady')
        if (HEAP_DIR && (steadyHandles.length === 1 || label === 'end')) {
          snapshot(label === 'end' ? 'last' : 'first')
        }
      }

      const expected = new Map()
      let seq = 0
      const write = async () => {
        const writer = pick(net.list.filter((p) => state[p.id] !== 'closed'))
        seq++
        const value = { seq, by: writer.id }
        await writer.add(`note/${seq}`, value)
        expected.set(seq, value)
      }

      // One fault at a time: `fault` holds the victim and how to heal it.
      let fault = null
      let nextIndex = 0
      const counts = { suspend: 0, close: 0, restart: 0, writes: 0, steady: 0 }
      const startFault = async ({ index, kind, victim: id, outage }) => {
        const victim = net.peers[id]
        counts[kind]++
        victim.trace('hygiene.fault', { index, kind, victim: id })
        if (kind === 'restart') {
          await victim.restartVault()
          return { victim, kind, healAt: Date.now() }
        }
        if (kind === 'suspend') {
          state[victim.id] = 'suspended'
          await victim.goOffline()
        } else {
          state[victim.id] = 'closed'
          await victim.closeVault()
        }
        return { victim, kind, healAt: Date.now() + outage }
      }
      const heal = async () => {
        const { victim, kind } = fault
        if (kind === 'suspend') await victim.goOnline()
        if (kind === 'close') await victim.openVault()
        state[victim.id] = 'open'
        victim.trace('hygiene.heal', { kind })
        fault = null
        await steady(`after ${kind} of ${victim.id}`)
        counts.steady++
      }

      sample('baseline')
      const t0 = Date.now()
      const deadline = t0 + SOAK_MS
      let nextWrite = t0 + between(1000, 2000)
      let nextSample = t0 + SAMPLE_MS
      let nextFault = t0 + plan[0].gap
      while (Date.now() < deadline) {
        const now = Date.now()
        if (now >= nextWrite) {
          await write()
          counts.writes++
          nextWrite = Date.now() + between(1000, 2000)
        }
        if (now >= nextSample) {
          sample(fault ? fault.kind : 'run')
          nextSample += SAMPLE_MS
        }
        if (fault && now >= fault.healAt) {
          const started = Date.now()
          await heal()
          nextFault = Math.max(nextFault, started + 2000)
        } else if (!fault && now >= nextFault && nextIndex < plan.length) {
          const next = plan[nextIndex++]
          nextFault = Date.now() + (plan[nextIndex]?.gap ?? Infinity)
          fault = await startFault(next)
        }
        await sleep(TICK_MS)
      }
      if (fault) await heal()

      // Ends converged: every peer holds every note as its writer wrote it.
      for (const peer of net.list) {
        await waitFor(
          async () => (await peer.list('note/')).length === expected.size,
          {
            timeout: 90000,
            label: `${peer.id} holds all ${expected.size} notes`
          }
        )
        const rows = await peer.list('note/')
        const got = new Map(rows.map((r) => [r.seq, r]))
        for (const [n, value] of expected) expect(got.get(n)).toEqual(value)
      }
      await steady('end')

      const summary = {}
      for (const metric of [
        'connections',
        'pending',
        'peers',
        'topics',
        'sockets',
        'handles',
        'timers'
      ]) {
        const values = series.map((s) => s[metric])
        summary[metric] = {
          min: Math.min(...values),
          max: Math.max(...values),
          first: values[0],
          last: values.at(-1)
        }
      }
      // Only steady samples follow a full collection.
      const heaps = steadyHandles.map((s) => s.heap)
      summary.heap = {
        min: Math.min(...heaps),
        max: Math.max(...heaps),
        first: heaps[0],
        last: heaps.at(-1)
      }
      net.list[0].trace('hygiene.summary', {
        replay: SEED,
        samples,
        faults: nextIndex,
        ...counts,
        summary
      })
      // eslint-disable-next-line no-console
      console.log(
        `hygiene soak seed ${SEED}: ${samples} samples, ${JSON.stringify(counts)}\n${JSON.stringify(summary)}`
      )
      expect(counts.steady).toBeGreaterThan(0)
      // Sockets end where they started; steady() checked every heal.
      for (const id of PEERS) expect(socketsOf(id)).toHaveLength(baseline[id])
      // A closed swarm that left its intervals running piles timers up.
      // Needs three steady samples to have a first and a last third.
      const timers = steadyHandles.map((s) => s.timers)
      const third = Math.floor(timers.length / 3)
      if (third > 0) {
        expect(Math.max(...timers.slice(-third))).toBeLessThanOrEqual(
          Math.max(...timers.slice(0, third)) + TIMER_SLACK
        )
      }

      // The app's lock (CLOSE_ALL_INSTANCES) on every peer leaves only the
      // testnet's sockets.
      for (const peer of net.list) await peer.closeAll()
      expect(
        guard
          .liveSockets()
          .filter((s) => udxOwner.get(s.udx) !== 'testnet')
          .map(describeSocket)
      ).toEqual([])
    },
    SOAK_MS + 300000
  )
})
