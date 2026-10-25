import v8 from 'v8'
import vm from 'vm'

import guard from './guard.cjs'
import { createNetwork, shareVault, sleep, waitFor } from './harness.js'

// Three peers on one vault for LOCKWRIGHT_NET_SOAK_MS (default 60 s): a
// write every 1-2 s, a fault every ~10 s (suspend/resume, close/reopen, or
// a vault restart), a `hygiene.sample` per peer every 5 s. The schedule
// comes from a seeded PRNG; LOCKWRIGHT_NET_SOAK_SEED replays a run. The
// samples bound what a swarm may hold while peers come and go, and every
// heal must bring each peer's UDX sockets back to the baseline.
const SOAK_MS = Number(process.env.LOCKWRIGHT_NET_SOAK_MS || 60000)
const SEED = Number(process.env.LOCKWRIGHT_NET_SOAK_SEED || Date.now() % 1e6)
const PEERS = ['A', 'B', 'C']
const N = PEERS.length
const SAMPLE_MS = 5000
const TICK_MS = 200
// PeerInfos a swarm may keep beyond its live peers: one per peer that is
// mid-backoff after a close, plus a restarted swarm's fresh entry.
const PEER_SLACK = 2
const HEAL_TIMEOUT = 60000

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
      const random = rng(SEED)
      const between = (min, max) => min + Math.floor(random() * (max - min))
      const pick = (list) => list[Math.floor(random() * list.length)]
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
      const describe = (socket) => {
        const address = socket.address()
        return {
          owner: udxOwner.get(socket.udx) ?? 'unknown',
          address: address ? `${address.host}:${address.port}` : 'unbound',
          streams: socket.streams.size
        }
      }
      const connected = () =>
        net.list.every(
          (p) =>
            state[p.id] === 'open' && swarmOf(p)?.connections.size === N - 1
        )

      await waitFor(connected, {
        timeout: HEAL_TIMEOUT,
        label: 'every peer holds a connection to each other peer'
      })
      const baseline = Object.fromEntries(
        PEERS.map((id) => [id, socketsOf(id).length])
      )
      const baseHandles = process.getActiveResourcesInfo().length
      net.list[0].trace('hygiene.baseline', {
        sockets: baseline,
        handles: baseHandles
      })

      const series = []
      let samples = 0
      const sample = (phase) => {
        samples++
        const handles = process.getActiveResourcesInfo().length
        if (phase === 'steady') gc()
        const heap = process.memoryUsage().heapUsed
        const other = guard
          .liveSockets()
          .filter((s) => !udxOwner.has(s.udx))
          .map(describe)
        if (other.length) fail('live UDX sockets no peer owns', other)
        for (const peer of net.list) {
          const swarm = swarmOf(peer)
          const row = {
            n: samples,
            phase,
            state: state[peer.id],
            connections: swarm?.connections.size ?? 0,
            pending: swarm
              ? swarm._allConnections.size - swarm.connections.size
              : 0,
            peers: swarm?.peers.size ?? 0,
            topics: swarm ? [...swarm.topics()].length : 0,
            sockets: socketsOf(peer.id).length,
            handles,
            heap
          }
          peer.trace('hygiene.sample', row)
          series.push({ peer: peer.id, at: Date.now(), ...row })
          const where = { peer: peer.id, ...row }
          if (row.connections > 2 * (N - 1)) {
            fail(`more than ${2 * (N - 1)} connections`, where)
          }
          if (swarm && row.topics !== 1)
            fail('not one topic on the swarm', where)
          if (row.peers > N - 1 + PEER_SLACK) {
            fail(`peers map past ${N - 1 + PEER_SLACK}`, where)
          }
          if (phase === 'steady' && row.connections !== N - 1) {
            fail(`not ${N - 1} connections at steady state`, where)
          }
        }
      }

      // Steady state after a heal: every peer back to one connection per
      // other peer, then its sockets back to the baseline.
      const steady = async (label) => {
        await waitFor(connected, {
          timeout: HEAL_TIMEOUT,
          interval: TICK_MS,
          label: `${label}: every peer reconnected`
        })
        await waitFor(
          () => PEERS.every((id) => socketsOf(id).length === baseline[id]),
          {
            timeout: 15000,
            interval: TICK_MS,
            label: `${label}: sockets back to ${JSON.stringify(baseline)}`
          }
        ).catch((error) => {
          fail(error.message, guard.liveSockets().map(describe))
        })
        sample('steady')
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
      const counts = { suspend: 0, close: 0, restart: 0, writes: 0, steady: 0 }
      const startFault = async () => {
        const victim = pick(net.list)
        const roll = random()
        const kind = roll < 0.45 ? 'suspend' : roll < 0.8 ? 'close' : 'restart'
        counts[kind]++
        victim.trace('hygiene.fault', { kind })
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
        return { victim, kind, healAt: Date.now() + between(2000, 4000) }
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
        // Peer keeps every instance it built so stop() can close a failed
        // init; drop the closed ones or the soak measures its own retention.
        for (const peer of net.list) {
          peer.created = peer.created.filter(({ instance }) => !instance.closed)
        }
      }

      sample('baseline')
      const t0 = Date.now()
      const deadline = t0 + SOAK_MS
      let nextWrite = t0 + between(1000, 2000)
      let nextSample = t0 + SAMPLE_MS
      let nextFault = t0 + between(8000, 12000)
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
        } else if (!fault && now >= nextFault) {
          nextFault = Date.now() + between(8000, 12000)
          fault = await startFault()
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
        'peers',
        'topics',
        'sockets',
        'handles',
        'heap'
      ]) {
        const values = series.map((s) => s[metric])
        summary[metric] = {
          min: Math.min(...values),
          max: Math.max(...values),
          first: values[0],
          last: values.at(-1)
        }
      }
      net.list[0].trace('hygiene.summary', {
        replay: SEED,
        samples,
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
      // Handles are mostly timers and swing with sync work; a closed swarm
      // that left its intervals running would pile them up past this.
      const steadyHandles = series
        .filter((s) => s.phase === 'steady' && s.peer === PEERS[0])
        .map((s) => s.handles)
      expect(steadyHandles.at(-1)).toBeLessThanOrEqual(
        Math.ceil(baseHandles * 1.5)
      )
    },
    SOAK_MS + 300000
  )
})
