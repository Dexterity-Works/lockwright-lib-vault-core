import { createNetwork, shareVault, sleep, waitFor } from './harness.js'

// Extension: a seeded soak. Random writes, removals, drops, restarts and
// one kick per round across 4 peers, for LOCKWRIGHT_SOAK_MINUTES (default
// 30). Opt-in: LOCKWRIGHT_SOAK=1. The seed is logged and in the trace;
// LOCKWRIGHT_SOAK_SEED replays a run. Every round ends with the peers that
// are still members agreeing on every key.
const soak = process.env.LOCKWRIGHT_SOAK === '1' ? test : test.skip
const minutes = Number(process.env.LOCKWRIGHT_SOAK_MINUTES || 30)
const seed = Number(process.env.LOCKWRIGHT_SOAK_SEED || Date.now() % 1000000)

// mulberry32
const rng = (s) => () => {
  s = (s + 0x6d2b79f5) | 0
  let t = Math.imul(s ^ (s >>> 15), 1 | s)
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296
}

describe('seeded soak', () => {
  let net = null
  afterEach(async () => {
    await net?.destroy()
    net = null
  })

  soak(
    `random faults for ${minutes} min (seed ${seed})`,
    async () => {
      const random = rng(seed)
      const pick = (list) => list[Math.floor(random() * list.length)]
      // eslint-disable-next-line no-console
      console.log(`soak seed ${seed}, ${minutes} min`)
      net = await createNetwork({
        peers: ['A', 'B', 'C', 'D'],
        size: 6,
        name: 'soak'
      })
      net.tracers.A.record('soak.seed', { seed, minutes })
      const { A } = net.peers
      await shareVault(net)
      await A.ensureEpoch({ start: true })
      const members = new Set(net.list.map((p) => p.id))
      const expected = new Map() // key -> value as the writer saw it
      const deadline = Date.now() + minutes * 60000
      let round = 0
      const faults = { drop: 0, restart: 0, kick: 0, writes: 0, removes: 0 }
      while (Date.now() < deadline) {
        round++
        const live = net.list.filter((p) => members.has(p.id))
        net.tracers.A.record('soak.round', { round, members: [...members] })
        const offline = []
        const roll = random()
        if (roll < 0.3 && live.length > 2) {
          const victim = pick(live.filter((p) => p !== A))
          await victim.goOffline()
          offline.push(victim)
          faults.drop++
        } else if (roll < 0.45) {
          const victim = pick(live.filter((p) => p !== A))
          await victim.restartVault()
          faults.restart++
        }
        // One operation per key per round: two peers writing the same key
        // before they sync are concurrent, and Autobase's linearization, not
        // program order, decides which one wins. The model assumes a single
        // last writer per key, so a round never touches a key twice.
        const touched = new Set()
        for (let i = 0; i < 1 + Math.floor(random() * 6); i++) {
          const writer = pick(live.filter((p) => !offline.includes(p)))
          const key = `note/${Math.floor(random() * 40)}`
          if (touched.has(key)) continue
          touched.add(key)
          if (random() < 0.15 && expected.has(key)) {
            await writer.remove(key)
            expected.delete(key)
            faults.removes++
            net.tracers.A.record('soak.op', {
              round,
              op: 'remove',
              key,
              by: writer.id
            })
          } else {
            const value = {
              round,
              by: writer.id,
              n: Math.floor(random() * 1e6)
            }
            await writer.add(key, value)
            expected.set(key, value)
            faults.writes++
            net.tracers.A.record('soak.op', {
              round,
              op: 'add',
              key,
              by: writer.id
            })
          }
        }
        await sleep(200 + Math.floor(random() * 800))
        for (const peer of offline) await peer.goOnline()
        if (random() < 0.08 && live.length > 2) {
          const victim = pick(
            live.filter((p) => p !== A && !offline.includes(p))
          )
          await A.kick(victim.deviceId)
          members.delete(victim.id)
          faults.kick++
          await waitFor(async () => (await victim.epochStatus()).revoked, {
            timeout: 60000,
            label: `${victim.id} learns it was kicked`
          })
        }
        // Convergence: every member reads what the last writer wrote.
        const now = net.list.filter((p) => members.has(p.id))
        for (const peer of now) {
          await waitFor(
            async () => {
              for (const [key, value] of expected) {
                const got = await peer.get(key)
                if (JSON.stringify(got) !== JSON.stringify(value)) return false
              }
              const rows = await peer.list('note/')
              return rows.length === expected.size
            },
            {
              timeout: 90000,
              label: `round ${round}: ${peer.id} converged on ${expected.size} keys`
            }
          )
        }
      }
      net.tracers.A.record('soak.done', { rounds: round, ...faults })
      // eslint-disable-next-line no-console
      console.log(
        `soak done: ${round} rounds, ${JSON.stringify(faults)}, members ${[...members]}`
      )
      expect(round).toBeGreaterThan(0)
    },
    (minutes + 10) * 60000
  )
})
