import crypto from 'crypto'

import { createNetwork, shareVault, sleep, waitFor } from './harness.js'

// How long C stays cut off. Production-shaped default: five minutes.
const PARTITION_MS = Number(process.env.LOCKWRIGHT_NET_PARTITION_MS ?? 300000)
const SEED = 500
const PREFIX = 'note/'
const key = (name) => `${PREFIX}${name}`

// Every fifth record carries a file of 4 to 32 KiB, derived from its key so
// any peer can rebuild the expected bytes. About 1.8 MiB over 500 records.
const hasFile = (i) => i % 5 === 0
const fileFor = (k) => {
  const seed = crypto.createHash('sha256').update(k).digest()
  const size = 4096 + (seed.readUInt16BE(0) % (28 * 1024 + 1))
  return Buffer.concat(
    Array.from({ length: Math.ceil(size / 32) }, () => seed)
  ).subarray(0, size)
}

/**
 * The view every peer must end with: key -> candidate rows. A row is
 * `{ value, file }` (file a Buffer or null); `null` is a removal. One
 * candidate for keys written on one side only, several for a contested key:
 * every peer must pick one, and the same one.
 */
class Expected {
  constructor() {
    this.rows = new Map()
  }

  write(k, value, file = null) {
    this.rows.set(k, [{ value, file }])
  }

  remove(k) {
    this.rows.set(k, [null])
  }

  /** Later writes on top of these: a key in `later` replaces this one. */
  then(later) {
    const out = new Expected()
    for (const [k, rows] of this.rows) out.rows.set(k, [...rows])
    for (const [k, rows] of later.rows) out.rows.set(k, [...rows])
    return out
  }

  /** Concurrent writes from another side: a key on both is contested. */
  merge(other) {
    const out = new Expected()
    for (const [k, rows] of this.rows) out.rows.set(k, [...rows])
    for (const [k, rows] of other.rows) {
      out.rows.set(k, [...(out.rows.get(k) ?? []), ...rows])
    }
    return out
  }
}

const same = (a, b) => JSON.stringify(a) === JSON.stringify(b)

/**
 * Compare one peer's rows under PREFIX with `expected`. Throws naming the
 * first missing, extra, duplicate or differing key. Returns the row each
 * contested key resolved to (as JSON) so peers can be compared with each
 * other.
 */
const checkView = async (peer, expected) => {
  const rows = await peer.list(PREFIX)
  const view = new Map()
  for (const row of rows) {
    if (view.has(row.k)) throw new Error(`${peer.id}: duplicate ${row.k}`)
    view.set(row.k, row)
  }
  for (const k of view.keys()) {
    if (!expected.rows.has(k)) throw new Error(`${peer.id}: unexpected ${k}`)
  }
  const chosen = {}
  for (const [k, candidates] of expected.rows) {
    const row = view.get(k) ?? null
    const match = candidates.find((c) =>
      c === null ? row === null : row !== null && same(c.value, row)
    )
    if (match === undefined) {
      const want = candidates.map((c) => JSON.stringify(c?.value ?? null))
      throw new Error(
        `${peer.id}: ${k} is ${JSON.stringify(row)}, wanted one of ${want.join(' | ')}`
      )
    }
    if (match?.file) {
      const bytes = await peer.getFile(k)
      if (!bytes || !Buffer.from(bytes).equals(match.file)) {
        throw new Error(
          `${peer.id}: ${k} file is ${bytes ? bytes.length : 'missing'}, wanted ${match.file.length} bytes`
        )
      }
    }
    if (candidates.length > 1) chosen[k] = JSON.stringify(match?.value ?? null)
  }
  if (view.size !== rows.length) throw new Error(`${peer.id}: duplicates`)
  return chosen
}

/** Every peer matches `expected` and they agree on every contested key. */
const converged = (peers, expected, { timeout, label }) =>
  waitFor(
    async () => {
      const picks = []
      for (const peer of peers) picks.push(await checkView(peer, expected))
      for (const [k, v] of Object.entries(picks[0])) {
        const odd = peers.findIndex((_, i) => picks[i][k] !== v)
        if (odd !== -1) {
          throw new Error(
            `${k}: ${peers[0].id} has ${v}, ${peers[odd].id} has ${picks[odd][k]}`
          )
        }
      }
      return picks[0]
    },
    { timeout, interval: 1000, label }
  )

const errors = (net) =>
  Object.values(net.tracers).flatMap((t) =>
    t.events
      .filter((e) => e.event === 'error')
      .map((e) => `${e.peer} ${e.where} ${e.code}: ${e.message}`)
  )

const updates = (net, id) =>
  net.tracers[id].events.filter(
    (e) => e.event === 'autobase.update' && e.label === 'vault'
  ).length

describe('a three-peer vault with 500 records across a partition', () => {
  let net = null

  afterEach(async () => {
    await net?.destroy()
    net = null
  })

  test(
    `C is cut off for ${PARTITION_MS} ms while both sides write, then all agree`,
    async () => {
      net = await createNetwork({ peers: ['A', 'B', 'C'], name: 'p500' })
      const { A, B, C } = net.peers
      await shareVault(net)

      // Seed: 500 records, written round-robin, every peer writing its share
      // at the same time.
      const seed = new Expected()
      const write = async (peer, k, value) => {
        const file = hasFile(Number(k.slice(k.indexOf('/s') + 2)))
          ? fileFor(k)
          : null
        if (file) {
          await peer.add(k, value, file, `${k}.bin`)
        } else {
          await peer.add(k, value)
        }
        seed.write(k, value, file)
      }
      await Promise.all(
        net.list.map(async (peer, share) => {
          for (let i = share; i < SEED; i += net.list.length) {
            const k = key(`s${i}`)
            await write(peer, k, { k, v: 0, by: peer.id })
          }
        })
      )
      expect(seed.rows.size).toBe(SEED)
      await converged(net.list, seed, {
        timeout: 240000,
        label: 'all three hold the 500 seed records'
      })

      const cut = Date.now()
      await C.goOffline()
      expect(C.instance.swarm.suspended).toBe(true)
      const before = Object.fromEntries(
        net.list.map((p) => [p.id, updates(net, p.id)])
      )

      // Both sides write apart. Seed keys with i % 5 === 0 carry a file and
      // are left alone; the rest are edited or removed.
      const ab = new Expected()
      const c = new Expected()
      const side = async (
        peers,
        model,
        tag,
        { edit, drop, contested, mix }
      ) => {
        const [first, second = first] = peers
        for (let i = 0; i < 50; i++) {
          const peer = i % 2 ? second : first
          const k = key(`p${tag}${i}`)
          const value = { k, v: 0, by: peer.id }
          if (i % 5 === 0) {
            await peer.add(k, value, fileFor(k), `${k}.bin`)
            model.write(k, value, fileFor(k))
          } else {
            await peer.add(k, value)
            model.write(k, value)
          }
        }
        for (const i of edit) {
          const k = key(`s${i}`)
          const value = { k, v: 1, by: first.id }
          await first.add(k, value)
          model.write(k, value)
        }
        for (const i of drop) {
          await second.remove(key(`s${i}`))
          model.remove(key(`s${i}`))
        }
        for (const i of contested) {
          const k = key(`s${i}`)
          const value = { k, v: 2, by: first.id, contested: true }
          await first.add(k, value)
          model.write(k, value)
        }
        if (mix === 'remove') {
          await first.remove(key('s21'))
          model.remove(key('s21'))
        } else {
          const value = { k: key('s21'), v: 3, by: first.id }
          await first.add(key('s21'), value)
          model.write(key('s21'), value)
        }
      }
      await Promise.all([
        side([A, B], ab, 'ab', {
          edit: [1, 2, 3, 4, 6, 7, 8, 9],
          drop: [101, 102, 103, 104, 106, 107, 108, 109],
          contested: [11, 12, 13, 14],
          mix: 'remove'
        }),
        side([C], c, 'c', {
          edit: [31, 32, 33, 34, 36, 37, 38, 39],
          drop: [201, 202, 203, 204, 206, 207, 208, 209],
          contested: [11, 12, 13, 14],
          mix: 'edit'
        })
      ])

      // Within the partition each side sees only its own writes.
      await converged([A, B], seed.then(ab), {
        timeout: 120000,
        label: 'A and B agree on their side'
      })
      await converged([C], seed.then(c), {
        timeout: 60000,
        label: 'C holds its own side'
      })
      expect(C.instance.swarm.suspended).toBe(true)
      const remaining = cut + PARTITION_MS - Date.now()
      if (remaining > 0) await sleep(remaining)

      await C.goOnline()
      expect(C.instance.swarm.suspended).toBe(false)
      const all = seed.then(ab.merge(c))
      // 500 - 8 - 8 removed; s21 is remove-vs-edit so it is counted either way
      const picks = await converged(net.list, all, {
        timeout: 240000,
        label: 'all three agree after the heal'
      })
      expect(Object.keys(picks).sort()).toEqual(
        [11, 12, 13, 14, 21].map((i) => key(`s${i}`))
      )
      const final = await A.list(PREFIX)
      const gone = 16 + (picks[key('s21')] === 'null' ? 1 : 0)
      expect(final).toHaveLength(SEED + 100 - gone)

      // Traces: C suspended then resumed and connected again; every base
      // kept updating; the only errors are resets on cut connections.
      const traceC = net.tracers.C.events
      const suspend = traceC.findIndex((e) => e.event === 'swarm.suspend')
      const resume = traceC.findIndex((e) => e.event === 'swarm.resume')
      expect(suspend).toBeGreaterThan(-1)
      expect(resume).toBeGreaterThan(suspend)
      expect(
        traceC
          .slice(resume)
          .some((e) => e.event === 'conn.open' && e.label === 'vault')
      ).toBe(true)
      for (const peer of net.list) {
        expect(updates(net, peer.id)).toBeGreaterThan(before[peer.id])
      }
      expect(
        errors(net).filter((line) => !/ conn ECONNRESET: /.test(line))
      ).toEqual([])
    },
    PARTITION_MS + 900000
  )
})
