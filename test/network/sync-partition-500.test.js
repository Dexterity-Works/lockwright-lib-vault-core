import crypto from 'crypto'

import { createNetwork, shareVault, sleep, waitFor } from './harness.js'

// About 12 minutes with the default partition, so opt-in (#109 in the
// superproject): LOCKWRIGHT_PARTITION_500=1, or LOCKWRIGHT_NET_PARTITION_MS.
const long =
  process.env.LOCKWRIGHT_PARTITION_500 === '1' ||
  process.env.LOCKWRIGHT_NET_PARTITION_MS
    ? test
    : test.skip
// How long C stays cut off. Production-shaped default: five minutes.
const PARTITION_MS = Number(process.env.LOCKWRIGHT_NET_PARTITION_MS ?? 300000)
// 500 seed rows: 400 notes and 100 records.
const SEED = 500
const NOTES = 400
const PREFIX = 'note/'
const key = (name) => `${PREFIX}${name}`

// Every fifth note and every third record carries a file of 4 to 32 KiB,
// derived from its key so any peer can rebuild the expected bytes.
const hasFile = (i) => i % 5 === 0
const fileFor = (k) => {
  const seed = crypto.createHash('sha256').update(k).digest()
  const size = 4096 + (seed.readUInt16BE(0) % (28 * 1024 + 1))
  return Buffer.concat(
    Array.from({ length: Math.ceil(size / 32) }, () => seed)
  ).subarray(0, size)
}

// Records as the app stores them (recordNamespaces.js): a row under
// `record/<id>` (schema 1) and its twin under `record-v2/<id>`, and each
// attachment under `<namespace><id>/file/<fileId>` in both.
const v1 = (id) => `record/${id}`
const v2 = (id) => `record-v2/${id}`
const fileKeys = (id, fileId) => [
  `${v2(id)}/file/${fileId}`,
  `${v1(id)}/file/${fileId}`
]
const attachmentsOf = (id) =>
  Number(id.replace(/\D/g, '')) % 3 === 0 ? { f0: fileFor(`${id}/f0`) } : null
const recordFor = (id, n, by, extra = {}) => ({
  id,
  type: 'note',
  vaultId: 'shared',
  folder: null,
  isFavorite: false,
  createdAt: 1,
  updatedAt: Date.now(),
  version: 1,
  data: { title: id, n, by, ...extra }
})
// What both namespaces must agree on. The v1 projection adds `websites`
// and the v2 conversion `uris`; neither is part of a non-login record.
const content = (record) => {
  const data = { ...record?.data }
  delete data.uris
  delete data.websites
  return { data, updatedAt: record?.updatedAt }
}

/**
 * Writes the way each client does. `app`: the current app, v2 first (the
 * worklet projects v1) and attachments to both namespaces. `old`: a schema 1
 * client, v1 only (the worklet mirrors v2). `held`: the attachments the
 * record has afterwards (an edit writes none and keeps its own).
 */
const records = {
  async write(
    peer,
    model,
    id,
    record,
    { as = 'app', files = null, held = files } = {}
  ) {
    if (as === 'app') {
      await peer.add(v2(id), { ...record, schema: 2 })
    } else {
      await peer.add(v1(id), record)
    }
    for (const [fileId, bytes] of Object.entries(files ?? {})) {
      const [k2, k1] = fileKeys(id, fileId)
      if (as === 'app') await peer.add(k2, {}, bytes, `${fileId}.bin`)
      await peer.add(k1, {}, bytes, `${fileId}.bin`)
    }
    model.write(id, content(record), held)
  },
  async remove(peer, model, id, { as = 'app' } = {}) {
    for (const fileId of Object.keys(attachmentsOf(id) ?? {})) {
      const [k2, k1] = fileKeys(id, fileId)
      if (as === 'app') await peer.appDeps.activeVaultRemoveFile(k2)
      await peer.appDeps.activeVaultRemoveFile(k1)
    }
    if (as === 'app') await peer.remove(v2(id))
    await peer.remove(v1(id))
    model.remove(id)
  }
}

/**
 * The view every peer must end with: key -> candidate rows. A row is
 * `{ value, file }` (file a Buffer, or for records `{ fileId: Buffer }`, or
 * null); `null` is a removal. One candidate for keys written on one side
 * only, several for a contested key: every peer must pick one, and the same
 * one.
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

/** Notes and records, combined the same way. */
const model = (notes = new Expected(), recs = new Expected()) => ({
  notes,
  records: recs
})
const then = (a, b) => model(a.notes.then(b.notes), a.records.then(b.records))
const merge = (a, b) =>
  model(a.notes.merge(b.notes), a.records.merge(b.records))

const same = (a, b) => JSON.stringify(a) === JSON.stringify(b)

/** Pick the candidate `row` is, or throw naming the key. */
const pick = (peer, k, candidates, row, eq) => {
  const match = candidates.find((c) =>
    c === null ? row === null : row !== null && eq(c.value, row)
  )
  if (match === undefined) {
    const want = candidates.map((c) => JSON.stringify(c?.value ?? null))
    throw new Error(
      `${peer.id}: ${k} is ${JSON.stringify(row)}, wanted one of ${want.join(' | ')}`
    )
  }
  return match
}

const sameFile = async (peer, k, want) => {
  const bytes = await peer.getFile(k)
  if (!bytes || !Buffer.from(bytes).equals(want)) {
    throw new Error(
      `${peer.id}: ${k} file is ${bytes ? bytes.length : 'missing'}, wanted ${want.length} bytes`
    )
  }
}

/** Every note and record key the peer's Autopass view holds, sorted. */
const storedKeys = async (peer) => {
  const keys = []
  for await (const { key: k } of peer.instance.list()) {
    if (/^(note|record|record-v2)\//.test(k)) keys.push(k)
  }
  return keys.sort()
}

/**
 * Notes: each value matches a candidate. Returns the keys the peer must
 * hold and the contested picks (as JSON).
 */
const checkNotes = async (peer, expected) => {
  const view = new Map()
  for (const row of await peer.list(PREFIX)) view.set(row.k, row)
  for (const k of view.keys()) {
    if (!expected.rows.has(k)) throw new Error(`${peer.id}: unexpected ${k}`)
  }
  const chosen = {}
  const keys = []
  for (const [k, candidates] of expected.rows) {
    const match = pick(peer, k, candidates, view.get(k) ?? null, same)
    if (match) keys.push(k)
    if (match?.file) await sameFile(peer, k, match.file)
    if (candidates.length > 1) chosen[k] = JSON.stringify(match?.value ?? null)
  }
  return { chosen, keys }
}

/**
 * Records, through the merged list the app reads (activeVaultList
 * 'record/'): each live id once and matching a candidate, deleted ids
 * absent; each live id's v1 and v2 rows agree; every attachment byte-equal
 * in both namespaces.
 */
const checkRecords = async (peer, expected, stored) => {
  const merged = new Map()
  for (const row of await peer.list('record/')) {
    if (merged.has(row.id)) {
      throw new Error(`${peer.id}: ${row.id} listed twice by the merged list`)
    }
    merged.set(row.id, row)
  }
  for (const id of merged.keys()) {
    if (!expected.rows.has(id)) throw new Error(`${peer.id}: unexpected ${id}`)
  }
  // Both namespaces' rows by id, record rows only (attachments carry {}).
  const twins = new Map()
  for (const row of await peer.list('record')) {
    if (!row?.id) continue
    twins.set(row.id, [...(twins.get(row.id) ?? []), content(row)])
  }
  const chosen = {}
  const keys = []
  // Every bad id, not only the first, each with the rows stored for it.
  const problems = []
  for (const [id, candidates] of expected.rows) {
    const own = (k) => k === v1(id) || k === v2(id) || k.includes(`/${id}/`)
    const row = merged.get(id) ?? null
    // Finding S1 (sync-delete-resurrect.test.js owns it): a delete can come
    // back as a lone record-v2 row when two incremental reconciles overlap.
    // Tolerated here only in exactly that shape, and traced, so this test
    // keeps judging everything else; LOCKWRIGHT_S1_STRICT=1 makes it fail.
    const lone = stored.filter(own)
    if (
      process.env.LOCKWRIGHT_S1_STRICT !== '1' &&
      row &&
      candidates.every((c) => c === null) &&
      lone.includes(v2(id)) &&
      lone.every((k) => k === v2(id) || k.startsWith(`${v2(id)}/`))
    ) {
      // The rebuilt v2 row, and the v2 attachment rows rebuilt with it.
      peer.trace('s1.observed', { id, rows: lone.length })
      keys.push(...lone)
      continue
    }
    try {
      const match = pick(peer, id, candidates, row && content(row), same)
      if (candidates.length > 1) {
        chosen[id] = JSON.stringify(match?.value ?? null)
      }
      if (!match) continue
      const rows = twins.get(id) ?? []
      if (rows.length !== 2 || !same(rows[0], rows[1])) {
        throw new Error(
          `${peer.id}: ${id} has ${rows.length} rows across record/ and record-v2/: ${JSON.stringify(rows)}`
        )
      }
      keys.push(v1(id), v2(id))
      for (const [fileId, bytes] of Object.entries(match.file ?? {})) {
        for (const k of fileKeys(id, fileId)) {
          await sameFile(peer, k, bytes)
          keys.push(k)
        }
      }
    } catch (error) {
      const held = stored.filter(own).join(', ') || 'none'
      problems.push(`${error.message} (stored: ${held})`)
    }
  }
  if (problems.length) {
    throw new Error(
      `${problems.length} record(s) wrong: ${problems.slice(0, 8).join('; ')}`
    )
  }
  return { chosen, keys }
}

/**
 * Compare one peer with `expected`. Throws naming the first missing,
 * extra, duplicate or differing key. Returns the row each contested key
 * resolved to (as JSON) so peers can be compared with each other.
 */
const checkView = async (peer, expected) => {
  const stored = await storedKeys(peer)
  const notes = await checkNotes(peer, expected.notes)
  const recs = await checkRecords(peer, expected.records, stored)
  const want = [...notes.keys, ...recs.keys].sort()
  if (!same(stored, want)) {
    const held = new Set(stored)
    const wanted = new Set(want)
    const extra = stored.filter((k) => !wanted.has(k))
    const missing = want.filter((k) => !held.has(k))
    throw new Error(
      `${peer.id}: stored keys differ: extra ${extra.slice(0, 5).join(', ')} (${extra.length}), missing ${missing.slice(0, 5).join(', ')} (${missing.length})`
    )
  }
  return { ...notes.chosen, ...recs.chosen }
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

describe('a three-peer vault with 500 notes and records across a partition', () => {
  let net = null

  afterEach(async () => {
    await net?.destroy()
    net = null
  })

  long(
    `C is cut off for ${PARTITION_MS} ms while both sides write, then all agree`,
    async () => {
      net = await createNetwork({ peers: ['A', 'B', 'C'], name: 'p500' })
      const { A, B, C } = net.peers
      await shareVault(net)

      // Seed: 400 notes and 100 records, written round-robin, every peer
      // writing its share at the same time. Records alternate between the
      // app's v2 write and a schema 1 client's v1 write.
      const seed = model()
      await Promise.all(
        net.list.map(async (peer, share) => {
          for (let i = share; i < SEED; i += net.list.length) {
            if (i >= NOTES) {
              const id = `r${i}`
              await records.write(
                peer,
                seed.records,
                id,
                recordFor(id, 0, peer.id),
                { as: i % 2 ? 'old' : 'app', files: attachmentsOf(id) }
              )
              continue
            }
            const k = key(`s${i}`)
            const value = { k, v: 0, by: peer.id }
            const file = hasFile(i) ? fileFor(k) : null
            if (file) {
              await peer.add(k, value, file, `${k}.bin`)
            } else {
              await peer.add(k, value)
            }
            seed.notes.write(k, value, file)
          }
        })
      )
      expect(seed.notes.rows.size + seed.records.rows.size).toBe(SEED)
      await converged(net.list, seed, {
        timeout: 240000,
        label: 'all three hold the 500 seed rows'
      })

      const cut = Date.now()
      await C.goOffline()
      expect(C.instance.swarm.suspended).toBe(true)

      // Both sides write apart. Seed notes with i % 5 === 0 carry a file and
      // are left alone; the rest are edited or removed. Records are edited
      // and removed by the app on A and B and by a schema 1 client on C.
      const ab = model()
      const c = model()
      const side = async (
        peers,
        m,
        tag,
        { as, edit, drop, contested, mix, recs }
      ) => {
        const [first, second = first] = peers
        for (let i = 0; i < 50; i++) {
          const peer = i % 2 ? second : first
          const k = key(`p${tag}${i}`)
          const value = { k, v: 0, by: peer.id }
          if (i % 5 === 0) {
            await peer.add(k, value, fileFor(k), `${k}.bin`)
            m.notes.write(k, value, fileFor(k))
          } else {
            await peer.add(k, value)
            m.notes.write(k, value)
          }
        }
        for (const i of edit) {
          const k = key(`s${i}`)
          const value = { k, v: 1, by: first.id }
          await first.add(k, value)
          m.notes.write(k, value)
        }
        for (const i of drop) {
          await second.remove(key(`s${i}`))
          m.notes.remove(key(`s${i}`))
        }
        for (const i of contested) {
          const k = key(`s${i}`)
          const value = { k, v: 2, by: first.id, contested: true }
          await first.add(k, value)
          m.notes.write(k, value)
        }
        if (mix === 'remove') {
          await first.remove(key('s21'))
          m.notes.remove(key('s21'))
        } else {
          const value = { k: key('s21'), v: 3, by: first.id }
          await first.add(key('s21'), value)
          m.notes.write(key('s21'), value)
        }

        for (let i = 0; i < 10; i++) {
          const peer = i % 2 ? second : first
          const id = `r${tag}${i}`
          await records.write(peer, m.records, id, recordFor(id, 0, peer.id), {
            as,
            files: attachmentsOf(id)
          })
        }
        for (const i of recs.edit) {
          const id = `r${i}`
          await records.write(
            first,
            m.records,
            id,
            recordFor(id, 1, first.id, { edited: tag }),
            { as, held: attachmentsOf(id) }
          )
        }
        for (const i of recs.drop) {
          await records.remove(second, m.records, `r${i}`, { as })
        }
      }
      // r440 and r441 are edited on both sides; r451 is removed on A and
      // edited on C, r452 the other way round.
      await Promise.all([
        side([A, B], ab, 'ab', {
          as: 'app',
          edit: [1, 2, 3, 4, 6, 7, 8, 9],
          drop: [101, 102, 103, 104, 106, 107, 108, 109],
          contested: [11, 12, 13, 14],
          mix: 'remove',
          recs: {
            edit: [400, 401, 402, 403, 404, 440, 441, 452],
            drop: [410, 411, 412, 413, 414, 451]
          }
        }),
        side([C], c, 'c', {
          as: 'old',
          edit: [31, 32, 33, 34, 36, 37, 38, 39],
          drop: [201, 202, 203, 204, 206, 207, 208, 209],
          contested: [11, 12, 13, 14],
          mix: 'edit',
          recs: {
            edit: [420, 421, 422, 423, 424, 440, 441, 451],
            drop: [430, 431, 432, 433, 434, 452]
          }
        })
      ])

      // Within the partition each side sees only its own writes: a key the
      // other side wrote fails the stored key check.
      const apart = () =>
        Promise.all([
          converged([A, B], then(seed, ab), {
            timeout: 120000,
            label: 'A and B agree on their side'
          }),
          converged([C], then(seed, c), {
            timeout: 60000,
            label: 'C holds its own side'
          })
        ])
      await apart()
      expect(C.instance.swarm.suspended).toBe(true)
      const remaining = cut + PARTITION_MS - Date.now()
      if (remaining > 0) await sleep(remaining)
      // Still apart at the end of the partition, not only at its start.
      await apart()
      expect(C.instance.swarm.suspended).toBe(true)

      await C.goOnline()
      expect(C.instance.swarm.suspended).toBe(false)
      const all = then(seed, merge(ab, c))
      const picks = await converged(net.list, all, {
        timeout: 240000,
        label: 'all three agree after the heal'
      })
      expect(Object.keys(picks).sort()).toEqual(
        [
          ...[11, 12, 13, 14, 21].map((i) => key(`s${i}`)),
          ...['r440', 'r441', 'r451', 'r452']
        ].sort()
      )
      // 16 notes removed, and s21 when its removal won.
      const gone = 16 + (picks[key('s21')] === 'null' ? 1 : 0)
      expect(await A.list(PREFIX)).toHaveLength(NOTES + 100 - gone)
      // 10 records removed, r451 and r452 when their removal won.
      const recsGone =
        10 + ['r451', 'r452'].filter((id) => picks[id] === 'null').length
      // A deleted id still listed is an S1 row checkRecords tolerated, and
      // traced; none may be listed untraced.
      const listed = await A.list('record/')
      const deleted = (row) =>
        all.records.rows.get(row.id).every((c) => c === null)
      const s1 = new Set(
        net.tracers.A.events
          .filter((e) => e.event === 's1.observed')
          .map((e) => e.id)
      )
      expect(listed.filter((row) => deleted(row) && !s1.has(row.id))).toEqual(
        []
      )
      expect(listed.filter((row) => !deleted(row))).toHaveLength(
        SEED - NOTES + 20 - recsGone
      )

      // Traces: C suspended then resumed and connected again, with no vault
      // connection in between; the only errors are resets on cut
      // connections.
      const traceC = net.tracers.C.events
      const suspend = traceC.findIndex((e) => e.event === 'swarm.suspend')
      const resume = traceC.findIndex((e) => e.event === 'swarm.resume')
      expect(suspend).toBeGreaterThan(-1)
      expect(resume).toBeGreaterThan(suspend)
      const vaultConn = (e) => e.event === 'conn.open' && e.label === 'vault'
      expect(traceC.slice(suspend, resume).filter(vaultConn)).toEqual([])
      expect(traceC.slice(resume).some(vaultConn)).toBe(true)
      expect(
        errors(net).filter((line) => !/ conn ECONNRESET: /.test(line))
      ).toEqual([])
    },
    // Slow under --detectOpenHandles (async hooks on ~2000 appends): a 20 s
    // partition run takes 8–16 min on a busy host.
    PARTITION_MS + 2400000
  )
})
