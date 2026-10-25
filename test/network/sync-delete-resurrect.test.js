import { createNetwork, sleep, waitFor } from './harness.js'

// Finding S1. The app deletes a record as `record-v2/<id>` then
// `record/<id>`, and vaultRemove (src/worklet/appDeps.js) mirrors each
// removal into the other namespace, so the two rows go in separate appends.
// An Autopass `update` between them schedules runIncrementalReconcile
// (appDeps.js:582), and scheduleIncrementalReconcile (:608) starts a run on
// every debounce tick without waiting for the run before it, so on a slow
// device several overlap. Here:
//   1. run W lists `record/<id>` without `record-v2/<id>`; reconcileDualStore
//      (src/worklet/utils/recordNamespaces.js:540-545) takes that for a
//      missing twin and writes v2 again from the old v1 row.
//   2. the delete finishes; run C lists neither row.
//   3. W's write lands and W sets previousV1RecordIds with the id (:605).
//   4. C, listing from before that write, finishes last and sets
//      previousV1RecordIds without it.
// The v1 row is gone and the id is no longer in previousV1RecordIds, so the
// delete mirror (recordNamespaces.js:555-559) never removes the rewritten
// v2 row: the deleted record is back in the merged list for good.
// The test holds each step until the next one is in place: W's write until
// C has taken its listing, C's listing until W has finished. Each hold gives
// up after HOLD_MS, so a reconcile that runs one at a time does not
// deadlock here; it then deletes the rewritten row and the test passes.
// Kept failing until runs no longer overlap.
const ID = 'r1'
const V1 = `record/${ID}`
const V2 = `record-v2/${ID}`
const HOLD_MS = 5000

const record = {
  id: ID,
  type: 'note',
  vaultId: 'shared',
  folder: null,
  isFavorite: false,
  createdAt: 1,
  updatedAt: 1,
  version: 1,
  schema: 2,
  data: { title: ID }
}

/** Resolves on `promise` or after HOLD_MS, whichever comes first. */
const hold = (promise) => Promise.race([promise, sleep(HOLD_MS)])

const deferred = () => {
  let resolve
  const promise = new Promise((r) => {
    resolve = r
  })
  return { promise, resolve }
}

/** Until no reconcile has finished for a while. */
const settle = async (peer) => {
  for (;;) {
    const n = peer.updates
    await sleep(500)
    if (peer.updates === n) return
  }
}

describe('a record deleted while incremental reconciles overlap (S1)', () => {
  let net = null

  afterEach(async () => {
    await net?.destroy()
    net = null
  })

  test.failing(
    'A deletes r1 while a stale reconcile finishes last: r1 stays deleted',
    async () => {
      net = await createNetwork({ peers: ['A'], name: 's1' })
      const { A } = net.peers
      await A.createVault({ id: 'shared' })

      // The app's write: v2 first, the worklet projects v1.
      const before = A.updates
      await A.add(V2, record)
      await waitFor(() => A.updates > before, {
        label: 'a reconcile ran after the write'
      })
      await settle(A)
      expect((await A.list('record/')).map((r) => r.id)).toEqual([ID])

      const pass = A.instance
      const view = pass.base.view
      const add = pass.add.bind(pass)
      const remove = pass.remove.bind(pass)
      const find = view.find.bind(view)
      const rewrite = deferred()
      const listed = deferred()
      const seen = { rewrite: false, stale: false, heldW: null }
      let phase = 'idle'
      // Every hold in force, so the test waits them out before it checks.
      const holds = []

      // vaultRemove(V2) removed v2 and now mirrors the v1 removal: wait
      // until a reconcile has listed v1 alone and writes v2 from it.
      pass.remove = async (key) => {
        if (phase === 'deleting' && key === V1) {
          phase = 'rewrite'
          A.trace('s1.hold', {
            step: 'v1 removal until a reconcile rewrites v2'
          })
          holds.push(hold(rewrite.promise))
          await holds.at(-1)
        }
        return remove(key)
      }
      // That reconcile's write (W): held until C has taken its listing.
      pass.add = async (key, ...rest) => {
        if (phase === 'rewrite' && key === V2) {
          seen.rewrite = true
          phase = 'held'
          A.trace('s1.rewrite', { key, step: 'W writes v2 from v1, held' })
          rewrite.resolve()
          holds.push(hold(listed.promise))
          await holds.at(-1)
          seen.heldW = A.updates
          A.trace('s1.rewrite.release', { key })
          return add(key, ...rest)
        }
        return add(key, ...rest)
      }
      // C's listing, the first full one after the delete: read from the
      // view as it is now, and handed over only once W has finished.
      view.find = (name, query = {}, ...rest) => {
        const full = !query.gte && !query.lte && !query.gt && !query.lt
        if (phase !== 'stale' || !full) return find(name, query, ...rest)
        phase = 'done'
        seen.stale = true
        const snapshot = view.snapshot()
        A.trace('s1.stale', { step: 'C lists, handed over once W is done' })
        listed.resolve()
        const finished = waitFor(
          () => seen.heldW !== null && A.updates > seen.heldW,
          { timeout: HOLD_MS, interval: 5, label: 'W finished' }
        ).catch(() => {})
        holds.push(finished)
        return (async function* () {
          try {
            await finished
            A.trace('s1.stale.release')
            yield* snapshot.find(name, query, ...rest)
          } finally {
            await snapshot.close()
          }
        })()
      }

      // The app's delete, as sync-partition-500 does it.
      phase = 'deleting'
      await A.remove(V2)
      await A.remove(V1)
      phase = phase === 'held' ? 'stale' : phase

      // Every hold released, every reconcile done, then one more run on an
      // unrelated write: nothing left that would heal later.
      for (let n = -1; n !== holds.length; ) {
        n = holds.length
        await Promise.all(holds)
        await settle(A)
      }
      pass.add = add
      pass.remove = remove
      view.find = find
      const nudge = A.updates
      await A.add('note/nudge', { v: 1 })
      await waitFor(() => A.updates > nudge, { label: 'a later reconcile' })
      await settle(A)

      A.trace('s1.check', {
        v1: !!(await A.raw(V1)),
        v2: !!(await A.raw(V2))
      })
      // Without the interleaving there is nothing to show: no throw, so
      // test.failing goes red instead of passing on a race that never ran.
      if (!seen.rewrite || !seen.stale) return
      expect(await A.raw(V1)).toBeNull()
      expect(await A.raw(V2)).toBeNull()
      expect(await A.list('record/')).toEqual([])
    },
    60000
  )
})
