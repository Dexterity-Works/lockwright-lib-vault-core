import crypto from 'crypto'

import {
  converge,
  createNetwork,
  holdsEpoch,
  shareVault,
  waitFor
} from './harness.js'
import { short } from './tracer.js'

// A deterministic file per key, so the bytes C reads can be rebuilt.
const fileFor = (key) => {
  const seed = crypto.createHash('sha256').update(key).digest()
  return Buffer.concat(Array.from({ length: 256 }, () => seed))
}

describe('a member offline across epoch rotations (ADR 0014)', () => {
  let net = null

  afterEach(async () => {
    await net?.destroy()
    net = null
  })

  // C misses three rotations (A kicks D, E and B) and must come back
  // reading every record sealed under every epoch it missed: the latest
  // epoch's box for C carries every earlier key.
  test('C misses three rotations and catches up on return', async () => {
    net = await createNetwork({ peers: ['A', 'B', 'C', 'D', 'E'] })
    const { A, C } = net.peers
    await shareVault(net)

    // A seals only to rows it can bind (signed, writer added); the last
    // joiner's row can land before its writer does.
    await waitFor(async () => (await A.epochStatus()).uncovered.length === 0, {
      label: 'A can seal to every device row'
    })
    const first = await A.ensureEpoch({ start: true })
    expect(first).toMatchObject({
      rotated: true,
      members: ['device-A', 'device-B', 'device-C', 'device-D', 'device-E']
    })
    for (const peer of net.list) await holdsEpoch(peer, first.id)

    await A.add('note/e0', { epoch: first.id, n: 0 })
    expect(await converge(net.list, 'note/e0')).toMatchObject({ n: 0 })

    await C.goOffline()
    expect(C.instance.swarm.suspended).toBe(true)

    // Every online member rotates on a roster change (appDeps syncEpoch runs
    // ensureEpoch on each update), so the kick's own result is advisory: A
    // and B can race to seal the same seq and reconcile with one more
    // epoch. What counts is that the online members settle on one epoch
    // without the kicked device before the next kick and the next write.
    const epochs = [first.id]
    const written = []
    let members = ['device-A', 'device-B', 'device-C', 'device-D', 'device-E']
    for (const [n, kicked] of ['device-D', 'device-E', 'device-B'].entries()) {
      members = members.filter((id) => id !== kicked)
      const online = members
        .filter((id) => id !== 'device-C')
        .map((id) => net.peers[id.slice('device-'.length)])
      const previous = (await A.epochStatus()).epoch
      await A.kick(kicked)
      const settled = await waitFor(
        async () => {
          const statuses = await Promise.all(online.map((p) => p.epochStatus()))
          const [lead] = statuses
          return lead.epoch !== previous &&
            lead.canRead &&
            JSON.stringify(lead.members) === JSON.stringify(members) &&
            statuses.every((s) => s.epoch === lead.epoch && s.canRead)
            ? lead
            : false
        },
        { label: `members settle on an epoch without ${kicked}` }
      )
      epochs.push(settled.epoch)
      const key = `note/e${n + 1}`
      const value = { epoch: settled.epoch, n: n + 1 }
      await A.add(key, value, fileFor(key), `${key}.bin`)
      written.push({ key, value })
    }
    expect(new Set(epochs).size).toBe(4)
    // A is the last writer standing, so once its ensureEpoch owes nothing
    // the chain is settled: a record B sealed before its kick that reaches
    // A late makes A rotate one more time (holdsMoreThan).
    const latest = await waitFor(
      async () => {
        const owed = await A.ensureEpoch()
        const status = await A.epochStatus()
        return !owed.rotated && status.canRead ? status.epoch : false
      },
      { label: 'A owes no rotation' }
    )
    const before = await A.epochStatus()
    expect(before).toMatchObject({
      epoch: latest,
      canRead: true,
      members: ['device-A', 'device-C']
    })
    // Every epoch record A wrote or received while C was away; at least
    // the three kicks' worth, more when a same-seq race added one.
    const missed = (await A.list('epoch/')).filter((e) => e.id !== first.id)
    expect(missed.length).toBeGreaterThanOrEqual(3)
    expect(missed.map((e) => e.id)).toContain(latest)
    // C has not heard of any of it.
    expect((await C.epochStatus()).epoch).toBe(first.id)

    await C.goOnline()
    expect(C.instance.swarm.suspended).toBe(false)
    // C replays the kicks on return, and its update reconcile can rotate
    // for a removal it sees before the epoch that answered it, as any
    // member that saw the removal may (5bd7788). So C reaches latest or one
    // more epoch above it, sealed to A and C, and A agrees on it.
    const settled = () =>
      waitFor(
        async () => {
          const [a, c] = await Promise.all([A.epochStatus(), C.epochStatus()])
          return a.canRead &&
            c.canRead &&
            a.epoch === c.epoch &&
            c.seq >= before.seq &&
            JSON.stringify(c.members) ===
              JSON.stringify(['device-A', 'device-C'])
            ? c
            : false
        },
        { label: 'A and C settle on an epoch sealed to A and C' }
      )
    await settled()
    for (const { key, value } of written) {
      // activeVaultGet hangs the file off the value; bytes are checked below.
      expect(
        await waitFor(() => C.get(key), { label: `C reads ${key}` })
      ).toMatchObject(value)
      const bytes = await waitFor(() => C.getFile(key), {
        label: `C has the file of ${key}`
      })
      expect(Buffer.from(bytes).equals(fileFor(key))).toBe(true)
    }
    await C.add('note/from-c', { epoch: latest })
    expect(
      await waitFor(() => A.get('note/from-c'), { label: 'A reads from C' })
    ).toEqual({ epoch: latest })

    // Trace: offline before online; after online the statuses end at the
    // epoch C and A settled on; canRead never dropped once C was a member.
    const events = net.tracers.C.events
    const offline = events.findIndex((e) => e.event === 'peer.offline')
    const online = events.findIndex((e) => e.event === 'peer.online')
    expect(offline).toBeGreaterThan(-1)
    expect(online).toBeGreaterThan(offline)
    // The status is pushed from the debounced update reconcile, so it can
    // trail the reads above.
    const pushed = await waitFor(
      async () => {
        const final = await settled()
        const after = events
          .slice(online)
          .filter((e) => e.event === 'epoch.status')
        return after.length && after.at(-1).epoch === short(final.epoch)
          ? after
          : false
      },
      { label: "C's trace ends at the settled epoch" }
    )
    expect(pushed.at(-1)).toMatchObject({
      canRead: true,
      members: ['device-A', 'device-C']
    })
    const statuses = events.filter((e) => e.event === 'epoch.status')
    const member = statuses.findIndex((e) => e.canRead && e.epoch)
    expect(member).toBeGreaterThan(-1)
    expect(statuses.slice(member).filter((e) => !e.canRead)).toEqual([])
    // Resets on the connections the suspend cut are the only errors.
    expect(
      events
        .filter(
          (e) =>
            e.event === 'error' &&
            !(e.where === 'conn' && e.code === 'ECONNRESET')
        )
        .map((e) => `${e.where} ${e.code}: ${e.message}`)
    ).toEqual([])
  }, 180000)
})
