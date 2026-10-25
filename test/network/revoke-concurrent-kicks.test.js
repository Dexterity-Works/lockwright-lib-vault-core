import {
  converge,
  createNetwork,
  epochRows,
  holdsEpoch,
  noKeyAfter,
  revokedStatus,
  sealedFrom,
  settledUnaided,
  shareVault,
  waitFor
} from './harness.js'

const AB = ['device-A', 'device-B']
const ABCD = ['device-A', 'device-B', 'device-C', 'device-D']

const ids = async (peer) => new Set((await epochRows(peer)).map((r) => r.key))

// ADR 0014: "two concurrent rotations both exclude the removed device". Two
// kicks at once must settle on one epoch sealed to the two who stay.
describe('two devices kicked at the same time (ADR 0014)', () => {
  let net = null

  afterEach(async () => {
    await net?.destroy()
    net = null
  })

  test('A kicks C while B, offline, kicks D; one epoch for A and B, C and D read nothing newer', async () => {
    net = await createNetwork({ peers: ['A', 'B', 'C', 'D'] })
    const { A, B, C, D } = net.peers
    await shareVault(net)

    const first = await A.ensureEpoch({ start: true })
    expect(first).toMatchObject({ rotated: true, seq: 1, members: ABCD })
    for (const peer of [B, C, D]) await holdsEpoch(peer, first.id)
    await A.add('note/before', { text: 'everyone' })
    expect(await converge(net.list, 'note/before')).toMatchObject({
      text: 'everyone'
    })

    // The race, forced: B is cut off, so neither kicker sees the other's
    // kick before it rotates. B's removal and record land on its own core.
    await B.goOffline()
    const kickC = await A.kick('device-C')
    expect(kickC).toMatchObject({
      rotated: true,
      seq: 2,
      members: ['device-A', 'device-B', 'device-D']
    })
    const kickD = await B.kick('device-D')
    expect(kickD).toMatchObject({
      rotated: true,
      seq: 2,
      members: ['device-A', 'device-B', 'device-C']
    })
    // Every record B wrote apart, and every record A's side wrote before B
    // came back: written by a member whose roster did not yet show the
    // other kick (ADR 0014's honest limit). A's side may hold more than A's
    // kick: D sees C removed and may rotate for it too.
    const firstKey = `epoch/${first.id}`
    const apartB = await ids(B)
    apartB.delete(firstKey)
    expect([...apartB]).toEqual([`epoch/${kickD.id}`])
    await waitFor(async () => (await ids(D)).has(`epoch/${kickC.id}`), {
      label: "D holds A's kick record"
    })
    const apartA = await ids(A)
    apartA.delete(firstKey)
    await B.goOnline()

    // Both seq 2 records reach A, then the merge.
    const both = await waitFor(
      async () => {
        const two = (await epochRows(A)).filter(
          ({ key }) =>
            key === `epoch/${kickC.id}` || key === `epoch/${kickD.id}`
        )
        return two.length === 2 && two
      },
      { label: 'A holds both seq 2 records' }
    )
    expect(both.map(({ record }) => record.seq)).toEqual([2, 2])
    const settled = await settledUnaided(net, [A, B], AB)
    expect(settled.epoch).not.toBe(first.id)
    expect(settled.members).toEqual(AB)
    expect(settled.seq).toBeGreaterThanOrEqual(3)
    expect((await A.devices()).map((d) => d.id).sort()).toEqual(AB)
    expect((await B.devices()).map((d) => d.id).sort()).toEqual(AB)

    await A.add('note/after-a', { text: 'from A, members only' })
    await B.add('note/after-b', { text: 'from B, members only' })
    for (const key of ['note/after-a', 'note/after-b']) {
      expect(await converge([A, B], key)).toMatchObject({
        text: expect.stringContaining('members only')
      })
    }
    // A kicked device may hold a key of an epoch the other kicker wrote
    // before it saw this kick, and nothing else above the first: checked on
    // its own epoch rows, every one of them.
    const report = []
    for (const [peer, allowed] of [
      [C, apartB],
      [D, apartA]
    ]) {
      expect(
        await revokedStatus(peer, (s) => s.epoch === settled.epoch)
      ).toMatchObject({ canRead: false })
      await sealedFrom(peer, 'note/after-a', 'members only')
      await sealedFrom(peer, 'note/after-b', 'members only')
      expect(await peer.get('note/before')).toMatchObject({ text: 'everyone' })
      const seen = await noKeyAfter(peer, {
        lastHeldSeq: first.seq,
        allow: (record) => allowed.has(`epoch/${record.id}`)
      })
      report.push(`${peer.id}:${seen.allowed}/${seen.above}`)
    }
    // C reads B's kick record and nothing else B or A wrote.
    expect(report[0]).toMatch(/^C:1\//)

    // The first epoch, two at seq 2, and the merge; more records are D
    // rotating for C's removal, or the loser of a same-seq race rotating
    // again. Reported per run.
    const records = await epochRows(A)
    const bySeq = {}
    for (const { record } of records)
      bySeq[record.seq] = (bySeq[record.seq] ?? 0) + 1
    // eslint-disable-next-line no-console
    console.log(
      `epoch records: ${records.length} (by seq ${JSON.stringify(bySeq)}; ` +
        `A's side apart: ${apartA.size}; settled seq ${settled.seq}; ` +
        `listing the kicked device, allowed/above: ${report.join(' ')})`
    )
    expect(records.length).toBeGreaterThanOrEqual(4)
  })
})
