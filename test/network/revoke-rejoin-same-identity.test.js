import {
  converge,
  createNetwork,
  holdsEpoch,
  holdsMembers,
  indexOf,
  pairOrCancel,
  revokedStatus,
  sealedFrom,
  settledEpoch,
  shareVault,
  statusPushed,
  waitFor
} from './harness.js'
import { short } from './tracer.js'

const AB = ['device-A', 'device-B']
const ABC = ['device-A', 'device-B', 'device-C']
const sameList = (a, b) => JSON.stringify(a) === JSON.stringify(b)

const members = async (peer) => (await peer.epochStatus()).members

const rows = async (peer) => (await peer.devices()).map((d) => d.id).sort()

// An epoch status C reported as readable for an epoch after the first.
const readableLater = (events, first) =>
  events.filter(
    (e) =>
      e.peer === 'C' &&
      e.event === 'epoch.status' &&
      e.epoch !== null &&
      e.epoch !== short(first.id) &&
      e.canRead
  )

/** How many blocks `peer` holds of the writer core `writerKey` (hex). */
const writerLength = async (peer, writerKey) => {
  const core = peer.instance.store.get({ key: Buffer.from(writerKey, 'hex') })
  await core.ready()
  const { length } = core
  await core.close()
  return length
}

// A kicked device comes back under the same masterTopic and device id.
describe('a kicked device returns under the same identity (ADR 0014)', () => {
  let net = null

  afterEach(async () => {
    await net?.destroy()
    net = null
  })

  const kickC = async () => {
    const { A, B, C } = net.peers
    const first = await A.ensureEpoch({ start: true })
    expect(first).toMatchObject({ rotated: true, members: ABC })
    for (const peer of [B, C]) await holdsEpoch(peer, first.id)
    await A.add('note/before', { text: 'everyone' })
    expect(await converge([A, B, C], 'note/before')).toMatchObject({
      text: 'everyone'
    })
    const kicked = await A.kick('device-C')
    expect(kicked).toMatchObject({ rotated: true, members: AB })
    // B may rotate for the same removal too; either way C is left out.
    const out = await holdsMembers(B, AB, { besides: first.id })
    await A.add('note/while-out', { text: 'without C' })
    expect(await converge([A, B], 'note/while-out')).toMatchObject({
      text: 'without C'
    })
    expect(
      await revokedStatus(
        C,
        (s) => s.epoch !== first.id && sameList(s.members, AB)
      )
    ).toMatchObject({ canRead: false })
    await sealedFrom(C, 'note/while-out', 'without C')
    // The push, too, before C acts on it.
    await statusPushed(net, C, (e) => e.revoked)
    return { first, out }
  }

  // ADR 0014: pairing is a roster change like any other ("kick, leave,
  // pairing ... share one rule") and "the box carries every earlier key, so
  // a new member reads history". A re-admitted C therefore reads what was
  // written while it was out: re-admission is the inviter's decision. C
  // pairs the way the app has it after a revoke: the vault's local copy is
  // wiped first, so only the device id and the masterTopic carry over.
  test('C paired again with a fresh invite is a member and reads on, history included', async () => {
    net = await createNetwork({ peers: ['A', 'B', 'C'] })
    const { A, B, C } = net.peers
    await shareVault(net)
    const { first, out } = await kickC()
    const writerBefore = C.writerKey
    const topicBefore = C.masterTopic

    await C.appDeps.removeVault(C.vaultId)
    await C.pair(await A.invite())
    expect(C.masterTopic).toBe(topicBefore)
    // A fresh store: a new local core, so a new writer key.
    expect(C.writerKey).not.toBe(writerBefore)

    // A, B and C may each rotate for C's row; the loser of a same-seq race
    // rotates once more to carry its key.
    const readmitted = await settledEpoch([A, B, C], ABC)
    expect(readmitted.epoch).not.toBe(out.epoch)
    expect(await rows(A)).toEqual(ABC)

    await A.add('note/after-rejoin', { text: 'with C again' })
    expect(await converge([A, B, C], 'note/after-rejoin')).toMatchObject({
      text: 'with C again'
    })
    // History handed over by the ring box (labelled, see above).
    expect(await C.get('note/while-out')).toMatchObject({ text: 'without C' })
    expect(await C.get('note/before')).toMatchObject({ text: 'everyone' })
    expect(await C.epochStatus()).toMatchObject({
      epoch: readmitted.epoch,
      canRead: true,
      revoked: false,
      uncovered: []
    })
    await C.add('note/from-c', { text: 'C is back' })
    expect(await converge([A, B, C], 'note/from-c')).toMatchObject({
      text: 'C is back'
    })

    // Trace: C was revoked before it paired again, then read the new epoch;
    // before the pairing it never read an epoch after the first.
    const { events } = net
    const revoked = indexOf(events, 'C', 'epoch.status', (e) => e.revoked)
    const joined = indexOf(events, 'C', 'peer.paired')
    const repaired = events.findLastIndex(
      (e) => e.peer === 'C' && e.event === 'peer.paired'
    )
    const back = indexOf(
      events,
      'C',
      'epoch.status',
      (e) => e.epoch === short(readmitted.epoch) && e.canRead
    )
    expect(revoked).toBeGreaterThan(joined)
    expect(repaired).toBeGreaterThan(revoked)
    expect(back).toBeGreaterThan(repaired)
    expect(readableLater(events.slice(0, repaired), first)).toEqual([])
  })

  // Finding R1. A kicked C that kept its local copy cannot pair again on
  // it. Autopass's joiner (AutopassPairer onadd) opens the vault on C's
  // existing store, where C's old writer core is the one A adds back. Then
  // either its deleteInvite appends while C's view still has C removed and
  // throws "Not writable" on the pairing connection, or the base is already
  // writable and _whenWritable returns without resolving. pair() hangs until
  // lib-vault's timeout, and the Autopass onadd built stays open. Kept as
  // failing until the pairing path handles a store it was a writer on.
  test.failing(
    'C that kept its copy pairs again on the same store',
    async () => {
      net = await createNetwork({ peers: ['A', 'B', 'C'] })
      const { A, C } = net.peers
      await shareVault(net)
      const { first } = await kickC()

      let result
      try {
        result = await pairOrCancel(C, await A.invite(), { timeout: 20000 })
      } finally {
        // The pairer's close leaves the Autopass its onadd built open when
        // the pairing did not resolve; it keeps the process alive at full
        // CPU. Part of the finding.
        const pairer = C.created.findLast((c) => c.label === 'pairer')
        await pairer?.instance.pass?.close()
      }
      expect(result).toMatchObject({ paired: true })
      await holdsMembers(A, ABC, { besides: first.id })
    }
  )

  // ADR 0014: "`removeWriter` stays". A kicked device that keeps the vault
  // key and the encryption key and reopens the vault under the same
  // identity stays revoked, reads nothing new and none of its writes reach
  // a member.
  test('a kicked C that keeps the keys and reopens the vault stays revoked and cannot write', async () => {
    net = await createNetwork({ peers: ['A', 'B', 'C'] })
    const { A, B, C } = net.peers
    await shareVault(net)
    const { first } = await kickC()

    await C.restartVault()
    // Straight after the reopen Autobase may report C writable until it
    // applies C's own removal again: try a raw append in that window.
    const early = await C.instance.add('note/from-c-early', 'plain').then(
      () => 'appended',
      (error) => error.message
    )
    expect(
      await revokedStatus(
        C,
        (s) => s.epoch !== first.id && sameList(s.members, AB)
      )
    ).toMatchObject({ canRead: false })
    await A.add('note/hostile-after', { text: 'members only' })
    expect(await converge([A, B], 'note/hostile-after')).toMatchObject({
      text: 'members only'
    })
    await sealedFrom(C, 'note/hostile-after', 'members only')
    expect(await C.get('note/while-out')).toBeNull()
    expect(await C.get('note/before')).toMatchObject({ text: 'everyone' })

    // Through the store: no key for the latest epoch, nothing is appended.
    await expect(C.add('note/from-c', { text: 'sneaky' })).rejects.toThrow(
      'Vault key not available yet'
    )
    await waitFor(() => C.instance.base.writable === false, {
      label: 'C is not writable'
    })
    // Past the store: Autobase refuses a removed writer.
    await expect(C.instance.add('note/from-c-raw', 'plain')).rejects.toThrow(
      'Not writable'
    )
    expect(await C.raw('note/from-c')).toBeNull()
    expect(await C.raw('note/from-c-raw')).toBeNull()

    // C cannot write a marker of its own, so the proof that nothing of C's
    // was held back is its writer core: once A and B hold every block C
    // appended, early append included, the view still has none of it.
    const length = C.instance.base.local.length
    for (const peer of [A, B]) {
      await waitFor(
        async () => (await writerLength(peer, C.writerKey)) >= length,
        { label: `${peer.id} holds all ${length} blocks of C's writer` }
      )
      expect(await peer.raw('note/from-c')).toBeNull()
      expect(await peer.raw('note/from-c-raw')).toBeNull()
      expect(await peer.raw('note/from-c-early')).toBeNull()
    }
    // eslint-disable-next-line no-console
    console.log(`C's raw append right after the reopen: ${early}`)
    expect(await rows(A)).toEqual(AB)
    expect(await members(A)).toEqual(AB)

    // Trace: nothing readable for C after the first epoch, and the restart
    // follows the revocation it learned before.
    const { events } = net
    const revoked = indexOf(events, 'C', 'epoch.status', (e) => e.revoked)
    const restart = indexOf(events, 'C', 'peer.restartVault')
    expect(revoked).toBeGreaterThan(-1)
    expect(restart).toBeGreaterThan(revoked)
    expect(readableLater(events, first)).toEqual([])
  })
})
