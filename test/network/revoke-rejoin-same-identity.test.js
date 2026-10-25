import { encode } from 'autopass/spec/hyperdispatch'

import {
  converge,
  createNetwork,
  holdsEpoch,
  holdsMembers,
  indexOf,
  noKeyAfter,
  pairOrCancel,
  revokedStatus,
  sameList,
  sealedFrom,
  settledUnaided,
  shareVault,
  statusPushed,
  waitFor
} from './harness.js'
import { short } from './tracer.js'

const AB = ['device-A', 'device-B']
const ABC = ['device-A', 'device-B', 'device-C']

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

/** How many blocks `peer` holds, from the start, of the writer core `writerKey` (hex). */
const writerLength = async (peer, writerKey) => {
  const core = peer.instance.store.get({ key: Buffer.from(writerKey, 'hex') })
  await core.ready()
  const length = core.contiguousLength
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
    const readmitted = await settledUnaided(net, [A, B, C], ABC)
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

  // Finding R1, a vault-core API hazard that lib-vault does not reach: on
  // vault-access-revoked the app wipes the vault (removeVault), and
  // lib-vault's pairActiveVault refuses while the vault's catalog row
  // exists. pearpassPairer.pairInstance opens vault/<id> without checking
  // that it is empty, so a caller that pairs on a kicked device's old store
  // gets Autopass's joiner (AutopassPairer onadd) on C's existing store,
  // where C's old writer core is the one A adds back. Either its
  // deleteInvite appends while C's view still has C removed and throws "Not
  // writable" on the pairing connection, or the base is already writable
  // and _whenWritable returns without resolving. Either way pair() never
  // resolves; the timeout's cancel rejects it. This pins that outcome.
  test('R1: C that kept its copy cannot pair again on the same store', async () => {
    net = await createNetwork({ peers: ['A', 'B', 'C'] })
    const { A, B, C } = net.peers
    await shareVault(net)
    await kickC()

    let result
    try {
      result = await pairOrCancel(C, await A.invite(), { timeout: 20000 })
    } finally {
      // The pairer's close leaves the Autopass its onadd built open (R2);
      // it keeps the process alive at full CPU.
      const pairer = C.created.findLast((c) => c.label === 'pairer')
      await pairer?.instance.pass?.close()
    }
    expect(result).toMatchObject({ paired: false })
    expect(result.error.message).toMatch(/^Pairing failed: .*Pairing closed$/)
    expect(
      net.tracers.C.events.some((e) => e.event === 'peer.pairTimeout')
    ).toBe(true)
    expect(await rows(A)).toEqual(AB)
    expect(await members(B)).toEqual(AB)
  })

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
    await C.instance.base.update()
    // Autobase keeps the applied view on disk, so the reopened base starts
    // with C's own removal applied: no window in which a plain append goes
    // through (10 of 10 runs). Asserted, not assumed.
    await expect(C.instance.add('note/from-c-early', 'plain')).rejects.toThrow(
      'Not writable'
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
    await noKeyAfter(C, { lastHeldSeq: first.seq })

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
    // Past the writable check: Autobase takes an optimistic append from a
    // non-writer and applies it only if apply acks the writer, which
    // Autopass never does. The block does land on C's writer core, so the
    // proof below is about a block A and B really hold.
    const length = C.instance.base.local.length
    await C.instance.base.append(
      encode('@autopass/put', {
        key: 'note/from-c-optimistic',
        value: 'plain'
      }),
      { optimistic: true }
    )
    expect(C.instance.base.local.length).toBe(length + 1)
    await C.instance.base.update()
    for (const key of ['note/from-c', 'note/from-c-raw', 'note/from-c-early']) {
      expect(await C.raw(key)).toBeNull()
    }

    // Once A and B hold every block of C's writer, the optimistic one
    // included, their views still have none of it.
    for (const peer of [A, B]) {
      await waitFor(
        async () => (await writerLength(peer, C.writerKey)) >= length + 1,
        { label: `${peer.id} holds all ${length + 1} blocks of C's writer` }
      )
      await peer.instance.base.update()
      for (const key of [
        'note/from-c',
        'note/from-c-raw',
        'note/from-c-early',
        'note/from-c-optimistic'
      ]) {
        expect(await peer.raw(key)).toBeNull()
      }
    }
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
