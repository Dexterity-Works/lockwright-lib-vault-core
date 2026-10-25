import { converge, createNetwork, shareVault, waitFor } from './harness.js'
import { isEnvelope } from '../../src/worklet/epoch/keyring.js'

// Local core userData the epoch store keeps an owed start under
// (src/worklet/epoch/epochStore.js START_OWED).
const START_OWED = 'lockwright/epoch-start-owed'

/** Like allSettled for one promise, with a third outcome: it never settled. */
const settle = (promise, ms) => {
  let timer
  return Promise.race([
    promise.then(
      (value) => ({ status: 'fulfilled', value }),
      (reason) => ({ status: 'rejected', reason })
    ),
    new Promise((resolve) => {
      timer = setTimeout(() => resolve({ status: 'timeout' }), ms)
    })
  ]).finally(() => clearTimeout(timer))
}

const at = (tracer, event, pick = (e) => e) =>
  tracer.events.filter((e) => e.event === event).map(pick)

const quiet = (promise) => promise.catch(() => null)

describe('lock during the first kick (lifecycle)', () => {
  let net = null

  afterEach(async () => {
    await net?.destroy()
    net = null
  })

  // A, B and C share a legacy vault (no epoch yet). A kicks C, which is
  // the first rotation, and locks (closeAllInstances, as lockAppSession
  // does) while the kick is in flight: by default on the kick's first write
  // (the removeWriter append), with LOCKWRIGHT_LOCK_AT=start as soon as the
  // kick is issued. Expected: either the kick finished before the close
  // (kick-first); or the close interrupted it before any write landed, so
  // the kick failed whole and a retry does it (interrupted-clean); or the
  // close interrupted it after a write and the start it owed was persisted
  // (START_OWED), so ensureEpoch() after unlock finishes the rotation
  // (interrupted-owed). Either way A and B end on one epoch with members A
  // and B, C is no longer a writer and cannot read the epoch, and nothing A
  // writes afterwards is plaintext. C never held a key (the first epoch
  // excludes it), so its status is not `revoked` (epochStore status(): a
  // device that held no ring is waiting, ADR 0014).
  //
  // Finding L1 (PROGRESS-network-scenarios): a lock between the kick's
  // roster writes and its ensureEpoch({ start: true }) left the vault
  // legacy, so A's next record was plaintext and the kicked C read it.
  // vaultRemoveWriter now owes the start before the removal lands
  // (epochStore oweStart), so unlock's ensureEpoch finishes the rotation.
  test('A locks while its kick of C is in flight; the rotation still lands', async () => {
    const lockAt = process.env.LOCKWRIGHT_LOCK_AT ?? 'append'
    let armed = false
    let lock = null
    const A_ = () => net.peers.A
    net = await createNetwork({
      peers: ['A', 'B', 'C'],
      onEvent: (line) => {
        if (!armed || line.peer !== 'A' || line.event !== 'autobase.append') {
          return
        }
        armed = false
        // Off the append's own call stack, like an RPC arriving next tick.
        lock = new Promise((resolve) =>
          setImmediate(() => resolve(A_().lock()))
        )
      }
    })
    const { A, B, C } = net.peers
    await shareVault(net)
    for (const peer of net.list) {
      expect(await peer.epochStatus()).toMatchObject({ legacy: true })
    }

    // The race.
    armed = lockAt === 'append'
    const kick = A.kick('device-C')
    if (lockAt === 'start') lock = A.lock()
    const kicked = await settle(kick, 20000)
    armed = false
    if (!lock) {
      // The kick ended before its first write: lock now, as kick-first.
      lock = A.lock()
    }
    const locked = await settle(lock, 20000)
    // lockAppSession gives closeAllInstances 5 s before it moves on.
    expect(locked).toMatchObject({ status: 'fulfilled' })
    expect(locked.value).toBeLessThan(5000)

    await A.unlock()
    const owedOnDisk =
      (await A.instance.base.local.getUserData(START_OWED))?.toString() ?? null
    const ensured = await A.ensureEpoch()
    // An update's epoch sync can run the owed start before this call does.
    const afterEnsure = await A.epochStatus()
    const tracer = net.tracers.A
    const [tKick] = at(tracer, 'peer.kick', (e) => e.t)
    const [tLocked] = at(tracer, 'peer.locked', (e) => e.t)
    const appendsDuringKick = at(tracer, 'autobase.append').filter(
      (e) => e.label === 'vault' && e.t > tKick && e.t < tLocked
    ).length

    let outcome
    if (kicked.status === 'fulfilled' && kicked.value.rotated) {
      outcome = 'kick-first'
      expect(kicked.value).toMatchObject({
        members: ['device-A', 'device-B']
      })
    } else if (kicked.status === 'timeout') {
      outcome = 'kick-hung'
    } else if (appendsDuringKick === 0) {
      outcome = 'interrupted-clean'
    } else if (ensured.rotated || !afterEnsure.legacy) {
      outcome = 'interrupted-owed'
    } else {
      outcome = 'interrupted-lost'
    }
    const devices = (await A.devices()).map((d) => d.id).sort()
    A.trace('race.outcome', {
      outcome,
      lockAt,
      appendsDuringKick,
      owedOnDisk,
      kick: kicked.status,
      kickError: kicked.reason?.message ?? null,
      kickResult: kicked.value ?? null,
      ensured,
      legacyAfterEnsure: afterEnsure.legacy,
      lockMs: locked.value,
      devices
    })
    // eslint-disable-next-line no-console
    console.log(
      `race: ${outcome} (lock at ${lockAt}; kick ${kicked.status}${kicked.reason ? `: ${kicked.reason.message}` : ''}; ${appendsDuringKick} append(s) before the close; owed on disk ${owedOnDisk}; devices ${devices.join(',')}; lock ${locked.value} ms)`
    )
    if (outcome === 'interrupted-clean') {
      // No roster write landed: the kick failed whole and is done again.
      // An owed start may have rotated on unlock with C still a member.
      expect(await A.kick('device-C')).toMatchObject({
        rotated: true,
        members: ['device-A', 'device-B']
      })
    }

    // Nothing written after the kick is plaintext.
    await A.add('note/after', { text: 'members only' })
    const stored = await A.raw('note/after')
    if (!isEnvelope(stored.value)) {
      // The consequence, for the timeline: does the kicked device read it?
      const cReads = await quiet(
        waitFor(() => C.get('note/after'), { timeout: 10000 })
      )
      A.trace('race.plaintext', {
        key: 'note/after',
        cReads: cReads?.text ?? null,
        cWritable: C.instance.base.writable,
        cDevices: (await C.devices()).map((d) => d.id).sort()
      })
    }
    expect(isEnvelope(stored.value)).toBe(true)
    expect(stored.value).not.toContain('members only')
    expect(['kick-first', 'interrupted-clean', 'interrupted-owed']).toContain(
      outcome
    )

    // End state: one epoch, members A and B, on A and B.
    const final = await waitFor(
      async () => {
        const s = await A.epochStatus()
        return !s.legacy && s.canRead && s.members?.length === 2 ? s : false
      },
      { label: 'A holds the rotated epoch' }
    )
    expect(final.members).toEqual(['device-A', 'device-B'])
    await waitFor(
      async () => {
        const s = await B.epochStatus()
        return s.epoch === final.epoch && s.canRead
      },
      { label: `B holds epoch ${final.epoch}` }
    )
    const epochRows = await A.list('epoch/')
    A.trace('race.epochs', { n: epochRows.length })
    expect(epochRows.length).toBeGreaterThanOrEqual(1)
    // A close between the removeWriter and the row removal leaves C's row
    // behind its removed writer: the epoch store does not count it (the
    // members above), and a retried kick drops it.
    const rows = (await A.devices()).map((d) => d.id).sort()
    A.trace('race.rows', { rows })
    expect(rows.filter((id) => id !== 'device-C')).toEqual([
      'device-A',
      'device-B'
    ])

    // C: no longer a writer, locked out of the epoch once it syncs.
    await waitFor(() => C.instance.base.writable === false, {
      label: 'C is no longer a writer'
    })
    const cStatus = await waitFor(
      async () => {
        const s = await C.epochStatus()
        return s.epoch === final.epoch ? s : false
      },
      { label: `C sees epoch ${final.epoch}` }
    )
    C.trace('race.cStatus', { revoked: cStatus.revoked })
    expect(cStatus).toMatchObject({
      canRead: false,
      members: ['device-A', 'device-B']
    })
    expect(await converge([A, B], 'note/after')).toMatchObject({
      text: 'members only'
    })
    await waitFor(() => C.raw('note/after'), {
      label: 'C holds the sealed row'
    })
    expect(await C.get('note/after')).toBeNull()

    // Trace order on A: kick < lock < unlock < the status with the members.
    const [tLock] = at(tracer, 'peer.lock', (e) => e.t)
    const [tUnlock] = at(tracer, 'peer.unlock', (e) => e.t)
    // The status is pushed from the next update, which may come later.
    const pushed = await waitFor(
      () =>
        at(tracer, 'epoch.status').findLast(
          (e) =>
            e.t > tUnlock &&
            final.epoch.startsWith(e.epoch) &&
            JSON.stringify(e.members) === '["device-A","device-B"]'
        ),
      { timeout: 10000, label: 'A pushes the status with members A, B' }
    )
    expect(tKick).toBeLessThan(tLock)
    expect(tLock).toBeLessThan(tUnlock)
    expect(pushed.t).toBeGreaterThan(tUnlock)
    // The lock traced its own close: it never outlived the budget.
    const [lockedEvent] = at(tracer, 'peer.locked')
    expect(lockedEvent.ms).toBeLessThan(5000)
  })
})
