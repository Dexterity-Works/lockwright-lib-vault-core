import { createNetwork, waitFor } from './harness.js'

// Finding F4 (and F4's twin in the Layer 2 pairing runs). When an applied
// block changes the indexer set (a device pairs, is promoted, or is
// removed), Autobase reboots: _drain (autobase/index.js:1877) calls
// _reboot (:1661), which closes the old ApplyState in finalize
// (:1665, lib/apply-state.js:967); its _free closes the SystemView
// (lib/apply-state.js:713) while `base._applyState` still points at it.
// `base.system` (autobase/index.js:275) hands that closing SystemView out
// until the new ApplyState is ready, and then null.
// epochStore reads the system on every refresh: readRoster
// (src/worklet/epoch/epochStore.js:205) and status (:879) call
// `instance.base.system?.get(writerKey)`. Hyperbee.get makes a snapshot of
// the closing core and throws SESSION_CLOSED "Cannot make sessions on a
// closing core". add() refreshes first (settle, :455), so an
// activeVaultAdd that lands in the window fails (appDeps.js:1225 rewraps
// it with the same message). Status reads and the incremental reconcile
// hit the same window and swallow it.
// The window is a few ms (1 to 13 ms in the traced schedule runs). The test
// holds it open: on A's first reboot after B is added, the old SystemView's
// close is let through and its promise held until A's write settles, at
// most HOLD_MS. A store that waits out the reboot, or reads the system in
// a way the reboot cannot close under it, writes once the hold lets go,
// and the test passes. Kept failing until a write during a reboot lands.
// Timeline: the `test.reboot`, `test.write` and `test.written` events
// (LOCKWRIGHT_NET_KEEP=1 keeps it when the test passes as test.failing).
const HOLD_MS = 5000

/** Resolves on `promise` or after HOLD_MS, whichever comes first. */
const hold = (promise) => {
  let timer
  return Promise.race([
    promise,
    new Promise((resolve) => {
      timer = setTimeout(resolve, HOLD_MS)
    })
  ]).finally(() => clearTimeout(timer))
}

describe('a write while Autobase reboots on an indexer change (F4)', () => {
  let net = null

  afterEach(async () => {
    await net?.destroy()
    net = null
  })

  test.failing(
    'A writes while it reboots after B is added: the write lands',
    async () => {
      net = await createNetwork({ peers: ['A', 'B'], name: 'f4' })
      const { A, B } = net.peers
      await A.createVault({ id: 'shared' })

      const base = A.instance.base
      const reboot = base._reboot
      let write = null
      let window = null
      // A's first reboot from here on: let the old SystemView's close start,
      // then write as the app does while `base.system` is that SystemView.
      base._reboot = function (...args) {
        base._reboot = reboot
        const state = this._applyState
        const system = state?.system
        if (system) {
          const close = system.close.bind(system)
          system.close = (...rest) => {
            const closing = close(...rest)
            window = {
              closing: !!system.core?.closing,
              same: base.system === system
            }
            A.trace('test.reboot', window)
            A.trace('test.write', { key: 'note/f4' })
            write = A.add('note/f4', { by: 'A' }).then(
              () => null,
              (error) => error
            )
            return closing.then(() => hold(write))
          }
        }
        return reboot.apply(this, args)
      }

      // Setup: a precondition that fails is logged and the body returns
      // without throwing, so this test.failing fails ("passed even though
      // it was supposed to fail") instead of passing on the wrong error.
      try {
        await B.pair(await A.invite())
        // B is a pending indexer until A acks B's writes; ack once A holds
        // them rather than wait for Autobase's ack timer (~15 s here).
        await waitFor(async () => (await A.devices()).length === 2, {
          label: "A holds B's device row"
        })
        await A.instance.base.ack()
        await waitFor(() => write !== null, {
          timeout: 45000,
          label: 'A reboots after B is added'
        })
        expect(window).toEqual({ closing: true, same: true })
      } catch (error) {
        base._reboot = reboot
        // eslint-disable-next-line no-console
        console.error(`F4 setup did not hold: ${error.message}`)
        return
      }

      const outcome = await write
      A.trace('test.written', {
        error: outcome?.message ?? null
      })
      const events = net.events.filter((e) => e.peer === 'A')
      const at = (event) => events.findIndex((e) => e.event === event)
      expect(at('test.reboot')).toBeGreaterThan(-1)
      expect(at('test.write')).toBeGreaterThan(at('test.reboot'))
      expect(at('test.written')).toBeGreaterThan(at('test.write'))
      expect(outcome?.message ?? null).toBeNull()
      await waitFor(async () => (await B.get('note/f4')) !== null, {
        label: 'B reads note/f4'
      })
    },
    60000
  )
})
