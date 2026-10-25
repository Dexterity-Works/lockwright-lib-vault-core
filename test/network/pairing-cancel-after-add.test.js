import guard from './guard.cjs'
import { createNetwork } from './harness.js'

// Finding R2. Autopass's AutopassPairer onadd (autopass/index.js:59-80)
// builds the joined Autopass on the pairer's swarm and store, then sets the
// pairer's own `swarm` and `store` to null. Its _close (:105-126) then has
// nothing to destroy, and its fallback closes `this.base`, which the pairer
// never sets, instead of `this.pass`. So a pairing cancelled or timed out
// after onadd and before finished() resolves (a lib-vault timeout, or the
// user cancelling while the joiner waits to become writable) rejects with
// "Pairing closed" and leaves the Autopass and its Hyperswarm running.
// pearpassPairer.cancelPairing then closes the corestore under that live
// Autopass: its Autobase rejects with SESSION_CLOSED and the swarm's
// connection handler (autopass/index.js:47-49) throws "Corestore is closed"
// uncaught on the next connection. Kept failing until the cancel closes
// what onadd built.
describe('pairing cancelled after the candidate was added (R2)', () => {
  let net = null
  let pairer = null

  // The leaked Autopass and its swarm, closed before the corestore under
  // them, so the uncaught errors above do not fail the run on top.
  const closeLeak = async (instance) => {
    await instance?.pass?.swarm?.destroy().catch(() => {})
    await instance?.pass?.close().catch(() => {})
  }

  afterEach(async () => {
    await closeLeak(pairer)
    pairer = null
    await net?.destroy()
    net = null
  })

  test.failing(
    'B cancels right after onadd on a fresh store: no swarm or Autopass is left open',
    async () => {
      let added
      const onadd = new Promise((resolve) => {
        added = resolve
      })
      // What is still open when the cancel's last step, the corestore
      // close, begins: by then a cancel that cleans up has closed it all.
      let leak = null
      let before = null
      net = await createNetwork({
        peers: ['A', 'B'],
        onCreate: (label, instance, peer) => {
          if (label !== 'pairer' || peer.id !== 'B') return
          // The candidate exists once ready() resolves, before any reply
          // from A; candidate calls `this.onadd` when the reply comes.
          instance
            .ready()
            .then(() => {
              const { store } = instance
              const closeStore = store.close.bind(store)
              // Autobase closes the corestore it was given, so the leaked
              // Autopass's own close comes back here: that one goes through.
              let closing = false
              store.close = async () => {
                if (closing) return closeStore()
                closing = true
                leak = {
                  open: [
                    ...peer.created
                      .filter(
                        (c) => c.label === 'autopass' && !c.instance.closed
                      )
                      .map(() => 'autopass'),
                    ...(instance.pass && !instance.pass.closed
                      ? ['pairer.pass']
                      : [])
                  ],
                  swarmDestroyed: instance.pass?.swarm?.destroyed ?? null,
                  sockets: guard.liveSockets().length,
                  before
                }
                peer.trace('test.leak', leak)
                await closeLeak(instance)
                return closeStore()
              }
              const original = instance.candidate.onadd
              instance.candidate.onadd = async (result) => {
                await original(result)
                peer.trace('test.onadd', { pass: instance.pass !== null })
                added(instance)
              }
            })
            .catch(() => {})
        }
      })
      const { A, B } = net.peers

      // Setup: a precondition that fails is logged and the body returns
      // without throwing, so this test.failing fails ("passed even though it
      // was supposed to fail") instead of passing on the wrong error.
      try {
        await A.createVault({ id: 'shared' })
        const invite = await A.invite()
        before = guard.liveSockets().length
        const pairing = B.pair(invite).then(
          () => 'paired',
          (error) => error
        )
        pairer = await Promise.race([onadd, pairing.then(() => null)])
        if (!pairer) throw new Error('pair() settled before onadd')
        expect(pairer.pass).not.toBeNull()
        B.trace('test.cancel')
        await B.appDeps.cancelPairActiveVault()
        const outcome = await pairing
        expect(outcome).toBeInstanceOf(Error)
        expect(outcome.message).toMatch(/Pairing closed$/)
        expect(pairer.closed).toBe(true)
        expect(leak).not.toBeNull()
      } catch (error) {
        // eslint-disable-next-line no-console
        console.error(`R2 setup did not hold: ${error.message}`)
        return
      }

      // Only the master vault stays open, and the sockets are the pre-pair
      // ones.
      expect(leak).toEqual({
        open: ['autopass'],
        swarmDestroyed: leak.swarmDestroyed === null ? null : true,
        sockets: before,
        before
      })
    }
  )
})
