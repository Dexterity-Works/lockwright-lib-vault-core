import fs from 'fs'

import { generate, minimise, peersOf, runSchedule } from './schedule.js'

// Property run: random fault schedules over one shared vault (schedule.js
// has the step format and the invariants). Each seed gets a fresh network;
// a failure names the invariant and keeps the timeline and the schedule
// under test-artifacts/schedule/.
//
// Opt-in: LOCKWRIGHT_SCHEDULE=1, or any LOCKWRIGHT_SCHEDULE_* below. A
// failing schedule can leave its network open, so jest may not exit, and the
// default seeds hit F2 and F4 now and then (schedule.js header).
//
// Env:
//   LOCKWRIGHT_SCHEDULE_SEEDS=<n>      n seeds from LOCKWRIGHT_SCHEDULE_SEED_BASE
//                                      (default: a random base, logged);
//                                      unset: the fixed seeds 1, 2, 3, 4
//                                      (a kick after an epoch, still out at
//                                      the end) and 102 (two kicks, the
//                                      second still out at the end)
//   LOCKWRIGHT_SCHEDULE_STEPS=<n>      steps per schedule (default 15)
//   LOCKWRIGHT_SCHEDULE_SEED=<seed>    replay one seed
//   LOCKWRIGHT_SCHEDULE_FILE=<json>    replay a saved schedule (a step list,
//                                      or { peers, steps, flush, settle,
//                                      known } as the runner and the
//                                      minimiser write them; the saved modes
//                                      win over the env)
//   LOCKWRIGHT_SCHEDULE_PEERS=A,B,C,D  peers (default A,B,C)
//   LOCKWRIGHT_SCHEDULE_KNOWN=1,R1,L1  also generate ops for known findings;
//                                      F1 resumes without the discovery wait,
//                                      F3 closes without the writable wait
//   LOCKWRIGHT_SCHEDULE_MINIMISE=1     shrink a failing schedule (ddmin)
//   LOCKWRIGHT_SCHEDULE_MAX_RUNS=<n>   minimiser run budget (default 80)
//   LOCKWRIGHT_SCHEDULE_MAX_MINUTES=<n> minimiser time budget (default 30)
//   LOCKWRIGHT_SCHEDULE_FAKE=kick      fail any schedule that kicked (to
//                                      prove the minimiser)
//   LOCKWRIGHT_FINDINGS=1              also run the F1 and F3 replays
//                                      (test.failing; add --forceExit)
const env = process.env
const OPT_IN =
  env.LOCKWRIGHT_SCHEDULE === '1' ||
  Object.keys(env).some((name) => name.startsWith('LOCKWRIGHT_SCHEDULE_'))
const list = (value) => (value ? value.split(',').filter(Boolean) : [])
const STEPS = Number(env.LOCKWRIGHT_SCHEDULE_STEPS || 15)
const KNOWN = list(env.LOCKWRIGHT_SCHEDULE_KNOWN)
const FLUSH = !KNOWN.includes('F1')
const SETTLE = !KNOWN.includes('F3')
const MINIMISE = env.LOCKWRIGHT_SCHEDULE_MINIMISE === '1'
const MAX_RUNS = Number(env.LOCKWRIGHT_SCHEDULE_MAX_RUNS || 80)
const MAX_MINUTES = Number(env.LOCKWRIGHT_SCHEDULE_MAX_MINUTES || 30)
const BASE = Number(env.LOCKWRIGHT_SCHEDULE_SEED_BASE || Date.now() % 1e6)

const say = (...args) => {
  // eslint-disable-next-line no-console
  console.log(...args)
}

const cases = () => {
  if (env.LOCKWRIGHT_SCHEDULE_FILE) {
    const saved = JSON.parse(fs.readFileSync(env.LOCKWRIGHT_SCHEDULE_FILE))
    const steps = Array.isArray(saved) ? saved : saved.steps
    return [
      {
        name: `file ${env.LOCKWRIGHT_SCHEDULE_FILE} (${saved.stepCount ?? steps.length} steps)`,
        seed: saved.seed ?? null,
        peers: saved.peers ?? peersOf(steps),
        flush: saved.flush ?? FLUSH,
        settle: saved.settle ?? SETTLE,
        known: saved.known ?? KNOWN,
        steps
      }
    ]
  }
  const peers = list(env.LOCKWRIGHT_SCHEDULE_PEERS)
  const seeds = env.LOCKWRIGHT_SCHEDULE_SEED
    ? [Number(env.LOCKWRIGHT_SCHEDULE_SEED)]
    : env.LOCKWRIGHT_SCHEDULE_SEEDS
      ? Array.from(
          { length: Number(env.LOCKWRIGHT_SCHEDULE_SEEDS) },
          (_, i) => BASE + i
        )
      : [1, 2, 3, 4, 102]
  return seeds.map((seed) => {
    const options = { steps: STEPS, known: KNOWN }
    if (peers.length) options.peers = peers
    const steps = generate(seed, options)
    return {
      name: `seed ${seed} × ${STEPS} steps`,
      seed,
      peers: options.peers ?? peersOf(steps),
      flush: FLUSH,
      settle: SETTLE,
      known: KNOWN,
      steps
    }
  })
}

const timeout = (MINIMISE ? MAX_MINUTES + 5 : 4) * 60000

const schedules = OPT_IN ? test : test.skip

// Replays of findings: opt-in, they fail by design and F3 leaks its network.
const findings = env.LOCKWRIGHT_FINDINGS === '1' ? test.failing : test.skip

describe('random fault schedules', () => {
  schedules.each(cases())(
    '$name',
    async ({ seed, peers, flush, settle, known, steps }) => {
      say(`schedule seed ${seed}, ${steps.length} steps, peers ${peers}`)
      const result = await runSchedule(steps, {
        seed,
        peers,
        flush,
        settle,
        known
      })
      if (result.ok) return
      const { invariant, message, teardown } = result.failure
      say(
        `schedule seed ${seed} failed ${invariant}: ${message}${teardown ? `\n${teardown}` : ''}\nschedule: ${result.schedule}\ntimeline: ${result.timeline}`
      )
      let minimal = null
      if (MINIMISE) {
        minimal = await minimise(result.steps, {
          failure: result.failure,
          seed,
          peers,
          maxRuns: MAX_RUNS,
          maxMinutes: MAX_MINUTES,
          flush,
          settle,
          known
        })
      }
      throw new Error(
        `seed ${seed}: ${invariant}: ${message}${teardown ? `; ${teardown}` : ''} (schedule ${result.schedule}${minimal ? `, minimal ${minimal.file}` : ''})`
      )
    },
    timeout
  )

  // Finding F1, minimised from seed 1003 × 25 (41 runs). Every peer is
  // offline at once, B writes, then all three resume within a few ms, as
  // the app resumes (swarm.resume, no wait): no connection opens, and B's
  // write never reaches A or C. Seen 4/4 here and 1/1 in a bare
  // suspend/resume probe (none in 40 s). With swarm.flush() after each
  // resume they connect in ~30 ms; a later discovery refresh() does not
  // bring them back. The cause inside hyperswarm/hyperdht resume is not
  // pinned down. Kept failing until peers that resume together reconnect.
  // Opt-in (LOCKWRIGHT_FINDINGS=1): under heavy host load the peers
  // sometimes do reconnect (1 run in ~20 at load 69).
  findings(
    'F1: three peers that resume together reconnect (seed 1003, minimised)',
    async () => {
      const result = await runSchedule(
        [
          { op: 'offline', peer: 'C' },
          { op: 'offline', peer: 'A' },
          {
            op: 'write',
            peer: 'B',
            key: 'note/6',
            value: { k: 'note/6', n: 21, by: 'B' }
          },
          { op: 'offline', peer: 'B' }
        ],
        { seed: 1003, label: 'F1-replay', flush: false, checkTimeout: 20000 }
      )
      expect(result.failure).toBeNull()
    },
    120000
  )

  // Finding F3, from seed 1007 × 25 (hung 3 of 4 replays), cut by hand to
  // these 6 steps: ddmin could not run it, since a stuck vault never
  // finishes closing. A writes, starts the first epoch; C locks while its
  // Autobase is not writable for a moment (applying A's rotation, length
  // 31, indexedLength 18); after the unlock C stays not writable, its
  // length never moves although it is connected and B counts it as an
  // indexer, and C's write never resolves (Autopass add waits in
  // base.append). 9 of 9 rounds that caught C not writable at the lock
  // hung, 0 of 7 that caught it writable (one 16-round probe). Opt-in, with
  // LOCKWRIGHT_FINDINGS=1: the stuck vault leaks its network, so run it
  // with --forceExit. Rounds that miss the window pass, so it tries 5.
  findings(
    'F3: a device locked while applying the first rotation writes again after the unlock',
    async () => {
      const steps = [
        {
          op: 'write',
          peer: 'A',
          key: 'note/4',
          value: { k: 'note/4', n: 0, by: 'A' },
          fileBytes: 65536
        },
        {
          op: 'write',
          peer: 'A',
          key: 'note/6',
          value: { k: 'note/6', n: 1, by: 'A' }
        },
        { op: 'epoch', peer: 'A' },
        { op: 'lock', peer: 'C' },
        { op: 'unlock', peer: 'C' },
        {
          op: 'write',
          peer: 'C',
          key: 'note/7',
          value: { k: 'note/7', n: 5, by: 'C' }
        }
      ]
      for (let round = 1; round <= 5; round++) {
        const result = await runSchedule(steps, {
          seed: 1007,
          label: `F3-replay-${round}`,
          settle: false
        })
        expect(result.failure).toBeNull()
      }
    },
    15 * 60000
  )
})
