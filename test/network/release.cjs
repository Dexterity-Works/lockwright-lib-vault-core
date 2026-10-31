'use strict'
// The released vault-core, run as a peer beside the current build in the
// network project (test/network/mixedversion.test.js). It is a checkout of
// RELEASE_COMMIT with its own node_modules, so the released code resolves
// the dependencies its own lockfile pins, as it does inside a shipped app.
// DEPS.md, "Mixed-version peers", says which copy each side uses.
//
// The released code has no network seam: it builds Autopass without a
// bootstrap, and Autopass then builds its Hyperswarm with `bootstrap: null`,
// which hyperdht turns into the public DHT. mockRelease() fills in the
// testnet bootstrap at the released Autopass only, and puts the released
// copies of hyperdht, hyperswarm and udx-native behind the same guard as
// the current build's copies, so any other builder in the released code
// that passes no bootstrap still breaches.
const { execFileSync } = require('child_process')
const fs = require('fs')
const path = require('path')

const RELEASE_COMMIT = '031d532'

const releaseDir = () =>
  process.env.LOCKWRIGHT_RELEASE_DIR ||
  path.resolve(__dirname, '..', '..', '..', `release-${RELEASE_COMMIT}`)

const real = (name, from) =>
  fs.realpathSync(require.resolve(name, { paths: [from] }))

let cached

/**
 * The release tree, or null when there is none. A tree at the wrong commit
 * or without node_modules throws: a scenario must never run some other code
 * under the released build's name.
 * @returns {{ dir: string, head: string, worklet: string, paths: Record<string, string> } | null}
 */
const locateRelease = () => {
  if (cached !== undefined) return cached
  const dir = releaseDir()
  if (!fs.existsSync(path.join(dir, 'src', 'worklet', 'appDeps.js'))) {
    cached = null
    return cached
  }
  const head = execFileSync('git', ['-C', dir, 'rev-parse', 'HEAD'], {
    encoding: 'utf8'
  }).trim()
  if (!head.startsWith(RELEASE_COMMIT)) {
    throw new Error(
      `release tree ${dir} is at ${head.slice(0, 7)}, not ${RELEASE_COMMIT}`
    )
  }
  if (!fs.existsSync(path.join(dir, 'node_modules'))) {
    throw new Error(
      `release tree ${dir} has no node_modules; run pnpm install --no-frozen-lockfile there`
    )
  }
  const worklet = path.join(dir, 'src', 'worklet')
  // Resolved the way the released code resolves them. pnpm keeps one copy
  // of each, so appDeps, personalSwarm and Autopass reach the same files.
  const autopass = real('autopass', worklet)
  const hyperswarm = real('hyperswarm', path.dirname(autopass))
  const hyperdht = real('hyperdht', path.dirname(hyperswarm))
  const udx = real(
    'udx-native',
    path.dirname(real('dht-rpc', path.dirname(hyperdht)))
  )
  for (const [name, expected] of [
    ['hyperswarm', hyperswarm],
    ['hyperdht', hyperdht]
  ]) {
    if (real(name, worklet) !== expected) {
      throw new Error(`release tree resolves two copies of ${name}`)
    }
  }
  cached = {
    dir,
    head,
    worklet,
    paths: { autopass, hyperswarm, hyperdht, udx }
  }
  return cached
}

/**
 * The released Autopass with the testnet bootstrap filled in where the
 * released code passes none. Each isolated module graph gets its own class,
 * so `harness` is one released peer's.
 */
const wrapAutopass = (Autopass) => {
  const harness = { bootstrap: null, onCreate: null }
  const withBootstrap = (opts = {}) =>
    (opts.bootstrap === undefined || opts.bootstrap === null) &&
    harness.bootstrap
      ? { ...opts, bootstrap: harness.bootstrap }
      : opts
  class ReleasedAutopass extends Autopass {
    constructor(store, opts) {
      super(store, withBootstrap(opts))
      harness.onCreate?.('autopass', this)
    }

    static pair(store, invite, opts) {
      const pairer = super.pair(store, invite, withBootstrap(opts))
      harness.onCreate?.('pairer', pairer)
      return pairer
    }
  }
  ReleasedAutopass.harness = harness
  return ReleasedAutopass
}

/** Called from jest.guard.cjs. A missing release tree mocks nothing. */
const mockRelease = (jest, guard) => {
  const release = locateRelease()
  if (!release) return
  const { autopass, hyperswarm, hyperdht, udx } = release.paths
  jest.mock(hyperdht, () => guard.guardDHT(jest.requireActual(hyperdht)))
  jest.mock(hyperswarm, () => guard.guardSwarm(jest.requireActual(hyperswarm)))
  jest.mock(udx, () => guard.guardUDX(jest.requireActual(udx)))
  jest.mock(autopass, () => wrapAutopass(jest.requireActual(autopass)))
}

module.exports = { RELEASE_COMMIT, locateRelease, mockRelease }
