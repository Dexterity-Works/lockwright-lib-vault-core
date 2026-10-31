import fs from 'fs'
import path from 'path'

import guard from './guard.cjs'
import { Peer } from './peer.js'
import { startTestnet } from './testnet.js'
import { writeTimeline } from './timeline.js'
import { mkdtemp, removeDir } from './tmp.js'
import { Tracer } from './tracer.js'

/* global jest */

// A private copy of the worklet module graph per peer. appDeps holds one
// device in module singletons, so every peer needs its own registry. The
// mocked libraries (hyperdht, hyperswarm, udx-native) come from jest's
// shared mock registry, so peers share those module instances; they keep
// no per-device state.
export const loadIsolatedModules = () => {
  let modules
  jest.isolateModules(() => {
    modules = {
      appDeps: require('../../src/worklet/appDeps'),
      network: require('../../src/worklet/utils/swarm'),
      personalSwarm: require('../../src/worklet/personalSwarm'),
      dht: require('../../src/worklet/utils/dht'),
      logger: require('../../src/worklet/utils/workletLogger')
    }
  })
  return modules
}

// Set by test/network/jest.environment.cjs from jest-circus events.
const currentTest = () =>
  globalThis.__lockwrightNetworkTest ?? {
    name: 'unknown test',
    failed: false,
    messages: []
  }

/**
 * A testnet plus K started peers (master vault open, no active vault yet).
 * Every peer writes a JSONL trace under `<dir>/traces/`; when the test
 * fails (or `keep` is set) `destroy()` merges them into a timeline under
 * `test-artifacts/<test name>/` and prints its path.
 * @param {{ peers?: string[], size?: number, relayThrough?: any, relayAddresses?: Set<string>, onCreate?: Function, onUpdate?: Function, onEvent?: Function, name?: string }} options
 */
export const createNetwork = async ({
  peers = ['A', 'B'],
  size = 3,
  relayThrough = [],
  relayAddresses = new Set(),
  onCreate,
  onUpdate,
  onEvent,
  name = 'net'
} = {}) => {
  const testnet = await startTestnet({ size })
  const dir = mkdtemp(name)
  const tracesDir = path.join(dir, 'traces')
  fs.mkdirSync(tracesDir, { recursive: true })
  const byId = {}
  const list = []
  const tracers = {}
  try {
    for (const id of peers) {
      const tracer = new Tracer({
        peer: id,
        file: path.join(tracesDir, `${id}.jsonl`),
        relayAddresses,
        onEvent
      })
      tracers[id] = tracer
      const peer = new Peer({
        id,
        modules: loadIsolatedModules(),
        bootstrap: testnet.bootstrap,
        relayThrough,
        dir: path.join(dir, id),
        tracer,
        onCreate,
        onUpdate
      })
      await peer.start()
      byId[id] = peer
      list.push(peer)
    }
  } catch (error) {
    for (const peer of list.reverse()) await peer.stop().catch(() => {})
    for (const tracer of Object.values(tracers)) tracer.close()
    await testnet.destroy()
    removeDir(dir)
    throw error
  }
  let destroyed = null
  return {
    testnet,
    bootstrap: testnet.bootstrap,
    peers: byId,
    list,
    tracers,
    dir,
    traceFiles: () => Object.values(tracers).map((t) => t.file),
    destroy: ({ keep = false } = {}) => {
      destroyed ??= destroy({ keep })
      return destroyed
    }
  }

  async function destroy({ keep }) {
    for (const peer of [...list].reverse()) await peer.stop({ keep: true })
    for (const tracer of Object.values(tracers)) tracer.close()
    await testnet.destroy()
    const test = currentTest()
    const wanted =
      keep || test.failed || process.env.LOCKWRIGHT_NET_KEEP === '1'
    let timeline = null
    if (wanted) {
      timeline = writeTimeline({
        name: test.name,
        files: Object.values(tracers).map((t) => t.file),
        failure: test.failed ? { messages: test.messages } : null
      })
      // eslint-disable-next-line no-console
      console.log(`timeline: ${timeline.txt}\nreport: ${timeline.html}`)
    }
    if (!keep) removeDir(dir)
    try {
      const errors = list.flatMap((peer) => peer.errors)
      if (errors.length) {
        throw new AggregateError(errors, `teardown: ${errors.length} error(s)`)
      }
      const breaches = guard.violations()
      guard.reset()
      if (breaches.length) {
        throw new Error(
          `guard: ${breaches.length} breach(es) during the test: ${breaches
            .map((b) => b.message)
            .join('; ')}`
        )
      }
    } catch (error) {
      if (!timeline) {
        timeline = writeTimeline({
          name: test.name,
          files: Object.values(tracers).map((t) => t.file),
          failure: { messages: [error.message] }
        })
        // eslint-disable-next-line no-console
        console.log(`timeline: ${timeline.txt}\nreport: ${timeline.html}`)
      }
      throw error
    }
    return { timeline }
  }
}

export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

/**
 * Poll until `fn` returns a truthy value.
 * @template T
 * @param {() => Promise<T> | T} fn
 * @param {{ timeout?: number, interval?: number, label?: string }} [options]
 * @returns {Promise<T>}
 */
export const waitFor = async (
  fn,
  { timeout = 30000, interval = 100, label = 'condition' } = {}
) => {
  const deadline = Date.now() + timeout
  let last
  for (;;) {
    try {
      last = await fn()
      if (last) return last
    } catch (error) {
      last = error
    }
    if (Date.now() >= deadline) break
    await sleep(interval)
  }
  const detail =
    last instanceof Error
      ? last.message
      : (JSON.stringify(last) ?? String(last))
  throw new Error(
    `waitFor: ${label} not met within ${timeout} ms (last: ${detail})`
  )
}

/** Wait until every peer reads the same value under `key`. */
export const converge = (peers, key, { timeout, label = key } = {}) =>
  waitFor(
    async () => {
      const values = await Promise.all(peers.map((p) => p.get(key)))
      const first = JSON.stringify(values[0])
      return values.every((v) => JSON.stringify(v) === first) && values[0]
        ? values[0]
        : false
    },
    { timeout, label: `converge ${label}` }
  )

/**
 * One vault created on `owner` and paired to every other peer, with every
 * peer seeing every device row.
 */
export const shareVault = async (
  net,
  { owner = net.list[0].id, id = 'shared' } = {}
) => {
  const host = net.peers[owner]
  await host.createVault({ id })
  for (const peer of net.list) {
    if (peer !== host) await peer.pair(await host.invite())
  }
  const n = net.list.length
  for (const peer of net.list) {
    await waitFor(async () => (await peer.devices()).length === n, {
      label: `${peer.id} sees ${n} device rows`
    })
  }
  return host
}
