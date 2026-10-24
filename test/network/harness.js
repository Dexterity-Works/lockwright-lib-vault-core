import path from 'path'

import { Peer } from './peer.js'
import { startTestnet } from './testnet.js'
import { mkdtemp, removeDir } from './tmp.js'

/* global jest */

// A private copy of the worklet module graph per peer. appDeps holds one
// device in module singletons, so every peer needs its own registry; the
// guard's jest.mock wrappers apply inside it too.
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

/**
 * A testnet plus K started peers (master vault open, no active vault yet).
 * @param {{ peers?: string[], size?: number, relayThrough?: any, onCreate?: Function, onUpdate?: Function, name?: string }} options
 */
export const createNetwork = async ({
  peers = ['A', 'B'],
  size = 3,
  relayThrough = [],
  onCreate,
  onUpdate,
  name = 'net'
} = {}) => {
  const testnet = await startTestnet({ size })
  const dir = mkdtemp(name)
  const byId = {}
  const list = []
  try {
    for (const id of peers) {
      const peer = new Peer({
        id,
        modules: loadIsolatedModules(),
        bootstrap: testnet.bootstrap,
        relayThrough,
        dir: path.join(dir, id),
        onCreate,
        onUpdate
      })
      await peer.start()
      byId[id] = peer
      list.push(peer)
    }
  } catch (error) {
    for (const peer of list.reverse()) await peer.stop().catch(() => {})
    await testnet.destroy()
    removeDir(dir)
    throw error
  }
  return {
    testnet,
    bootstrap: testnet.bootstrap,
    peers: byId,
    list,
    dir,
    destroy: async ({ keep = false } = {}) => {
      for (const peer of [...list].reverse()) await peer.stop({ keep })
      await testnet.destroy()
      if (!keep) removeDir(dir)
    }
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
