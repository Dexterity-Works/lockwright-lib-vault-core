import { traceCreated } from '../trace/index.js'

export async function getConfig(store) {
  try {
    const Swarmconf = require('@tetherto/swarmconf')
    const conf = new Swarmconf(store)
    await conf.ready()
    return conf
  } catch {
    // Package not installed, so we return a dummy config
    // You can replace this with your own Hyperconf instance
    // see https://github.com/holepunchto/hyperconf
    return {
      current: {
        version: 0,
        blindRelays: [],
        blindPeers: []
      }
    }
  }
}

// Test seam for everything that builds a Hyperswarm, an Autopass or a DHT.
// Production never sets overrides: `networkOptions(options)` then returns
// `options` itself and `networkCreated` only hands the instance back, so each
// builder gets exactly the options it always got. Tests point every builder
// at a local testnet bootstrap, replace the relays with local ones or none,
// and see each instance as it is built. A host that opted into a trace file
// (SET_LOG_OPTIONS traceFile) also gets each instance traced; the options
// stay the same.
let networkOverrides = null

/**
 * @param {{
 *   bootstrap?: Array<{ host: string, port: number } | string>,
 *   relayThrough?: Array<Buffer | string> | null,
 *   onCreate?: (label: string, instance: object) => void
 * } | null} overrides
 */
export const setNetworkOverrides = (overrides) => {
  networkOverrides = overrides ?? null
}

/**
 * @template T
 * @param {T} [options]
 * @returns {T}
 */
export const networkOptions = (options) => {
  if (networkOverrides === null) return options
  const next = { ...options }
  if ('bootstrap' in networkOverrides) {
    next.bootstrap = networkOverrides.bootstrap
  }
  if ('relayThrough' in networkOverrides) {
    next.relayThrough = networkOverrides.relayThrough
  }
  return next
}

/**
 * @template T
 * @param {string} label
 * @param {T} instance
 * @param {string} [role] what the tracer calls it, when `label` is shared
 * @returns {T}
 */
export const networkCreated = (label, instance, role = label) => {
  networkOverrides?.onCreate?.(label, instance)
  traceCreated(role, instance)
  return instance
}
