'use strict'
// Public-DHT guard for the network harness. While it is installed, every
// HyperDHT and Hyperswarm must be built with an explicit bootstrap list of
// local addresses, every relay must be one the harness started, and every
// UDX socket or stream may only talk to local addresses. A breach throws a
// NetworkGuardError and is recorded, so a test can also assert afterwards
// that nothing was even attempted.
//
// The public bootstrap list is read from hyperdht's own source, not copied.
// hyperdht falls back to it for any falsy `bootstrap` (hyperdht/index.js:28,
// `opts.bootstrap || BOOTSTRAP_NODES`); `[]` is an isolated node and passes.
const net = require('net')

const { BOOTSTRAP_NODES } = require('hyperdht/lib/constants')

class NetworkGuardError extends Error {
  constructor(message) {
    super(message)
    this.name = 'NetworkGuardError'
    this.code = 'NETWORK_GUARD'
  }
}

const PUBLIC_BOOTSTRAP = Object.freeze([...BOOTSTRAP_NODES])

// 'ip@hostname:port' or 'host:port' -> { ip, host, port }
const parsePublicEntry = (entry) => {
  const [ip, rest] = entry.includes('@') ? entry.split('@') : [null, entry]
  const at = rest.lastIndexOf(':')
  return {
    ip,
    host: rest.slice(0, at).toLowerCase(),
    port: Number(rest.slice(at + 1))
  }
}

const PUBLIC_HOSTS = new Set()
for (const entry of PUBLIC_BOOTSTRAP) {
  const { ip, host } = parsePublicEntry(entry)
  if (ip) PUBLIC_HOSTS.add(ip)
  PUBLIC_HOSTS.add(host)
}

const state = {
  allowPrivate: process.env.LOCKWRIGHT_NET_ALLOW_PRIVATE === '1',
  hosts: new Set(),
  relays: new Set(),
  violations: []
}

const isPrivateV4 = (host) => {
  const [a, b] = host.split('.').map(Number)
  return (
    a === 10 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254)
  )
}

const isLocalHost = (host) => {
  if (typeof host !== 'string') return false
  const lower = host.toLowerCase()
  if (lower === 'localhost' || lower === '::1') return true
  if (state.hosts.has(lower)) return true
  if (!net.isIPv4(lower)) return false
  if (lower.startsWith('127.')) return true
  return state.allowPrivate && isPrivateV4(lower)
}

const breach = (message) => {
  const error = new NetworkGuardError(message)
  state.violations.push({ at: Date.now(), message })
  return error
}

const describe = (value) => {
  if (value === undefined) return 'undefined'
  if (value === null) return 'null'
  if (Array.isArray(value)) return `an array of ${value.length}`
  return typeof value
}

const parseEntry = (entry, who) => {
  if (typeof entry === 'number') return { host: '127.0.0.1', port: entry }
  if (typeof entry === 'string') {
    const parsed = parsePublicEntry(entry)
    if (parsed.ip || !net.isIPv4(parsed.host)) {
      throw breach(
        `${who}: bootstrap entry ${JSON.stringify(entry)} names a host, which needs DNS; use a local IPv4 literal`
      )
    }
    return parsed
  }
  if (entry && typeof entry === 'object' && typeof entry.host === 'string') {
    return { host: entry.host.toLowerCase(), port: entry.port }
  }
  throw breach(`${who}: unreadable bootstrap entry ${JSON.stringify(entry)}`)
}

/**
 * @param {{ bootstrap?: unknown } | undefined} opts
 * @param {string} who
 */
const assertBootstrap = (opts, who) => {
  const bootstrap = opts ? opts.bootstrap : undefined
  if (!Array.isArray(bootstrap)) {
    throw breach(
      `${who} built without an explicit bootstrap array (got ${describe(bootstrap)}); hyperdht would fall back to the public DHT`
    )
  }
  for (const entry of bootstrap) {
    const { host, port } = parseEntry(entry, who)
    if (PUBLIC_HOSTS.has(host)) {
      throw breach(
        `${who}: bootstrap entry ${host}:${port} is a public hyperdht bootstrap node`
      )
    }
    if (!isLocalHost(host)) {
      throw breach(
        `${who}: bootstrap host ${host} is not local (loopback, an allowed host, or a private range when LOCKWRIGHT_NET_ALLOW_PRIVATE=1)`
      )
    }
  }
}

const toHex = (key) => {
  if (typeof key === 'string') return key.toLowerCase()
  if (key && typeof key.length === 'number') {
    return Buffer.from(key).toString('hex')
  }
  return null
}

/**
 * @param {unknown} relayThrough
 * @param {string} who
 */
const assertRelays = (relayThrough, who) => {
  if (relayThrough === undefined || relayThrough === null) return
  const value =
    typeof relayThrough === 'function' ? relayThrough() : relayThrough
  if (value === undefined || value === null) return
  const keys = Array.isArray(value) ? value : [value]
  for (const key of keys) {
    const hex = toHex(key)
    if (hex === null || !state.relays.has(hex)) {
      throw breach(
        `${who}: relayThrough key ${hex ? hex.slice(0, 8) : '?'}… is not a relay this harness started`
      )
    }
  }
}

const assertDestination = (host, who) => {
  if (!isLocalHost(host)) {
    throw breach(`${who} to ${host}: not a local address`)
  }
}

/**
 * @template {new (...args: any[]) => any} T
 * @param {T} HyperDHT
 * @returns {T}
 */
const guardDHT = (HyperDHT) => {
  class GuardedHyperDHT extends HyperDHT {
    constructor(opts = {}) {
      assertBootstrap(opts, 'HyperDHT')
      super(opts)
      if (this.bootstrapNodes === BOOTSTRAP_NODES) {
        throw breach('HyperDHT ended up on the public bootstrap list')
      }
    }
  }
  return GuardedHyperDHT
}

/**
 * @template {new (...args: any[]) => any} T
 * @param {T} Hyperswarm
 * @returns {T}
 */
const guardSwarm = (Hyperswarm) => {
  class GuardedHyperswarm extends Hyperswarm {
    constructor(opts = {}) {
      if (!opts.dht) assertBootstrap(opts, 'Hyperswarm')
      assertRelays(opts.relayThrough, 'Hyperswarm')
      super(opts)
    }
  }
  return GuardedHyperswarm
}

const guardSocket = (socket) => {
  const send = socket.send.bind(socket)
  const trySend = socket.trySend.bind(socket)
  // async like the original, so a breach rejects instead of throwing
  socket.send = async (buffer, port, host, ttl) => {
    assertDestination(host, 'udx socket send')
    return send(buffer, port, host, ttl)
  }
  socket.trySend = (buffer, port, host, ttl) => {
    assertDestination(host, 'udx socket trySend')
    return trySend(buffer, port, host, ttl)
  }
  return socket
}

const guardStream = (stream) => {
  const connect = stream.connect.bind(stream)
  const changeRemote = stream.changeRemote.bind(stream)
  stream.connect = (socket, remoteId, port, host, opts) => {
    assertDestination(host, 'udx stream connect')
    return connect(socket, remoteId, port, host, opts)
  }
  stream.changeRemote = (socket, remoteId, port, host) => {
    assertDestination(host, 'udx stream changeRemote')
    return changeRemote(socket, remoteId, port, host)
  }
  return stream
}

/**
 * Patches every socket and stream a UDX instance hands out, plus DNS.
 * @template {new (...args: any[]) => any} T
 * @param {T} UDX
 * @returns {T}
 */
const guardUDX = (UDX) => {
  if (UDX.prototype.__networkGuard) return UDX
  const { createSocket, createStream, lookup } = UDX.prototype
  UDX.prototype.createSocket = function (opts) {
    return guardSocket(createSocket.call(this, opts))
  }
  UDX.prototype.createStream = function (id, opts) {
    return guardStream(createStream.call(this, id, opts))
  }
  UDX.prototype.lookup = function (host, opts) {
    if (String(host).toLowerCase() !== 'localhost') {
      throw breach(`udx lookup of ${host}: DNS is off`)
    }
    return lookup.call(this, host, opts)
  }
  UDX.prototype.__networkGuard = true
  return UDX
}

module.exports = {
  NetworkGuardError,
  PUBLIC_BOOTSTRAP,
  assertBootstrap,
  assertRelays,
  assertDestination,
  isLocalHost,
  guardDHT,
  guardSwarm,
  guardUDX,
  /** Allow one more host, for a container address or a NAT gateway. */
  allowHost: (host) => state.hosts.add(String(host).toLowerCase()),
  allowPrivateRanges: (on = true) => {
    state.allowPrivate = !!on
  },
  /** Register a relay the harness started; `relayThrough` may then name it. */
  allowRelay: (publicKey) => state.relays.add(toHex(publicKey)),
  violations: () => [...state.violations],
  reset: () => {
    state.hosts.clear()
    state.relays.clear()
    state.violations.length = 0
    state.allowPrivate = process.env.LOCKWRIGHT_NET_ALLOW_PRIVATE === '1'
  }
}
