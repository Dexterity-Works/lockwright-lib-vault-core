import b4a from 'b4a'

import { redact } from '../utils/redact.js'

// What a trace may hold. A trace is a local file the user turned on, read by
// the user, so it records 8-char key prefixes, peer IP:port, topic and
// autobase lengths, error codes and timings. It never records secrets,
// record contents, vault or item names, passwords, invite codes or full
// keys: fields go through the worklet's redact(), keys only ever appear as
// short() prefixes, and scrub() cuts what reaches a string field anyway:
// an absolute path to its last component, a UUID to its first 8 chars, and
// any long hex, base64 or z32 run to [REDACTED].
//
// The tracer only listens. It adds no 'error' listener to anything it
// watches: autobase and streams treat a missing listener as "crash", and a
// listener would turn that into a silently closed vault. Errors are read on
// close instead.

/** The first 8 chars of a key or id: enough to tell peers apart, never the key. */
export const short = (value) => {
  if (value === null || value === undefined) return null
  if (typeof value === 'string') return value.slice(0, 8)
  return b4a.toString(value, 'hex').slice(0, 8)
}

const LONG_RUNS = [
  /[0-9a-f]{32,}/gi,
  /[A-Za-z0-9+/]{40,}={0,2}/g,
  /[ybndrfg8ejkmcpqxot1uwisza345h769]{40,}/g
]

// Absolute only: at the start, or after a space, quote, bracket, = or :.
const POSIX_PATH = /(?<=^|[\s'"`(=:,])(?:\/+[^\s/'"`]+)+\/([^\s/'"`]+)/g
const WINDOWS_PATH = /\b[A-Za-z]:\\(?:[^\s\\'"`]+\\)*([^\s\\'"`]+)/g
const UUID =
  /\b([0-9a-f]{8})-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi

/** A string with paths, UUIDs and key-length runs cut down. */
export const scrub = (value) => {
  if (typeof value === 'string') {
    let out = value
      .replace(POSIX_PATH, '$1')
      .replace(WINDOWS_PATH, '$1')
      .replace(UUID, '$1')
    for (const run of LONG_RUNS) out = out.replace(run, '[REDACTED]')
    return out
  }
  if (Array.isArray(value)) return value.map(scrub)
  if (value && typeof value === 'object') {
    const out = {}
    for (const key of Object.keys(value)) out[key] = scrub(value[key])
    return out
  }
  return value
}

const now = () => globalThis.performance?.now?.() ?? Date.now()

const socketName = (socket, dht) => {
  if (!socket) return null
  if (socket === dht.io.serverSocket) return 'server'
  if (socket === dht.io.clientSocket) return 'client'
  if (dht._socketPool?.lookup(socket)) return 'pool'
  return 'other'
}

const hex = (key) => {
  if (!key) return null
  return typeof key === 'string' ? key.toLowerCase() : b4a.toString(key, 'hex')
}

/**
 * direct / holepunched / relayed, from where the raw stream's packets go.
 * Nothing on the connection names the path (test/network/DEPS.md Recipes c).
 * A relayed stream rides the relay connection's socket and address, so
 * `relayAddresses` is where the known relays answered. `ridden(address)` is
 * the key of another stream dialed to that address, if any: a stream on
 * someone else's address that is not a known relay is `unknown`, never
 * `direct`.
 */
export const classify = (conn, dht, relayAddresses, ridden = () => null) => {
  const rs = conn.rawStream
  if (!rs || !rs.connected) return 'pending'
  const remote = `${rs.remoteHost}:${rs.remotePort}`
  if (relayAddresses.has(remote)) return 'relayed'
  const owner = ridden(remote)
  if (owner && owner !== hex(conn.remotePublicKey)) return 'unknown'
  if (dht._socketPool?.lookup(rs.socket)) return 'holepunched'
  if (rs.socket === dht.io.serverSocket || rs.socket === dht.io.clientSocket) {
    return 'direct'
  }
  return 'unknown'
}

// The error a stream closed with, as streamx keeps it (hyperswarm reads it
// the same way). Read on close, so the tracer adds no error listener.
const streamError = (stream) =>
  stream._readableState?.error || stream._writableState?.error || null

const errorCode = (error) =>
  error ? (error.code ?? error.name ?? 'Error') : null

/**
 * One device's trace: JSONL, one event per line, with a monotonic clock in
 * ms since the tracer started (`t`) and the wall clock (`wall`).
 */
export class Tracer {
  /**
   * @param {{
   *   peer?: string | null,
   *   sink: { write: (line: string) => void, close?: () => void },
   *   relayAddresses?: Set<string>,
   *   onEvent?: (event: object) => void,
   *   keepEvents?: boolean,
   *   sampleInterval?: number
   * }} options
   */
  constructor({
    peer = null,
    sink,
    relayAddresses = new Set(),
    onEvent,
    keepEvents = false,
    sampleInterval = 500
  }) {
    this.peer = peer
    this.sink = sink
    this.relayAddresses = relayAddresses
    // Relay keys from the swarms' relayThrough and the dials' options; the
    // address a dial to one of them opens on is a relay address.
    this.relayKeys = new Set()
    // Per DHT: remote address -> key of the dialed stream open on it.
    this.dialed = new WeakMap()
    this.onEvent = onEvent
    this.events = keepEvents ? [] : null
    this.sampleInterval = sampleInterval
    this.t0 = now()
    this.swarms = new WeakSet()
    this.dhts = new WeakSet()
    this.bases = new WeakSet()
    this.samplers = new Set()
    this.timer = null
    this.lastEpochStatus = null
    this.closed = false
  }

  /** Never throws: a trace must not break the code it watches. */
  record(event, fields = {}) {
    if (this.closed) return null
    try {
      const line = {
        t: Math.round((now() - this.t0) * 1000) / 1000,
        wall: new Date().toISOString(),
        peer: this.peer,
        event,
        ...scrub(redact(fields))
      }
      this.events?.push(line)
      this.sink.write(`${JSON.stringify(line)}\n`)
      this.onEvent?.(line)
      return line
    } catch {
      return null
    }
  }

  error(where, error, extra = {}) {
    return this.record('error', {
      where,
      code: error?.code ?? null,
      name: error?.name ?? null,
      message: String(error?.message ?? error).slice(0, 200),
      ...extra
    })
  }

  /**
   * Instruments whatever networkCreated handed out. `label` is the role:
   * personalSwarm, personalSend, sharedDHT, master, vault, encryption,
   * autopass or pairer.
   */
  attach(label, instance) {
    switch (label) {
      case 'personalSwarm':
      case 'personalSend':
        return this.attachSwarm(label, instance)
      case 'sharedDHT':
        return this.attachDHT(label, instance)
      case 'autopass':
      case 'master':
      case 'vault':
      case 'encryption':
        this.record('autopass.create', { label })
        instance
          .ready()
          .then(() => {
            if (instance.swarm) this.attachSwarm(label, instance.swarm)
            this.attachBase(label, instance.base)
          })
          .catch((error) => this.error(`${label}.ready`, error))
        return
      case 'pairer':
        this.record('pairing.start', { label })
        instance
          .ready()
          .then(() => {
            if (instance.swarm) this.attachSwarm(label, instance.swarm)
          })
          .catch((error) => this.error(`${label}.ready`, error))
        return
      default:
        this.record('create', { label })
    }
  }

  attachDHT(label, dht) {
    if (this.dhts.has(dht)) return
    this.dhts.add(dht)
    this.record('dht.create', { label, bootstrap: dht.bootstrapNodes })
    dht
      .fullyBootstrapped()
      .then(() =>
        this.record('dht.ready', {
          label,
          port: dht.address()?.port ?? null,
          firewalled: dht.firewalled,
          randomized: dht.randomized
        })
      )
      .catch((error) => this.error(`${label}.bootstrap`, error))

    // Every outgoing connect, the swarm's and a relay dial's alike. One
    // that closes without opening is a conn.fail with the stream's error.
    const dialed = new Map()
    this.dialed.set(dht, dialed)
    const connect = dht.connect.bind(dht)
    dht.connect = (remotePublicKey, opts) => {
      if (typeof opts?.relayThrough !== 'function') {
        this.learnRelays(opts?.relayThrough)
      }
      const conn = connect(remotePublicKey, opts)
      const remote = short(remotePublicKey)
      const key = hex(remotePublicKey)
      const started = now()
      let opened = false
      let address = null
      this.record('conn.attempt', {
        label,
        remote,
        relayed: !!opts?.relayThrough
      })
      conn.once('open', () => {
        opened = true
        const rs = conn.rawStream
        if (!rs?.connected) return
        address = `${rs.remoteHost}:${rs.remotePort}`
        dialed.set(address, key)
        if (this.relayKeys.has(key)) {
          this.relayAddresses.add(address)
          this.record('relay.open', { label, remote, address })
        }
      })
      conn.once('close', () => {
        if (address && dialed.get(address) === key) dialed.delete(address)
        if (opened) return
        const error = streamError(conn)
        this.record('conn.fail', {
          label,
          remote,
          code: errorCode(error),
          ms: Math.round(now() - started)
        })
      })
      return conn
    }

    // Counters only: dht-rpc's own query and command counts move on every
    // ping and would fill an idle trace.
    this.sample(
      () => dht.destroyed,
      () => ({
        punches: { ...dht.stats?.punches },
        relaying: { ...dht.stats?.relaying }
      }),
      (stats) => this.record('dht.stats', { label, ...stats })
    )
  }

  attachSwarm(label, swarm) {
    if (this.swarms.has(swarm)) return
    this.swarms.add(swarm)
    const dht = swarm.dht
    try {
      // hyperswarm's relayThrough(force, swarm) only returns its option.
      this.learnRelays(swarm.relayThrough?.(true, swarm))
    } catch {
      // a relay we cannot name is classified `unknown`, not `direct`
    }
    this.record('swarm.create', {
      label,
      key: short(swarm.keyPair.publicKey),
      bootstrap: dht.bootstrapNodes
    })
    this.attachDHT(label, dht)

    // Autopass joins before ready() resolves; list what is already joined.
    for (const discovery of swarm.topics()) {
      this.record('topic.join', {
        label,
        topic: short(discovery.topic),
        server: discovery.isServer,
        client: discovery.isClient,
        late: true
      })
    }
    const join = swarm.join.bind(swarm)
    swarm.join = (topic, opts = {}) => {
      this.record('topic.join', {
        label,
        topic: short(topic),
        server: opts.server !== false,
        client: opts.client !== false
      })
      return join(topic, opts)
    }
    const leave = swarm.leave.bind(swarm)
    swarm.leave = (topic) => {
      this.record('topic.leave', { label, topic: short(topic) })
      return leave(topic)
    }
    const suspend = swarm.suspend.bind(swarm)
    swarm.suspend = (opts) => {
      this.record('swarm.suspend', { label })
      return suspend(opts)
    }
    const resume = swarm.resume.bind(swarm)
    swarm.resume = (opts) => {
      this.record('swarm.resume', { label })
      return resume(opts)
    }
    const destroy = swarm.destroy.bind(swarm)
    swarm.destroy = (opts) => {
      if (!swarm.destroyed) this.record('swarm.destroy', { label })
      return destroy(opts)
    }

    // Already open when the tracer arrived: their open time is not known.
    for (const conn of swarm.connections) {
      this.watchConnection(label, conn, dht, true)
    }
    swarm.on('connection', (conn) => this.watchConnection(label, conn, dht))
    swarm.on('ban', (info, error) =>
      this.record('peer.ban', {
        label,
        remote: short(info.publicKey),
        reason: error?.code ?? error?.message ?? null
      })
    )

    // `updates` moves on every swarm event; the rest only on a change.
    this.sample(
      () => swarm.destroyed,
      () => ({
        connects: {
          client: { ...swarm.stats.connects.client },
          server: { ...swarm.stats.connects.server }
        },
        bannedPeers: swarm.stats.bannedPeers,
        connections: swarm.connections.size,
        connecting: swarm.connecting
      }),
      (stats) => this.record('swarm.stats', { label, ...stats })
    )
    this.sample(
      () => swarm.destroyed,
      () =>
        [...swarm.peers.values()].map((info) => ({
          remote: short(info.publicKey),
          attempts: info.attempts,
          banned: info.banned,
          tried: info.tried,
          queued: info.queued,
          proven: info.proven,
          forceRelaying: info.forceRelaying,
          topics: info.topics?.length ?? 0
        })),
      (peers) => this.record('swarm.peers', { label, peers })
    )
  }

  /** @param {Buffer | string | Array<Buffer | string> | null | undefined} keys */
  learnRelays(keys) {
    for (const key of Array.isArray(keys) ? keys : [keys]) {
      if (key && (typeof key === 'string' || b4a.isBuffer(key))) {
        this.relayKeys.add(hex(key))
      }
    }
  }

  /**
   * Records `take()` now and again every sampleInterval ms, but only when
   * it changed, so idle periods stay quiet. Stops once `done()` is true.
   */
  sample(done, take, emit) {
    let last = null
    const tick = () => {
      if (done()) return false
      const value = take()
      const json = JSON.stringify(value)
      if (json !== last) {
        last = json
        emit(value)
      }
      return true
    }
    if (!tick()) return
    this.samplers.add(tick)
    if (this.timer) return
    this.timer = setInterval(() => {
      for (const sampler of this.samplers) {
        try {
          if (!sampler()) this.samplers.delete(sampler)
        } catch {
          this.samplers.delete(sampler)
        }
      }
      // Nothing left to watch; the next sample() starts it again.
      if (this.samplers.size === 0) {
        clearInterval(this.timer)
        this.timer = null
      }
    }, this.sampleInterval)
    this.timer.unref?.()
  }

  watchConnection(label, conn, dht, late = false) {
    const remote = short(conn.remotePublicKey)
    const stats = () => ({
      punches: { ...dht.stats.punches },
      relaying: { ...dht.stats.relaying }
    })
    const describe = () => {
      const rs = conn.rawStream
      return {
        label,
        remote,
        initiator: conn.isInitiator,
        path: classify(
          conn,
          dht,
          this.relayAddresses,
          (address) => this.dialed.get(dht)?.get(address) ?? null
        ),
        socket: socketName(rs?.socket, dht),
        remoteAddress: rs?.connected
          ? `${rs.remoteHost}:${rs.remotePort}`
          : null,
        stats: stats()
      }
    }
    this.record('conn.open', late ? { ...describe(), late } : describe())
    conn.rawStream?.on('remote-changed', () =>
      this.record('conn.upgrade', describe())
    )
    conn.on('close', () =>
      this.record('conn.close', {
        label,
        remote,
        code: errorCode(streamError(conn)),
        bytesRead: conn.rawBytesRead,
        bytesWritten: conn.rawBytesWritten
      })
    )
  }

  attachBase(label, base) {
    if (this.bases.has(base)) return
    this.bases.add(base)
    const snapshot = () => ({
      label,
      length: base.length,
      signedLength: base.signedLength,
      indexedLength: base.indexedLength,
      viewLength: base.view?.core?.length ?? null,
      writable: base.writable
    })
    this.record('autobase.open', {
      ...snapshot(),
      key: short(base.key),
      discoveryKey: short(base.discoveryKey),
      local: short(base.local?.key)
    })
    base.local?.on('append', () =>
      this.record('autobase.append', { label, localLength: base.local.length })
    )
    base.on('update', () => this.record('autobase.update', snapshot()))
    base.on('writable', () => this.record('autobase.writable', { label }))
    base.on('unwritable', () => this.record('autobase.unwritable', { label }))
    base.on('is-indexer', () => this.record('autobase.indexer', { label }))
    base.on('is-non-indexer', () =>
      this.record('autobase.non-indexer', { label })
    )
    base.on('fast-forward', () =>
      this.record('autobase.fast-forward', { label })
    )
    base.on('interrupt', () => this.record('autobase.interrupt', { label }))
    base.on('warning', (error) =>
      this.error('autobase.warning', error, { label })
    )
    // Not base.on('error'): see the note at the top of this file.
    base.on('close', () => {
      const error = base.getLastError?.() ?? null
      if (error) this.error('autobase.close', error, { label })
      else this.record('autobase.close', { label })
    })
  }

  /** Recorded when it differs from the last status this tracer saw. */
  epochStatus(status) {
    const fields = {
      vault: short(status.vaultId),
      epoch: short(status.epoch),
      seq: status.seq,
      legacy: status.legacy,
      canRead: status.canRead,
      revoked: status.revoked,
      members: (status.members ?? []).map(short),
      uncovered: (status.uncovered ?? []).map(short)
    }
    const json = JSON.stringify(fields)
    if (json === this.lastEpochStatus) return null
    this.lastEpochStatus = json
    return this.record('epoch.status', fields)
  }

  close() {
    if (this.closed) return
    this.closed = true
    if (this.timer) clearInterval(this.timer)
    this.timer = null
    this.samplers.clear()
    try {
      this.sink.close?.()
    } catch {
      // best-effort close
    }
  }
}
