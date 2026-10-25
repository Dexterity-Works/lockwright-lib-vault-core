import fs from 'fs'
import { performance } from 'perf_hooks'

import { redact } from '../../src/worklet/utils/redact.js'

/** The first 8 hex chars of a key: enough to tell peers apart, never the key. */
export const short = (value) => {
  if (value === null || value === undefined) return null
  if (typeof value === 'string') return value.slice(0, 8)
  return Buffer.from(value).toString('hex').slice(0, 8)
}

const socketName = (socket, dht) => {
  if (!socket) return null
  if (socket === dht.io.serverSocket) return 'server'
  if (socket === dht.io.clientSocket) return 'client'
  if (dht._socketPool?.lookup(socket)) return 'pool'
  return 'other'
}

/**
 * direct / holepunched / relayed, from where the raw stream's packets go.
 * DEPS.md Recipes (c): nothing on the connection names the path.
 */
export const classify = (conn, dht, relayAddresses) => {
  const rs = conn.rawStream
  if (!rs || !rs.connected) return 'pending'
  const remote = `${rs.remoteHost}:${rs.remotePort}`
  if (relayAddresses.has(remote)) return 'relayed'
  if (dht._socketPool?.lookup(rs.socket)) return 'holepunched'
  if (rs.socket === dht.io.serverSocket || rs.socket === dht.io.clientSocket) {
    return 'direct'
  }
  return 'unknown'
}

/**
 * One peer's trace: JSONL, one event per line, with a monotonic clock in ms
 * since the tracer started and the wall clock. Fields go through the
 * worklet's redact() and keys are only ever logged as 8-char prefixes.
 */
export class Tracer {
  /**
   * @param {{ peer: string, file: string, relayAddresses?: Set<string>, onEvent?: Function }} options
   */
  constructor({ peer, file, relayAddresses = new Set(), onEvent }) {
    this.peer = peer
    this.file = file
    this.relayAddresses = relayAddresses
    this.onEvent = onEvent
    this.t0 = performance.now()
    this.events = []
    this.fd = fs.openSync(file, 'a')
    this.swarms = new WeakSet()
    this.bases = new WeakSet()
    this.closed = false
  }

  record(event, fields = {}) {
    if (this.closed) return null
    const line = {
      t: Math.round((performance.now() - this.t0) * 1000) / 1000,
      wall: new Date().toISOString(),
      peer: this.peer,
      event,
      ...redact(fields)
    }
    this.events.push(line)
    fs.writeSync(this.fd, `${JSON.stringify(line)}\n`)
    this.onEvent?.(line)
    return line
  }

  error(where, error, extra = {}) {
    return this.record('error', {
      where,
      code: error?.code ?? null,
      message: error?.message ?? String(error),
      ...extra
    })
  }

  /** Hook for the seam's onCreate: instruments whatever it handed out. */
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
  }

  attachSwarm(label, swarm) {
    if (this.swarms.has(swarm)) return
    this.swarms.add(swarm)
    const dht = swarm.dht
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

    for (const conn of swarm.connections) this.watchConnection(label, conn, dht)
    swarm.on('connection', (conn) => this.watchConnection(label, conn, dht))
    swarm.on('ban', (info, error) =>
      this.record('peer.ban', {
        label,
        remote: short(info.publicKey),
        reason: error?.code ?? error?.message ?? null
      })
    )
  }

  watchConnection(label, conn, dht) {
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
        path: classify(conn, dht, this.relayAddresses),
        socket: socketName(rs?.socket, dht),
        remoteAddress: rs?.connected
          ? `${rs.remoteHost}:${rs.remotePort}`
          : null,
        stats: stats()
      }
    }
    this.record('conn.open', describe())
    conn.rawStream?.on('remote-changed', () =>
      this.record('conn.upgrade', describe())
    )
    conn.on('error', (error) => this.error('conn', error, { label, remote }))
    conn.on('close', () =>
      this.record('conn.close', {
        label,
        remote,
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
    base.on('error', (error) => this.error('autobase', error, { label }))
  }

  epochStatus(status) {
    this.record('epoch.status', {
      epoch: short(status.epoch),
      seq: status.seq,
      legacy: status.legacy,
      canRead: status.canRead,
      revoked: status.revoked,
      members: status.members,
      uncovered: status.uncovered
    })
  }

  close() {
    if (this.closed) return
    this.closed = true
    fs.closeSync(this.fd)
  }
}
