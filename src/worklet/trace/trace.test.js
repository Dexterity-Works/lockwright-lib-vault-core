import { EventEmitter } from 'events'
import fs from 'fs'
import os from 'os'
import path from 'path'

import bareFs from 'bare-fs'

import { openTraceFile } from './file.js'
import { configureTrace, getTracer, trace } from './index.js'
import { Tracer } from './tracer.js'
import { networkCreated, networkOptions } from '../utils/swarm'

jest.mock('bare-fs', () => jest.requireActual('fs'))

// Enough of a Hyperswarm for the tracer to instrument.
const fakeSwarm = () => {
  const swarm = new EventEmitter()
  const dht = {
    bootstrapNodes: [],
    stats: { punches: {}, relaying: {} },
    destroyed: false,
    io: { serverSocket: { name: 'server' }, clientSocket: { name: 'client' } },
    _socketPool: { lookup: () => false },
    connect: () => new EventEmitter(),
    fullyBootstrapped: () => new Promise(() => {}),
    address: () => null
  }
  Object.assign(swarm, {
    dht,
    keyPair: { publicKey: Buffer.alloc(32, 1) },
    connections: new Set(),
    peers: new Map(),
    stats: { connects: { client: {}, server: {} } },
    topics: () => [],
    join: () => ({}),
    leave: () => {},
    suspend: () => {},
    resume: () => {},
    destroy: () => {}
  })
  return swarm
}

const methods = (swarm) => ({
  join: swarm.join,
  leave: swarm.leave,
  suspend: swarm.suspend,
  resume: swarm.resume,
  destroy: swarm.destroy,
  connect: swarm.dht.connect,
  listeners: swarm.eventNames()
})

describe('worklet trace switch', () => {
  let dir = null

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'trace-'))
  })

  afterEach(async () => {
    await configureTrace({ traceFile: null })
    fs.rmSync(dir, { recursive: true, force: true })
  })

  test('with no traceFile nothing is attached and builder options are unchanged', async () => {
    await configureTrace({})
    await configureTrace({ traceFile: undefined })
    expect(getTracer()).toBeNull()
    expect(trace('anything', { a: 1 })).toBeNull()

    const options = { relayThrough: ['relay'], keyPair: { publicKey: 'k' } }
    expect(networkOptions(options)).toBe(options)
    expect(options).toEqual({
      relayThrough: ['relay'],
      keyPair: { publicKey: 'k' }
    })

    const swarm = fakeSwarm()
    const before = methods(swarm)
    expect(networkCreated('personalSwarm', swarm)).toBe(swarm)
    expect(methods(swarm)).toEqual(before)

    const autopass = { ready: jest.fn(() => Promise.resolve()) }
    expect(networkCreated('autopass', autopass, 'vault')).toBe(autopass)
    expect(autopass.ready).not.toHaveBeenCalled()
  })

  test('a traceFile attaches the tracer until it is set to null', async () => {
    const file = path.join(dir, 'laptop.jsonl')
    await configureTrace({ traceFile: file })
    expect(getTracer()).not.toBeNull()

    const swarm = fakeSwarm()
    const before = methods(swarm)
    const options = { relayThrough: null }
    expect(networkOptions(options)).toBe(options)
    networkCreated('personalSwarm', swarm)
    expect(swarm.join).not.toBe(before.join)
    expect(swarm.dht.connect).not.toBe(before.connect)
    swarm.dht.connect(Buffer.alloc(32, 2), { relayThrough: () => null })
    swarm.dht.connect(Buffer.alloc(32, 2), { relayThrough: [] })
    swarm.dht.connect(Buffer.alloc(32, 2), {
      relayThrough: [Buffer.alloc(32, 7)]
    })
    swarm.dht.connect(Buffer.alloc(32, 2), { relayThrough: null })

    await configureTrace({ traceFile: null })
    expect(getTracer()).toBeNull()
    const lines = fs
      .readFileSync(file, 'utf8')
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line))
    expect(lines.map((e) => e.event)).toEqual([
      'trace.start',
      'swarm.create',
      'dht.create',
      'dht.stats',
      'swarm.stats',
      'swarm.peers',
      'conn.attempt',
      'conn.attempt',
      'conn.attempt',
      'conn.attempt'
    ])
    expect(lines.slice(-4).map((e) => e.relayed)).toEqual([
      null,
      false,
      true,
      false
    ])
    expect(lines.at(-1)).toMatchObject({
      label: 'personalSwarm',
      remote: '02020202'
    })
    expect(lines[1].key).toBe('01010101')
  })

  test('the trace file rotates at its size cap, keeping one previous file', () => {
    const file = path.join(dir, 'trace.jsonl')
    const sink = openTraceFile(file, { maxSize: 100 })
    for (let i = 0; i < 12; i++) sink.write(`${'x'.repeat(19)}\n`)
    sink.close()
    expect(fs.statSync(file).size).toBeLessThanOrEqual(100)
    expect(fs.statSync(`${file}.1`).size).toBe(100)
  })

  test('scrubs key-length runs from any string a caller passes', async () => {
    const file = path.join(dir, 'trace.jsonl')
    await configureTrace({ traceFile: file })
    const hex = 'ab'.repeat(32)
    const line = trace('probe', {
      where: `failed for ${hex}`,
      inviteCode: 'secret',
      nested: { b64: `${'Q'.repeat(43)}=` }
    })
    expect(JSON.stringify(line)).not.toContain(hex)
    expect(line).toMatchObject({
      where: 'failed for [REDACTED]',
      inviteCode: '[REDACTED]',
      nested: { b64: '[REDACTED]' }
    })
  })

  test('a failed rotation stops the trace and never closes a reused fd', () => {
    const file = path.join(dir, 'trace.jsonl')
    fs.mkdirSync(`${file}.1`)
    const closeSync = jest.spyOn(bareFs, 'closeSync')
    try {
      const sink = openTraceFile(file, { maxSize: 10 })
      expect(() => {
        sink.write('0123456789\n')
        sink.write('rotates, fails\n')
        sink.write('dropped\n')
        sink.close()
      }).not.toThrow()
      expect(closeSync).toHaveBeenCalledTimes(1)
      expect(fs.readFileSync(file, 'utf8')).toBe('0123456789\n')
    } finally {
      closeSync.mockRestore()
    }
  })
})

describe('worklet tracer', () => {
  const memoryTracer = () =>
    new Tracer({ sink: { write: () => {} }, keepEvents: true })

  test('adds no error listener to an autobase or a connection', () => {
    const tracer = memoryTracer()
    const base = Object.assign(new EventEmitter(), {
      getLastError: () => null
    })
    tracer.attachBase('vault', base)
    expect(base.listenerCount('error')).toBe(0)

    const swarm = fakeSwarm()
    tracer.attachSwarm('vault', swarm)
    const conn = Object.assign(new EventEmitter(), {
      remotePublicKey: Buffer.alloc(32, 3)
    })
    swarm.emit('connection', conn)
    expect(conn.listenerCount('error')).toBe(0)
    expect(swarm.listenerCount('error')).toBe(0)

    // A fatal error is read when the base closes.
    const fatal = Object.assign(new Error('boom'), { code: 'FATAL' })
    base.getLastError = () => fatal
    base.emit('close')
    expect(tracer.events.at(-1)).toMatchObject({
      event: 'error',
      where: 'autobase.close',
      code: 'FATAL'
    })
    tracer.close()
  })

  test('learns relay addresses at runtime and never calls a ridden stream direct', () => {
    const relayKey = Buffer.alloc(32, 9)
    const peerKey = Buffer.alloc(32, 4)
    const otherKey = Buffer.alloc(32, 5)
    const stream = (key, host, port, socket) =>
      Object.assign(new EventEmitter(), {
        remotePublicKey: key,
        rawStream: Object.assign(new EventEmitter(), {
          connected: true,
          remoteHost: host,
          remotePort: port,
          socket
        })
      })
    const run = (relayThrough) => {
      const tracer = memoryTracer()
      const swarm = fakeSwarm()
      swarm.relayThrough = relayThrough
      const dials = []
      swarm.dht.connect = (key) => {
        const conn = stream(key, '10.0.0.9', 4000, swarm.dht.io.clientSocket)
        dials.push(conn)
        return conn
      }
      tracer.attachSwarm('vault', swarm)
      // hyperdht dials the relay itself, then the app stream rides it.
      swarm.dht.connect(relayKey)
      dials[0].emit('open')
      // The app's own dial to the peer opens on the relay's address before
      // hyperswarm hands it out as a connection.
      const peer = swarm.dht.connect(peerKey)
      peer.emit('open')
      swarm.emit('connection', peer)
      swarm.emit(
        'connection',
        stream(otherKey, '10.0.0.7', 5000, swarm.dht.io.serverSocket)
      )
      tracer.close()
      return tracer.events.filter((e) => e.event === 'conn.open')
    }

    const known = run(() => [relayKey])
    expect(known.map((e) => e.path)).toEqual(['relayed', 'direct'])
    // A relay the tracer cannot name: unknown, not direct.
    const unnamed = run(null)
    expect(unnamed.map((e) => e.path)).toEqual(['unknown', 'direct'])
  })

  test('cuts UUIDs and absolute paths in any string', () => {
    const tracer = memoryTracer()
    const uuid = '3f2c9a71-5b6e-4d2a-9c1f-7e8d6b5a4c3b'
    const line = tracer.error(
      'open',
      new Error(
        `ENOENT: no such file, open '/home/someone/Lockwright/vault/${uuid}/db' and C:\\Users\\someone\\trace.jsonl`
      )
    )
    expect(line.message).toBe("ENOENT: no such file, open 'db' and trace.jsonl")
    expect(tracer.record('probe', { id: uuid }).id).toBe('3f2c9a71')
    tracer.close()
  })

  test('the sample timer stops with its last sampler and starts again', () => {
    jest.useFakeTimers()
    try {
      const tracer = memoryTracer()
      const first = fakeSwarm()
      tracer.attachSwarm('vault', first)
      expect(tracer.timer).not.toBeNull()
      first.destroyed = true
      first.dht.destroyed = true
      jest.advanceTimersByTime(500)
      expect(tracer.samplers.size).toBe(0)
      expect(tracer.timer).toBeNull()
      expect(jest.getTimerCount()).toBe(0)
      tracer.attachSwarm('personalSwarm', fakeSwarm())
      expect(tracer.timer).not.toBeNull()
      tracer.close()
      expect(jest.getTimerCount()).toBe(0)
    } finally {
      jest.useRealTimers()
    }
  })
})
