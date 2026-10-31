import { EventEmitter } from 'events'
import fs from 'fs'
import os from 'os'
import path from 'path'

import { openTraceFile } from './file.js'
import { configureTrace, getTracer, trace } from './index.js'
import { networkCreated, networkOptions } from '../utils/swarm'

jest.mock('bare-fs', () => jest.requireActual('fs'))

// Enough of a Hyperswarm for the tracer to instrument.
const fakeSwarm = () => {
  const swarm = new EventEmitter()
  const dht = {
    bootstrapNodes: [],
    stats: { punches: {}, relaying: {} },
    destroyed: false,
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
      'conn.attempt'
    ])
    expect(lines.at(-1)).toMatchObject({
      label: 'personalSwarm',
      remote: '02020202',
      relayed: true
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
})
