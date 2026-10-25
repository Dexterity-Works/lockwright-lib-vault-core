import fs from 'fs'
import os from 'os'
import path from 'path'

import { converge, createNetwork, shareVault, waitFor } from './harness.js'
import { Tracer, short } from './tracer.js'

const HEX_32 = /[0-9a-f]{64}/i
const B64_32 = /[A-Za-z0-9+/]{43}=/
const Z32_LONG = /[ybndrfg8ejkmcpqxot1uwisza345h769]{52,}/

describe('per-peer tracer', () => {
  let net = null

  afterEach(async () => {
    await net?.destroy()
    net = null
  })

  test('records the network, autobase, pairing and epoch events', async () => {
    net = await createNetwork({ peers: ['A', 'B'] })
    const { A, B } = net.peers
    await shareVault(net)
    await A.add('note/1', { text: 'traced' })
    await converge(net.list, 'note/1')
    const epoch = await A.ensureEpoch({ start: true })
    await waitFor(async () => (await B.epochStatus()).epoch === epoch.id, {
      label: 'B holds the epoch'
    })
    // Legacy statuses read fine too; wait for the one naming this epoch.
    const traced = (e) =>
      e.event === 'epoch.status' && e.epoch === short(epoch.id)
    await waitFor(() => net.tracers.B.events.some(traced), {
      label: 'B traced the epoch status'
    })

    const a = net.tracers.A.events
    const b = net.tracers.B.events
    const names = (events) => new Set(events.map((e) => e.event))

    const swarm = a.find(
      (e) => e.event === 'swarm.create' && e.label === 'vault'
    )
    expect(
      a.some((e) => e.event === 'swarm.create' && e.label === 'master')
    ).toBe(true)
    expect(swarm.bootstrap).toEqual(net.bootstrap)
    expect(typeof a.find((e) => e.event === 'dht.ready').firewalled).toBe(
      'boolean'
    )
    expect(
      a.find((e) => e.event === 'topic.join' && e.label === 'vault')
    ).toMatchObject({
      topic: short(A.instance.discoveryKey),
      server: true,
      client: true
    })
    const open = a.find((e) => e.event === 'conn.open' && e.label === 'vault')
    expect(open).toMatchObject({
      path: 'direct',
      remote: short(B.instance.swarm.keyPair.publicKey)
    })
    // hyperdht may take the LAN shortcut through one of this host's own
    // addresses; either way the packets stay on the machine.
    const own = new Set(
      Object.values(os.networkInterfaces())
        .flat()
        .map((entry) => entry.address)
    )
    const [host] = open.remoteAddress.split(':')
    expect(own.has(host) || host === '127.0.0.1').toBe(true)
    for (const name of [
      'autobase.open',
      'autobase.append',
      'autobase.update',
      'epoch.status',
      'peer.createVault',
      'peer.invite'
    ]) {
      expect(names(a)).toContain(name)
    }
    for (const name of [
      'pairing.start',
      'peer.pair',
      'peer.paired',
      'conn.open'
    ]) {
      expect(names(b)).toContain(name)
    }
    expect(b.find(traced)).toMatchObject({
      canRead: true,
      legacy: false,
      members: ['device-A', 'device-B']
    })
    for (const event of [...a, ...b]) {
      expect(typeof event.t).toBe('number')
      expect(Date.parse(event.wall)).not.toBeNaN()
    }
    const lines = fs.readFileSync(net.tracers.A.file, 'utf8').trim().split('\n')
    expect(lines).toHaveLength(a.length)
  })

  test('never writes key material', async () => {
    net = await createNetwork({ peers: ['A', 'B'] })
    const { A, B } = net.peers
    const code = await (async () => {
      await A.createVault({ id: 'shared' })
      return A.invite()
    })()
    await B.pair(code)
    await A.ensureEpoch({ start: true })
    await A.add('note/1', { text: 'sealed' })
    await converge(net.list, 'note/1')

    const secrets = []
    for (const peer of net.list) {
      secrets.push(
        peer.encryptionKey,
        peer.masterKey,
        peer.hashedPassword,
        peer.writerKey,
        peer.masterTopic,
        peer.instance.swarm.keyPair.publicKey.toString('hex'),
        peer.instance.key.toString('hex'),
        peer.instance.encryptionKey.toString('hex')
      )
    }
    secrets.push(code.split('/')[1])
    expect(secrets.every((s) => typeof s === 'string' && s.length >= 32)).toBe(
      true
    )

    const lines = net.list.flatMap((peer) =>
      net.tracers[peer.id].events.map((e) => JSON.stringify(e))
    )
    expect(lines.length).toBeGreaterThan(20)
    for (const line of lines) {
      for (const secret of secrets) expect(line).not.toContain(secret)
      expect(line).not.toMatch(HEX_32)
      expect(line).not.toMatch(B64_32)
      expect(line).not.toMatch(Z32_LONG)
    }
  })

  test('redacts sensitive field names the way the worklet logger does', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tracer-'))
    const tracer = new Tracer({ peer: 'T', file: path.join(dir, 'T.jsonl') })
    const line = tracer.record('probe', {
      encryptionKey: 'k',
      nested: { password: 'p', fine: 1 }
    })
    tracer.close()
    expect(line).toMatchObject({
      peer: 'T',
      event: 'probe',
      encryptionKey: '[REDACTED]',
      nested: { password: '[REDACTED]', fine: 1 }
    })
    expect(fs.readFileSync(tracer.file, 'utf8')).toContain('[REDACTED]')
    fs.rmSync(dir, { recursive: true, force: true })
  })
})
