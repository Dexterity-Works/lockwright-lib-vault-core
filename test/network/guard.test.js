import fs from 'fs'
import os from 'os'
import path from 'path'

import Autopass from 'autopass'
import Corestore from 'corestore'
import HyperDHT from 'hyperdht'
import createTestnet from 'hyperdht/testnet'
import Hyperswarm from 'hyperswarm'
import UDX from 'udx-native'

import {
  NetworkGuardError,
  PUBLIC_BOOTSTRAP,
  allowRelay,
  reset,
  violations
} from './guard.cjs'

// The guard is installed by test/network/jest.guard.cjs for every file in
// this project. These tests prove it fires on each way the production code,
// or a careless test, could reach the public DHT.
describe('public-DHT guard', () => {
  afterEach(() => reset())

  test('reads the public bootstrap nodes from hyperdht itself', () => {
    expect(PUBLIC_BOOTSTRAP).toEqual(HyperDHT.BOOTSTRAP)
    expect(PUBLIC_BOOTSTRAP.length).toBeGreaterThanOrEqual(3)
    for (const entry of PUBLIC_BOOTSTRAP) expect(entry).toMatch(/hyperdht\.org/)
  })

  test('a HyperDHT without an explicit bootstrap never binds', () => {
    expect(() => new HyperDHT()).toThrow(NetworkGuardError)
    expect(() => new HyperDHT({})).toThrow(/public DHT/)
    expect(() => new HyperDHT({ bootstrap: null })).toThrow(NetworkGuardError)
    expect(() => new HyperDHT({ bootstrap: undefined })).toThrow(
      NetworkGuardError
    )
    expect(violations()).toHaveLength(4)
  })

  test('the public bootstrap nodes are refused by name and by address', () => {
    expect(() => new HyperDHT({ bootstrap: HyperDHT.BOOTSTRAP })).toThrow(
      NetworkGuardError
    )
    const { ip, host } = parse(PUBLIC_BOOTSTRAP[0])
    expect(
      () => new HyperDHT({ bootstrap: [{ host: ip, port: 49737 }] })
    ).toThrow(/public hyperdht bootstrap node/)
    expect(() => new HyperDHT({ bootstrap: [`${host}:49737`] })).toThrow(
      /needs DNS/
    )
  })

  test('a non-local address is refused', () => {
    expect(
      () => new HyperDHT({ bootstrap: [{ host: '1.2.3.4', port: 1 }] })
    ).toThrow(/not local/)
    expect(
      () => new HyperDHT({ bootstrap: [{ host: '10.0.0.5', port: 1 }] })
    ).toThrow(/not local/)
  })

  test('an address this host owns counts as local', async () => {
    const os = await import('os')
    const own = Object.values(os.networkInterfaces())
      .flat()
      .find((entry) => entry.family === 'IPv4' && !entry.internal)
    if (!own) return
    const node = new HyperDHT({
      bootstrap: [{ host: own.address, port: 1 }],
      ephemeral: true
    })
    expect(node.bootstrapNodes).toEqual([{ host: own.address, port: 1 }])
    await node.destroy()
    expect(
      () => new HyperDHT({ bootstrap: [{ host: '8.8.8.8', port: 1 }] })
    ).toThrow(/not local/)
  })

  test('a Hyperswarm without a bootstrap never builds its DHT', () => {
    expect(() => new Hyperswarm()).toThrow(NetworkGuardError)
    expect(() => new Hyperswarm({ bootstrap: HyperDHT.BOOTSTRAP })).toThrow(
      NetworkGuardError
    )
  })

  test('an Autopass without a bootstrap is caught when it builds its swarm', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'guard-autopass-'))
    const store = new Corestore(dir)
    const pass = new Autopass(store)
    try {
      await expect(pass.ready()).rejects.toThrow(NetworkGuardError)
      const pair = Autopass.pair(store, 'not-an-invite')
      await expect(pair.ready()).rejects.toThrow(NetworkGuardError)
    } finally {
      await store.close()
      fs.rmSync(dir, { recursive: true, force: true })
    }
  })

  test('an isolated node and a local testnet pass', async () => {
    const isolated = new HyperDHT({ bootstrap: [] })
    const testnet = await createTestnet(2)
    const node = new HyperDHT({ bootstrap: testnet.bootstrap })
    try {
      await node.fullyBootstrapped()
      expect(node.bootstrapNodes).toEqual(testnet.bootstrap)
      expect(node.bootstrapNodes).not.toBe(HyperDHT.BOOTSTRAP)
      expect(violations()).toEqual([])
    } finally {
      await node.destroy()
      await isolated.destroy()
      await testnet.destroy()
    }
  })

  test('relayThrough must name a relay the harness started', async () => {
    const testnet = await createTestnet(1)
    const key = HyperDHT.keyPair().publicKey
    try {
      expect(
        () =>
          new Hyperswarm({ bootstrap: testnet.bootstrap, relayThrough: [key] })
      ).toThrow(/relayThrough key/)
      expect(
        () =>
          new Hyperswarm({
            bootstrap: testnet.bootstrap,
            relayThrough: () => key
          })
      ).toThrow(NetworkGuardError)
      allowRelay(key)
      const swarm = new Hyperswarm({
        bootstrap: testnet.bootstrap,
        relayThrough: [key]
      })
      await swarm.destroy()
    } finally {
      await testnet.destroy()
    }
  })

  test('a UDX socket or stream refuses to leave the loopback', async () => {
    const udx = new UDX()
    const socket = udx.createSocket()
    socket.bind(0, '127.0.0.1')
    const stream = udx.createStream(1)
    try {
      expect(() => socket.trySend(Buffer.from('x'), 53, '8.8.8.8')).toThrow(
        NetworkGuardError
      )
      await expect(
        socket.send(Buffer.from('x'), 53, '1.1.1.1')
      ).rejects.toThrow(/not a local address/)
      expect(() => stream.connect(socket, 2, 53, '9.9.9.9')).toThrow(
        NetworkGuardError
      )
      expect(() => udx.lookup('node1.hyperdht.org')).toThrow(/DNS is off/)
      socket.trySend(Buffer.from('x'), socket.address().port, '127.0.0.1')
      expect(violations().map((v) => v.message)).toEqual([
        'udx socket trySend to 8.8.8.8: not a local address',
        'udx socket send to 1.1.1.1: not a local address',
        'udx stream connect to 9.9.9.9: not a local address',
        'udx lookup of node1.hyperdht.org: DNS is off'
      ])
    } finally {
      stream.destroy()
      await socket.close()
    }
  })
})

function parse(entry) {
  const [ip, rest] = entry.split('@')
  return { ip, host: rest.slice(0, rest.lastIndexOf(':')) }
}
