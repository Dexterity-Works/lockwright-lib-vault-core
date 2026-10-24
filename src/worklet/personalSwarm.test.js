import { jest } from '@jest/globals'
import Hyperswarm from 'hyperswarm'

const mockFlushed = jest.fn(() => new Promise(() => {}))
const mockJoin = jest.fn(() => ({ flushed: mockFlushed }))
const mockOn = jest.fn()
const mockDestroy = jest.fn().mockResolvedValue(undefined)

jest.mock('hyperswarm', () =>
  jest.fn().mockImplementation(() => ({
    join: mockJoin,
    on: mockOn,
    destroy: mockDestroy
  }))
)

jest.mock('./appDeps', () => ({
  getPersonalKeyPair: jest.fn().mockResolvedValue({
    publicKey: Buffer.alloc(32, 1)
  }),
  getVaultsInstance: jest.fn().mockReturnValue({
    store: {
      createKeyPair: jest.fn().mockResolvedValue({
        publicKey: Buffer.alloc(32, 2),
        secretKey: Buffer.alloc(64, 3)
      })
    }
  })
}))

jest.mock('./utils/swarm', () => ({
  ...jest.requireActual('./utils/swarm'),
  getConfig: jest.fn().mockResolvedValue({ current: { blindRelays: [] } })
}))

jest.mock('./utils/workletLogger', () => ({
  workletLogger: { error: jest.fn(), info: jest.fn(), debug: jest.fn() }
}))

import { personalSwarmClose, personalSwarmInit } from './personalSwarm'
import { setNetworkOverrides } from './utils/swarm'

describe('personalSwarmInit', () => {
  afterEach(async () => {
    await personalSwarmClose()
    jest.clearAllMocks()
  })

  test('returns without waiting for DHT flushed', async () => {
    const result = await Promise.race([
      personalSwarmInit(),
      new Promise((_, reject) =>
        setTimeout(
          () => reject(new Error('personalSwarmInit waited on flushed')),
          100
        )
      )
    ])

    expect(mockJoin).toHaveBeenCalled()
    expect(mockFlushed).toHaveBeenCalled()
    expect(result.topic).toMatch(/^[0-9a-f]{64}$/)
  })
})

describe('personalSwarmInit network seam', () => {
  afterEach(async () => {
    await personalSwarmClose()
    setNetworkOverrides(null)
    jest.clearAllMocks()
  })

  test('builds the swarm with exactly keyPair and relayThrough by default', async () => {
    await personalSwarmInit()

    expect(Hyperswarm).toHaveBeenCalledTimes(1)
    const [options] = Hyperswarm.mock.calls[0]
    expect(Object.keys(options)).toEqual(['keyPair', 'relayThrough'])
    expect(options.keyPair.publicKey).toEqual(Buffer.alloc(32, 2))
    expect(options.relayThrough).toEqual([])
  })

  test('passes the overridden bootstrap and relays and reports the swarm', async () => {
    const onCreate = jest.fn()
    const bootstrap = [{ host: '127.0.0.1', port: 49737 }]
    setNetworkOverrides({ bootstrap, relayThrough: null, onCreate })

    await personalSwarmInit()

    const [options] = Hyperswarm.mock.calls[0]
    expect(options).toEqual({
      keyPair: expect.anything(),
      relayThrough: null,
      bootstrap
    })
    expect(onCreate).toHaveBeenCalledWith(
      'personalSwarm',
      Hyperswarm.mock.results[0].value
    )
  })
})
