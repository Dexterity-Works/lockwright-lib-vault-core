jest.mock('hyperdht', () =>
  jest.fn().mockImplementation(() => ({
    destroy: jest.fn().mockResolvedValue(undefined)
  }))
)

import DHT from 'hyperdht'

import { destroySharedDHT, getSharedDHT } from './dht'
import { setNetworkOverrides } from './swarm'

describe('getSharedDHT', () => {
  afterEach(async () => {
    await destroySharedDHT()
    setNetworkOverrides(null)
    jest.clearAllMocks()
  })

  test('builds the DHT with no options by default and reuses it', () => {
    const dht = getSharedDHT()

    expect(getSharedDHT()).toBe(dht)
    expect(DHT).toHaveBeenCalledTimes(1)
    expect(DHT.mock.calls[0][0]).toBeUndefined()
  })

  test('passes the overridden bootstrap and reports the DHT', () => {
    const onCreate = jest.fn()
    const bootstrap = [{ host: '127.0.0.1', port: 49737 }]
    setNetworkOverrides({ bootstrap, onCreate })

    const dht = getSharedDHT()

    expect(DHT).toHaveBeenCalledWith({ bootstrap })
    expect(onCreate).toHaveBeenCalledWith('sharedDHT', dht)
  })

  test('destroySharedDHT destroys and forgets the instance', async () => {
    const dht = getSharedDHT()

    await destroySharedDHT()

    expect(dht.destroy).toHaveBeenCalled()
    expect(getSharedDHT()).not.toBe(dht)
  })
})
