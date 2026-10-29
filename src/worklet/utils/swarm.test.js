import { networkCreated, networkOptions, setNetworkOverrides } from './swarm'

describe('network seam', () => {
  afterEach(() => {
    setNetworkOverrides(null)
  })

  test('networkOptions hands the options object back untouched by default', () => {
    const options = {
      keyPair: { publicKey: Buffer.alloc(32) },
      relayThrough: []
    }
    expect(networkOptions(options)).toBe(options)
    expect(Object.keys(options)).toEqual(['keyPair', 'relayThrough'])
    expect(networkOptions(undefined)).toBeUndefined()
  })

  test('networkCreated hands the instance back and calls nothing by default', () => {
    const instance = {}
    expect(networkCreated('personalSwarm', instance)).toBe(instance)
  })

  test('overrides set the bootstrap and replace the relays, leaving the rest alone', () => {
    const bootstrap = [{ host: '127.0.0.1', port: 49737 }]
    setNetworkOverrides({ bootstrap, relayThrough: null })
    const options = { keyPair: 'kp', relayThrough: ['relay'] }
    const next = networkOptions(options)
    expect(next).toEqual({ keyPair: 'kp', relayThrough: null, bootstrap })
    expect(next).not.toBe(options)
    expect(options).toEqual({ keyPair: 'kp', relayThrough: ['relay'] })
    expect(networkOptions(undefined)).toEqual({ bootstrap, relayThrough: null })
  })

  test('an override without relayThrough keeps the relays the caller passed', () => {
    setNetworkOverrides({ bootstrap: [] })
    expect(networkOptions({ relayThrough: ['relay'] })).toEqual({
      relayThrough: ['relay'],
      bootstrap: []
    })
  })

  test('onCreate sees each instance with its label', () => {
    const onCreate = jest.fn()
    setNetworkOverrides({ onCreate })
    const instance = { swarm: true }
    expect(networkCreated('autopass', instance)).toBe(instance)
    expect(onCreate).toHaveBeenCalledWith('autopass', instance)
    expect(networkOptions({ a: 1 })).toEqual({ a: 1 })
  })

  test('setNetworkOverrides(null) and (undefined) clear the seam', () => {
    setNetworkOverrides({ bootstrap: [] })
    setNetworkOverrides(undefined)
    const options = {}
    expect(networkOptions(options)).toBe(options)
  })
})
