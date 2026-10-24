import DHT from 'hyperdht'

import { networkCreated, networkOptions } from './swarm'

let sharedDHT = null

export const getSharedDHT = () => {
  if (!sharedDHT) {
    sharedDHT = networkCreated('sharedDHT', new DHT(networkOptions()))
  }
  return sharedDHT
}

export const destroySharedDHT = async () => {
  if (sharedDHT) {
    try {
      await sharedDHT.destroy()
    } catch {}
    sharedDHT = null
  }
}
