import BlindRelay from 'blind-relay'
import HyperDHT from 'hyperdht'
import createTestnet from 'hyperdht/testnet'

import guard from './guard.cjs'

/**
 * A private hyperdht testnet on the loopback: `size` persistent, unfirewalled
 * bootstrap nodes. `bootstrap` is what every peer must be given.
 * @returns {Promise<{ nodes: Array, bootstrap: Array<{ host: string, port: number }>, destroy: () => Promise<void> }>}
 */
export const startTestnet = async ({
  size = 3,
  host = '127.0.0.1',
  port = 0
} = {}) => {
  const testnet = await createTestnet(size, { host, port })
  return testnet
}

/**
 * A local blind relay on its own DHT node, registered with the guard so a
 * peer may name it in `relayThrough`.
 * @returns {Promise<{ publicKey: Buffer, addresses: Set<string>, dht: object, destroy: () => Promise<void> }>}
 */
export const startRelay = async (testnet) => {
  const dht = testnet.createNode({ ephemeral: false, firewalled: false })
  await dht.fullyBootstrapped()
  const keyPair = HyperDHT.keyPair()
  const server = new BlindRelay.Server({
    createStream: (opts) => dht.createRawStream(opts)
  })
  const listener = dht.createServer((socket) => {
    server.accept(socket, { id: socket.remotePublicKey })
  })
  await listener.listen(keyPair)
  guard.allowRelay(keyPair.publicKey)
  const address = dht.io.serverSocket.address()
  return {
    publicKey: keyPair.publicKey,
    addresses: new Set([`${address.host}:${address.port}`]),
    dht,
    server,
    destroy: async () => {
      await listener.close()
      await server.close()
      // the testnet owns `dht` and destroys it
    }
  }
}
