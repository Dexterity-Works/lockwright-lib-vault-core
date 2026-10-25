import { createNetwork, shareVault, waitFor } from './harness.js'

// Extension: ten peers in one process. Each has its own module registry,
// Corestore, master vault, swarms and DHT; pairing is serial (one invite
// at a time), the writes and the reads are not.
const PEERS = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J']

describe('ten peers over a local testnet', () => {
  let net = null

  afterEach(async () => {
    await net?.destroy()
    net = null
  })

  test('every peer pairs, every write reaches every peer', async () => {
    net = await createNetwork({ peers: PEERS, size: 6, name: 'ten' })
    await shareVault(net)
    for (const peer of net.list)
      await peer.add(`note/${peer.id}`, { from: peer.id })
    for (const peer of net.list) {
      await waitFor(
        async () => (await peer.list('note/')).length === PEERS.length,
        {
          timeout: 60000,
          label: `${peer.id} holds all ${PEERS.length} notes`
        }
      )
    }
    const seen = await net.peers.J.list('note/')
    expect(seen.map((r) => r.from).sort()).toEqual(PEERS)
    const connections = net.list.map((p) => p.instance.swarm.connections.size)
    expect(Math.min(...connections)).toBeGreaterThan(0)
  }, 300000)
})
