// Run by timeline.test.js in a child jest: a network test that fails on
// purpose, so the harness has to leave a timeline behind.
import { createNetwork } from '../harness.js'

describe('forced failure', () => {
  let net = null
  afterEach(async () => {
    await net?.destroy()
  })
  test('fails after creating a vault', async () => {
    net = await createNetwork({ peers: ['A', 'B'] })
    await net.peers.A.createVault({ id: 'doomed' })
    expect(await net.peers.A.get('vault')).toEqual({ id: 'nothing-like-it' })
  })
})
