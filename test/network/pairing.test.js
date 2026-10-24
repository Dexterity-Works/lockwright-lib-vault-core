import { createNetwork, waitFor } from './harness.js'

describe('pairing over a local testnet', () => {
  let net = null

  afterEach(async () => {
    await net?.destroy()
    net = null
  })

  test('invite on A, join on B, both see the vault and each other', async () => {
    net = await createNetwork({ peers: ['A', 'B'] })
    const { A, B } = net.peers

    await A.createVault({ id: 'shared' })
    const code = await A.invite()
    expect(code).toMatch(/^shared\/[a-z0-9]+$/)

    await B.pair(code)
    expect(B.vaultId).toBe('shared')
    expect(await B.get('vault')).toMatchObject({ id: 'shared' })

    await waitFor(async () => (await A.devices()).length === 2, {
      label: 'A sees both device rows'
    })
    await waitFor(async () => (await B.devices()).length === 2, {
      label: 'B sees both device rows'
    })
    expect((await A.devices()).map((d) => d.id).sort()).toEqual([
      'device-A',
      'device-B'
    ])
    expect(B.writerKey).not.toBe(A.writerKey)
  })
})
