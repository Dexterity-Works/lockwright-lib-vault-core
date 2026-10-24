import { converge, createNetwork, shareVault, waitFor } from './harness.js'

describe('device revoke over a local testnet (ADR 0014)', () => {
  let net = null

  afterEach(async () => {
    await net?.destroy()
    net = null
  })

  test('kicking C rotates the epoch; A and B read on, C cannot', async () => {
    net = await createNetwork({ peers: ['A', 'B', 'C'] })
    const { A, B, C } = net.peers
    await shareVault(net)

    const first = await A.ensureEpoch({ start: true })
    expect(first).toMatchObject({
      rotated: true,
      members: ['device-A', 'device-B', 'device-C']
    })
    for (const peer of [B, C]) {
      await waitFor(
        async () => {
          const status = await peer.epochStatus()
          return status.epoch === first.id && status.canRead
        },
        { label: `${peer.id} holds epoch ${first.id}` }
      )
    }

    await A.add('note/before', { text: 'everyone' })
    expect(await converge(net.list, 'note/before')).toMatchObject({
      text: 'everyone'
    })

    const kicked = await A.kick('device-C')
    expect(kicked).toMatchObject({
      rotated: true,
      members: ['device-A', 'device-B']
    })
    expect(kicked.id).not.toBe(first.id)

    await waitFor(
      async () => {
        const status = await B.epochStatus()
        return status.epoch === kicked.id && status.canRead
      },
      { label: `B holds epoch ${kicked.id}` }
    )
    await A.add('note/after', { text: 'members only' })
    expect(await converge([A, B], 'note/after')).toMatchObject({
      text: 'members only'
    })

    const status = await waitFor(
      async () => {
        const s = await C.epochStatus()
        return s.revoked ? s : false
      },
      { label: 'C learns it was revoked' }
    )
    expect(status).toMatchObject({ epoch: kicked.id, canRead: false })
    expect(await C.get('note/after')).toBeNull()
    expect(await C.get('note/before')).toMatchObject({ text: 'everyone' })

    const rows = (await A.devices()).map((d) => d.id).sort()
    expect(rows).toEqual(['device-A', 'device-B'])
  })
})
