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

    // Not pinned to A's epoch id: B may rotate for the same removal at the
    // same time (seen under 200 ms latency in the lab), and both then settle
    // on a later epoch with the same two members.
    const members = ['device-A', 'device-B']
    const settled = await waitFor(
      async () => {
        const status = await B.epochStatus()
        return status.canRead &&
          status.epoch !== first.id &&
          JSON.stringify(status.members) === JSON.stringify(members)
          ? status
          : false
      },
      { label: 'B holds the epoch without C' }
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
    expect(status).toMatchObject({ epoch: settled.epoch, canRead: false })
    // C holds the row itself, so the null read below is a key it lacks, not
    // a block it has not synced.
    const stored = await waitFor(() => C.raw('note/after'), {
      label: 'C holds the sealed row'
    })
    expect(stored.value).not.toContain('members only')
    expect(await C.get('note/after')).toBeNull()
    expect(await C.get('note/before')).toMatchObject({ text: 'everyone' })

    const rows = (await A.devices()).map((d) => d.id).sort()
    expect(rows).toEqual(['device-A', 'device-B'])
  })
})
