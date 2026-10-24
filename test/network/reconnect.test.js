import { createNetwork, shareVault, sleep, waitFor } from './harness.js'

const allNotes = async (peer, n) => {
  const rows = await peer.list('note/')
  return rows.length === n ? rows.map((r) => r.i).sort((a, b) => a - b) : null
}

describe('reconnect after a dropped swarm', () => {
  let net = null

  afterEach(async () => {
    await net?.destroy()
    net = null
  })

  test("B's swarm dies mid-sync; B reopens and converges", async () => {
    net = await createNetwork({ peers: ['A', 'B'] })
    const { A, B } = net.peers
    await shareVault(net)

    const total = 40
    const writer = (async () => {
      for (let i = 0; i < total; i++) {
        await A.add(`note/${i}`, { i })
        await sleep(25)
      }
    })()

    await waitFor(async () => (await B.list('note/')).length >= 5, {
      label: 'B received the first notes'
    })
    const before = B.instance.swarm
    await before.destroy()
    expect(before.destroyed).toBe(true)

    await writer
    await sleep(500)
    expect((await B.list('note/')).length).toBeLessThan(total)

    await B.restartVault()
    expect(B.instance.swarm).not.toBe(before)
    expect(B.instance.swarm.destroyed).toBe(false)

    const expected = Array.from({ length: total }, (_, i) => i)
    expect(
      await waitFor(() => allNotes(B, total), { label: 'B caught up' })
    ).toEqual(expected)

    await B.add('note/from-b', { i: total })
    await waitFor(async () => (await A.get('note/from-b')) !== null, {
      label: 'A hears B again'
    })
  })
})
