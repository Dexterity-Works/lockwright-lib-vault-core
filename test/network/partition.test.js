import {
  converge,
  createNetwork,
  shareVault,
  sleep,
  waitFor
} from './harness.js'

describe('concurrent writes across a partition', () => {
  let net = null

  afterEach(async () => {
    await net?.destroy()
    net = null
  })

  test('A and B write apart, then heal and agree', async () => {
    net = await createNetwork({ peers: ['A', 'B'] })
    const { A, B } = net.peers
    await shareVault(net)

    await B.goOffline()
    expect(B.instance.swarm.suspended).toBe(true)

    for (let i = 0; i < 10; i++) {
      await A.add(`note/a${i}`, { from: 'A', i })
      await B.add(`note/b${i}`, { from: 'B', i })
    }
    await A.add('contested', { from: 'A' })
    await B.add('contested', { from: 'B' })
    await sleep(500)
    expect((await A.list('note/')).length).toBe(10)
    expect((await B.list('note/')).length).toBe(10)
    expect(await A.get('contested')).toEqual({ from: 'A' })
    expect(await B.get('contested')).toEqual({ from: 'B' })

    await B.goOnline()
    expect(B.instance.swarm.suspended).toBe(false)

    for (const peer of [A, B]) {
      await waitFor(async () => (await peer.list('note/')).length === 20, {
        label: `${peer.id} holds all 20 notes`
      })
    }
    const winner = await converge([A, B], 'contested')
    expect(['A', 'B']).toContain(winner.from)
    const keysA = (await A.list('note/')).map((r) => `${r.from}${r.i}`).sort()
    const keysB = (await B.list('note/')).map((r) => `${r.from}${r.i}`).sort()
    expect(keysA).toEqual(keysB)
    expect(keysA).toHaveLength(20)
  })
})
