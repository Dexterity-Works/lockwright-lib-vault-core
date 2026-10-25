import guard from './guard.cjs'
import { createNetwork, waitFor } from './harness.js'

const TOTAL = 200
const SWITCH_AT = 50

const hex = (key) => Buffer.from(key).toString('hex')

const count = (tracer, event, where = {}) =>
  tracer.events.filter(
    (e) =>
      e.event === event && Object.entries(where).every(([k, v]) => e[k] === v)
  ).length

describe('vault switch mid-sync (lifecycle)', () => {
  let net = null

  afterEach(async () => {
    await net?.destroy()
    net = null
  })

  // A and B share vault-1, A and C share vault-2. B floods vault-1 with
  // TOTAL records; mid-way A switches to vault-2 (initActiveVaultInstance
  // closes the previous instance), writes there while C does too, then
  // switches back and must converge on all of B's records. Every switch
  // must leave nothing of the old instance behind: swarm, DHT and UDX
  // sockets closed, connections closed, listeners gone, and the new
  // instance joined to its own topic only with the same listener count as
  // the first open. Records never cross vaults.
  test('A switches to vault-2 while B floods vault-1, and back', async () => {
    net = await createNetwork({ peers: ['A', 'B', 'C'] })
    const { A, B, C } = net.peers
    const tracer = net.tracers.A

    // What a freshly opened instance looks like, measured once.
    let shape = null
    const measure = (peer) => ({
      update: peer.instance.listenerCount('update'),
      baseUpdate: peer.instance.base.listenerCount('update'),
      topics: [...peer.instance.swarm.topics()].length
    })

    // Live connections of the current swarm must account for every open
    // the trace has not seen closed yet: nothing of an old swarm lingers.
    const connsBalanced = (peer) =>
      waitFor(
        () =>
          count(tracer, 'conn.open', { label: 'vault' }) -
            count(tracer, 'conn.close', { label: 'vault' }) ===
          peer.instance.swarm.connections.size,
        { label: `${peer.id} conn.open - conn.close = live connections` }
      )

    // After a switch: the old instance is gone for good, the new one is
    // the same shape as the first.
    const assertSwitched = async (peer, old, destroys) => {
      expect(old.instance.closed).toBe(true)
      expect(old.instance.swarm.destroyed).toBe(true)
      expect(old.instance.swarm.dht.destroyed).toBe(true)
      expect(old.instance.swarm.connections.size).toBe(0)
      expect(old.instance.listenerCount('update')).toBe(0)
      const { io } = old.instance.swarm.dht
      for (const socket of [io.serverSocket, io.clientSocket]) {
        expect(socket.closing).toBe(true)
        expect(guard.liveSockets()).not.toContain(socket)
      }
      expect(count(tracer, 'swarm.destroy', { label: 'vault' })).toBe(destroys)
      expect(peer.instance).not.toBe(old.instance)
      expect(peer.instance.swarm.destroyed).toBe(false)
      const topics = [...peer.instance.swarm.topics()].map((d) => hex(d.topic))
      expect(topics).toContain(hex(peer.instance.discoveryKey))
      expect(topics).not.toContain(old.topic)
      expect(measure(peer)).toEqual(shape)
      await connsBalanced(peer)
    }
    const snapshot = (peer) => ({
      instance: peer.instance,
      topic: hex(peer.instance.discoveryKey)
    })

    // vault-1: A and B.
    await A.createVault({ id: 'vault-1' })
    await B.pair(await A.invite())
    for (const peer of [A, B]) {
      await waitFor(async () => (await peer.devices()).length === 2, {
        label: `${peer.id} sees both vault-1 devices`
      })
    }
    const v1 = { id: A.vaultId, encryptionKey: A.encryptionKey }
    shape = measure(A)
    expect(shape.topics).toBe(1)
    A.trace('shape', shape)

    // vault-2: A and C. createVault switches A off vault-1.
    let old = snapshot(A)
    await A.createVault({ id: 'vault-2' })
    await assertSwitched(A, old, 1)
    await C.pair(await A.invite())
    for (const peer of [A, C]) {
      await waitFor(async () => (await peer.devices()).length === 2, {
        label: `${peer.id} sees both vault-2 devices`
      })
    }
    const v2 = { id: A.vaultId, encryptionKey: A.encryptionKey }
    expect(v2.id).not.toBe(v1.id)

    // Back to vault-1 before the flood.
    old = snapshot(A)
    await A.switchVault(v1)
    await assertSwitched(A, old, 2)
    await waitFor(async () => (await A.devices()).length === 2, {
      label: 'A reads vault-1 again'
    })
    const socketsBefore = guard.liveSockets().length
    A.trace('sockets', { live: socketsBefore, when: 'before' })

    // B floods vault-1.
    let floodError = null
    const flood = (async () => {
      for (let i = 0; i < TOTAL; i++) await B.add(`note/${i}`, { i })
    })().catch((error) => {
      floodError = error
    })
    await waitFor(async () => (await A.list('note/')).length >= SWITCH_AT, {
      label: `A received ${SWITCH_AT} of B's records`
    })

    // Mid-flood: A goes to vault-2, writes, C writes, both converge.
    old = snapshot(A)
    await A.switchVault(v2)
    await assertSwitched(A, old, 3)
    expect(await A.list('note/')).toEqual([])
    for (let i = 0; i < 5; i++) await A.add(`v2/a-${i}`, { i, from: 'A' })
    for (let i = 0; i < 5; i++) await C.add(`v2/c-${i}`, { i, from: 'C' })
    for (const peer of [A, C]) {
      await waitFor(async () => (await peer.list('v2/')).length === 10, {
        label: `${peer.id} has every vault-2 record`
      })
    }
    expect(await A.list('note/')).toEqual([])

    // Back to vault-1: converge on all of B's records.
    old = snapshot(A)
    await A.switchVault(v1)
    await assertSwitched(A, old, 4)
    await flood
    expect(floodError).toBeNull()
    expect(
      await waitFor(
        async () => {
          const rows = await A.list('note/')
          return rows.length === TOTAL ? rows : false
        },
        { label: `A has all ${TOTAL} records` }
      )
    ).toHaveLength(TOTAL)
    expect((await B.list('note/')).length).toBe(TOTAL)

    // Records never cross vaults.
    expect(await A.list('v2/')).toEqual([])
    expect(await B.list('v2/')).toEqual([])
    expect(await C.list('note/')).toEqual([])
    expect((await C.list('v2/')).length).toBe(10)

    // A switch cycle leaves the process with the sockets it had.
    const socketsAfter = await waitFor(
      () => {
        const live = guard.liveSockets().length
        return live === socketsBefore ? live : false
      },
      { timeout: 10000, label: `live UDX sockets back to ${socketsBefore}` }
    )
    A.trace('sockets', { live: socketsAfter, when: 'after' })
    expect(socketsAfter).toBe(socketsBefore)

    // Trace: four switches of the vault label, every open closed, once.
    expect(count(tracer, 'peer.switchVault')).toBe(3)
    expect(count(tracer, 'swarm.create', { label: 'vault' })).toBe(5)
    expect(count(tracer, 'swarm.destroy', { label: 'vault' })).toBe(4)
    await connsBalanced(A)
  })
})
