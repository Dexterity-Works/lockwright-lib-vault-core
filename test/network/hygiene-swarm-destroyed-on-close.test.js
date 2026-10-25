import guard from './guard.cjs'
import { createNetwork, waitFor } from './harness.js'
import { short } from './tracer.js'

// Every live UDX socket with the swarm (or testnet node) that owns its UDX
// instance, so a leftover can be named: `A:vault 127.0.0.1:41234`.
const describeSockets = (net, swarms) => {
  const owners = new Map()
  for (const node of net.testnet.nodes) owners.set(node.udx, 'testnet')
  for (const { owner, swarm } of swarms) owners.set(swarm.dht.udx, owner)
  return guard.liveSockets().map((socket) => {
    const address = socket.address()
    return {
      owner: owners.get(socket.udx) ?? 'unknown',
      address: address ? `${address.host}:${address.port}` : 'unbound',
      streams: socket.streams.size
    }
  })
}

const peerSockets = (net, swarms) =>
  describeSockets(net, swarms).filter((s) => s.owner !== 'testnet')

// Active libuv handles and timers by type. UDX sockets are native and do
// not show here; guard.liveSockets() counts those.
const resources = () => {
  const byType = {}
  for (const type of process.getActiveResourcesInfo()) {
    byType[type] = (byType[type] ?? 0) + 1
  }
  return byType
}
const untimed = (byType) =>
  Object.fromEntries(
    Object.entries(byType).filter(([t]) => t !== 'Timeout' && t !== 'Immediate')
  )

const count = (tracer, event, label) =>
  tracer.events.filter((e) => e.event === event && e.label === label).length

const expectSwarmGone = (swarm) => {
  expect(swarm.destroyed).toBe(true)
  expect(swarm.dht.destroyed).toBe(true)
  expect(swarm.connections.size).toBe(0)
  expect([...swarm.topics()]).toHaveLength(0)
  expect(swarm.dht.io.serverSocket.closing).toBe(true)
  expect(swarm.dht.io.clientSocket.closing).toBe(true)
  expect(guard.liveSockets().filter((s) => s.udx === swarm.dht.udx)).toEqual([])
}

describe('a closed vault leaves no swarm behind', () => {
  let net = null

  afterEach(async () => {
    await net?.destroy()
    net = null
  })

  test('close on B, then closeAllInstances on both: sockets back to the testnet', async () => {
    // Every swarm the seam hands out, by `<peer>:<label>`; the pairer sets
    // its own `swarm` to null once paired, so take it at ready().
    const swarms = []
    net = await createNetwork({
      peers: ['A', 'B'],
      onCreate: (label, instance, peer) => {
        const owner = `${peer.id}:${
          label === 'autopass' ? (peer.started ? 'vault' : 'master') : label
        }`
        instance
          .ready()
          .then(() => {
            if (instance.swarm) swarms.push({ owner, swarm: instance.swarm })
          })
          .catch(() => {})
      }
    })
    const { A, B } = net.peers
    const testnetSockets = describeSockets(net, swarms).filter(
      (s) => s.owner === 'testnet'
    ).length
    // Two masters, each a DHT with a server and a client socket.
    const beforeVault = guard.liveSockets().length
    const handlesBeforeVault = resources()
    expect(peerSockets(net, swarms)).toHaveLength(4)

    await A.createVault({ id: 'shared' })
    await B.pair(await A.invite())
    for (const peer of net.list) {
      await waitFor(async () => (await peer.devices()).length === 2, {
        label: `${peer.id} sees both device rows`
      })
    }
    const swarmOf = (owner) => swarms.find((s) => s.owner === owner)?.swarm
    const pairer = swarmOf('B:pairer')
    const vaultA = swarmOf('A:vault')
    const vaultB = swarmOf('B:vault')
    expect(pairer).toBeDefined()
    expect(vaultA).toBeDefined()
    expect(vaultB).toBeDefined()
    expect(vaultB).not.toBe(pairer)

    // The pairer's swarm went into the paired Autopass, which pearpassPairer
    // closes before returning the encryption key: destroyed, topic gone.
    expectSwarmGone(pairer)
    expect(count(net.tracers.B, 'swarm.destroy', 'pairer')).toBe(1)
    expect(count(net.tracers.B, 'conn.close', 'pairer')).toBe(
      count(net.tracers.B, 'conn.open', 'pairer')
    )

    const afterPair = guard.liveSockets().length
    const handlesAfterPair = resources()
    expect(afterPair).toBeGreaterThan(beforeVault)
    expect(vaultB.connections.size).toBe(1)
    expect(vaultA.connections.size).toBe(1)
    const remoteB = short(vaultB.keyPair.publicKey)

    await B.closeVault()
    expect(B.instance).toBeNull()
    expectSwarmGone(vaultB)
    expect(count(net.tracers.B, 'swarm.destroy', 'vault')).toBe(1)
    await waitFor(
      () =>
        count(net.tracers.B, 'conn.close', 'vault') ===
        count(net.tracers.B, 'conn.open', 'vault'),
      { label: "every conn.open on B's vault swarm has its conn.close" }
    )
    expect(count(net.tracers.B, 'conn.open', 'vault')).toBeGreaterThan(0)
    await waitFor(
      () =>
        net.tracers.A.events.some(
          (e) =>
            e.event === 'conn.close' &&
            e.label === 'vault' &&
            e.remote === remoteB
        ),
      { label: 'A saw the connection to B close' }
    )
    expect(vaultA.connections.size).toBe(0)
    expect(vaultA.destroyed).toBe(false)
    const handlesAfterClose = resources()
    // B is back to its master only.
    expect(
      peerSockets(net, swarms).filter((s) => s.owner.startsWith('B:'))
    ).toEqual(peerSockets(net, swarms).filter((s) => s.owner === 'B:master'))

    // lockAppSession: everything closes, the master vault too.
    await B.appDeps.closeAllInstances()
    await A.appDeps.closeAllInstances()
    for (const { swarm } of swarms) expectSwarmGone(swarm)
    expect(count(net.tracers.A, 'swarm.destroy', 'master')).toBe(1)
    expect(count(net.tracers.B, 'swarm.destroy', 'master')).toBe(1)
    // A failure prints each leftover with its owner and bound address.
    expect(peerSockets(net, swarms)).toEqual([])
    expect(guard.liveSockets()).toHaveLength(testnetSockets)
    expect(guard.liveSockets().length).toBeLessThan(beforeVault)
    // No handle outlives the swarms; timers wind down within a poll.
    expect(untimed(resources())).toEqual(untimed(handlesBeforeVault))
    await waitFor(
      () =>
        (resources().Timeout ?? 0) <= (handlesBeforeVault.Timeout ?? 0) &&
        resources(),
      { label: `timers back to the pre-vault ${handlesBeforeVault.Timeout}` }
    )
    A.trace('hygiene.sockets', {
      beforeVault,
      afterPair,
      afterCloseAll: guard.liveSockets().length,
      testnet: testnetSockets,
      handles: {
        beforeVault: handlesBeforeVault,
        afterPair: handlesAfterPair,
        afterClose: handlesAfterClose,
        afterCloseAll: resources()
      }
    })
  })
})
