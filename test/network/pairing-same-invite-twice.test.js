import { createNetwork, pairOrCancel, waitFor } from './harness.js'

// One invite, two joiners. autopass deletes the invite after the first
// confirmed join (member onadd, autopass/index.js:332-348), so a request
// that arrives later is never answered and lib-vault's timeout cancels it.

const of = (net, peer, event, where = {}) =>
  net.tracers[peer].events.filter(
    (e) =>
      e.event === event && Object.entries(where).every(([k, v]) => e[k] === v)
  )

const members = (peer) => peer.instance.base.system.members

const pairingTimeout = 8000

const seesDevices = async (peers, n) => {
  for (const peer of peers) {
    await waitFor(async () => (await peer.devices()).length === n, {
      label: `${peer.id} sees ${n} device rows`
    })
  }
}

// A joiner that lost: never paired, cancelled, pairer swarm gone.
const expectCancelled = (net, peer, result) => {
  expect(result.paired).toBe(false)
  expect(result.error.message).toMatch(/Pairing closed/)
  expect(peer.vaultId).toBeNull()
  expect(peer.appDeps.getActiveVaultInstance()).toBeFalsy()
  expect(of(net, peer.id, 'peer.paired')).toHaveLength(0)
  expect(of(net, peer.id, 'autobase.writable')).toHaveLength(0)
  expect(of(net, peer.id, 'peer.pairTimeout')).toHaveLength(1)
  expect(of(net, peer.id, 'swarm.destroy', { label: 'pairer' })).toHaveLength(1)
  expect(of(net, peer.id, 'error', { where: 'peer.pair' })).toHaveLength(1)
}

describe('two joiners on the same invite', () => {
  let net = null

  afterEach(async () => {
    await net?.destroy()
    net = null
  })

  // Finding P1: both concurrent joiners are accepted on one invite. The
  // member's onadd reads the invite row, then awaits add-writer and confirm
  // before del-invite (autopass/index.js:334-348); a second request that
  // lands in that window still finds the row. Single use holds only once
  // the first join has been applied.
  test.failing('concurrent: exactly one of B and C is accepted', async () => {
    net = await createNetwork({ peers: ['A', 'B', 'C'] })
    const { A, B, C } = net.peers
    await A.createVault({ id: 'shared' })
    const code = await A.invite()

    const results = await Promise.all([
      pairOrCancel(B, code, { timeout: pairingTimeout }),
      pairOrCancel(C, code, { timeout: pairingTimeout })
    ])
    expect(results.filter((r) => r.paired)).toHaveLength(1)
  })

  test('concurrent: the roster and the writer set match the joins', async () => {
    net = await createNetwork({ peers: ['A', 'B', 'C'] })
    const { A, B, C } = net.peers
    await A.createVault({ id: 'shared' })
    const code = await A.invite()

    const [b, c] = await Promise.all([
      pairOrCancel(B, code, { timeout: pairingTimeout }),
      pairOrCancel(C, code, { timeout: pairingTimeout })
    ])
    const joined = [B, C].filter((p, i) => [b, c][i].paired)
    const left = [B, C].filter((p, i) => ![b, c][i].paired)
    // eslint-disable-next-line no-console
    console.log(
      `same invite twice: ${joined.map((p) => p.id).join('+') || 'nobody'} joined`
    )
    expect(joined.length).toBeGreaterThanOrEqual(1)
    expect(of(net, 'A', 'peer.invite')).toHaveLength(1)
    for (const peer of joined) {
      expect(of(net, peer.id, 'peer.paired')).toHaveLength(1)
      expect(peer.vaultId).toBe('shared')
    }
    for (const peer of left) {
      expectCancelled(net, peer, peer === B ? b : c)
    }
    const n = 1 + joined.length
    await seesDevices([A, ...joined], n)
    expect((await A.devices()).map((d) => d.id).sort()).toEqual(
      ['device-A', ...joined.map((p) => `device-${p.id}`)].sort()
    )
    await waitFor(() => members(A) === n, { label: `A counts ${n} writers` })

    for (const peer of left) await peer.pair(await A.invite())
    await seesDevices(net.list, 3)
    await waitFor(() => members(A) === 3, { label: 'A counts three writers' })
  })

  test('sequential: the second joiner on a spent invite is cancelled, then pairs anew', async () => {
    net = await createNetwork({ peers: ['A', 'B', 'C'] })
    const { A, B, C } = net.peers
    await A.createVault({ id: 'shared' })
    const code = await A.invite()

    await B.pair(code)
    await seesDevices([A, B], 2)
    await waitFor(() => members(A) === 2, { label: 'A counts two writers' })

    const c = await pairOrCancel(C, code, { timeout: pairingTimeout })
    expectCancelled(net, C, c)
    expect(of(net, 'C', 'conn.open', { label: 'pairer' })).not.toHaveLength(0)
    expect((await A.devices()).map((d) => d.id).sort()).toEqual([
      'device-A',
      'device-B'
    ])
    expect(members(A)).toBe(2)
    expect(of(net, 'A', 'peer.invite')).toHaveLength(1)

    await C.pair(await A.invite())
    await seesDevices(net.list, 3)
    expect(of(net, 'C', 'peer.paired')).toHaveLength(1)
    expect(of(net, 'A', 'peer.invite')).toHaveLength(2)
    await waitFor(() => members(A) === 3, { label: 'A counts three writers' })
  })
})
