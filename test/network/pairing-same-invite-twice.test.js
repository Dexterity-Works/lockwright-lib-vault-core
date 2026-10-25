import {
  createNetwork,
  inviteRow,
  members,
  of,
  pairOrCancel,
  waitFor
} from './harness.js'

// One invite, two joiners. autopass deletes the invite after the first
// confirmed join (member onadd, autopass/index.js:332-349), so a request
// that is read after that delete is never answered and lib-vault's timeout
// cancels it.

const pairingTimeout = 8000

const seesDevices = async (peers, n) => {
  for (const peer of peers) {
    await waitFor(async () => (await peer.devices()).length === n, {
      label: `${peer.id} sees ${n} device rows`
    })
  }
}

/**
 * Hold `peer`'s member onadd until requests from `n` pairing sessions have
 * entered it, then let them all through in the same tick, so every one of
 * them reads the invite row before any del-invite is appended. Bounded: on
 * `timeout` the held calls go through and `met` stays false.
 */
const holdOnadd = (peer, { n = 2, timeout = 10000 } = {}) => {
  const member = peer.instance.member
  const onadd = member.onadd
  const sessions = new Set()
  let release
  const released = new Promise((resolve) => {
    release = resolve
  })
  const timer = setTimeout(release, timeout)
  const gate = {
    met: false,
    sessions,
    restore: () => {
      clearTimeout(timer)
      release()
      member.onadd = onadd
    }
  }
  member.onadd = async (request) => {
    const session = Buffer.from(request.requestData.session).toString('hex')
    sessions.add(session)
    peer.trace('test.onadd', { n: sessions.size })
    if (sessions.size >= n) {
      gate.met = true
      clearTimeout(timer)
      release()
    }
    await released
    return onadd(request)
  }
  return gate
}

// A joiner that lost: never paired, cancelled, pairer swarm gone, and A saw
// every connection from the loser's pairer close.
const expectCancelled = async (net, peer, result) => {
  expect(result.paired).toBe(false)
  expect(result.error.message).toMatch(/Pairing closed/)
  expect(peer.vaultId).toBeNull()
  expect(peer.appDeps.getActiveVaultInstance()).toBeFalsy()
  expect(of(net, peer.id, 'peer.paired')).toHaveLength(0)
  expect(of(net, peer.id, 'autobase.writable')).toHaveLength(0)
  expect(of(net, peer.id, 'peer.pairTimeout')).toHaveLength(1)
  expect(of(net, peer.id, 'swarm.destroy', { label: 'pairer' })).toHaveLength(1)
  expect(of(net, peer.id, 'error', { where: 'peer.pair' })).toHaveLength(1)
  const pairer = of(net, peer.id, 'swarm.create', { label: 'pairer' })[0].key
  await waitFor(
    () => {
      const where = { label: 'vault', remote: pairer }
      const closed = of(net, 'A', 'conn.close', where).length
      return closed > 0 && closed === of(net, 'A', 'conn.open', where).length
    },
    { label: `A saw ${peer.id}'s cancelled pairer leave` }
  )
}

describe('two joiners on the same invite', () => {
  let net = null
  let gate = null

  afterEach(async () => {
    gate?.restore()
    gate = null
    await net?.destroy()
    net = null
  })

  // Finding P1: both concurrent joiners are accepted on one invite.
  // autopass member onadd (autopass/index.js:332-349) reads the invite row
  // (:334), awaits addWriter (:341), calls candidate.confirm (synchronous:
  // blind-pairing-core MemberRequest.confirm), then awaits deleteInvite
  // (:348), which reads the row again and appends del-invite (:276-281).
  // blind-pairing starts one onadd per request session and nothing
  // serialises the calls (blind-pairing/index.js:456-462), so a second
  // request read before the del-invite is applied finds the row too. The
  // gate makes that overlap certain instead of a matter of timing.
  // At most one, not exactly one, and no throw on a lost pairing: a run
  // where the gate times out (one join) or nobody joins passes this and
  // turns the test.failing red instead of hiding behind the bug.
  test.failing(
    'concurrent, both requests in onadd: at most one of B and C is accepted',
    async () => {
      net = await createNetwork({ peers: ['A', 'B', 'C'] })
      const { A, B, C } = net.peers
      await A.createVault({ id: 'shared' })
      gate = holdOnadd(A)
      const code = await A.invite()

      const results = await Promise.allSettled([
        pairOrCancel(B, code, { timeout: pairingTimeout }),
        pairOrCancel(C, code, { timeout: pairingTimeout })
      ])
      const joined = results.filter(
        (r) => r.status === 'fulfilled' && r.value.paired
      )
      expect(joined.length).toBeLessThanOrEqual(1)
    }
  )

  test('concurrent: both requests reach A onadd before either joiner is answered', async () => {
    net = await createNetwork({ peers: ['A', 'B', 'C'] })
    const { A, B, C } = net.peers
    await A.createVault({ id: 'shared' })
    gate = holdOnadd(A)
    const code = await A.invite()

    await Promise.all([
      pairOrCancel(B, code, { timeout: pairingTimeout }),
      pairOrCancel(C, code, { timeout: pairingTimeout })
    ])
    expect(gate.met).toBe(true)
    expect(gate.sessions.size).toBe(2)
    const entered = net.events.filter(
      (e) => e.peer === 'A' && e.event === 'test.onadd'
    )
    const second = net.events.indexOf(entered.find((e) => e.n === 2))
    const firstPaired = net.events.findIndex((e) => e.event === 'peer.paired')
    expect(second).toBeGreaterThan(-1)
    if (firstPaired > -1) expect(second).toBeLessThan(firstPaired)
  })

  // Natural timing, no gate: whoever joined is on the roster and in the
  // writer set and whoever did not is cleanly cancelled. Not a regression
  // check for single use; that is the test.failing above.
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
      await expectCancelled(net, peer, peer === B ? b : c)
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
    await waitFor(async () => (await inviteRow(A)) === null, {
      label: 'A reads the spent invite row as gone'
    })

    const c = await pairOrCancel(C, code, { timeout: pairingTimeout })
    await expectCancelled(net, C, c)
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
