import crypto from 'crypto'

import { createNetwork, shareVault, waitFor } from './harness.js'

// The personal swarm carries device-to-device envelopes, e.g. the notice a
// kicked device gets (lib-vault's kickDevice signs and sends it; its
// content is lib-vault's and not modelled here). These tests drive the
// vault-core transport over the testnet: send, deliver, and fail.

const hex = (n) => crypto.randomBytes(n).toString('hex')

describe('personal swarm over a local testnet', () => {
  let net = null

  afterEach(async () => {
    await net?.destroy()
    net = null
  })

  test('a kick notice reaches the kicked device on its master topic', async () => {
    net = await createNetwork({ peers: ['A', 'B', 'C'] })
    const { A, C } = net.peers
    await shareVault(net)
    await A.ensureEpoch({ start: true })
    const topicC = await C.personalInit()

    // A finds C's topic where lib-vault does: on C's device row.
    const row = (await A.devices()).find((d) => d.id === 'device-C')
    expect(row.masterTopic).toBe(topicC)

    await A.kick('device-C')
    const envelope = Buffer.from(
      JSON.stringify({ type: 'kick', vaultId: A.vaultId, nonce: hex(8) })
    ).toString('hex')
    expect(await A.personalSend(topicC, envelope)).toEqual({ ok: true })

    await waitFor(() => C.envelopes.length === 1, {
      label: 'C got the envelope'
    })
    expect(C.envelopes[0]).toBe(envelope)
    await waitFor(async () => (await C.epochStatus()).revoked, {
      label: 'C also learns it was revoked from the vault'
    })

    const sends = net.tracers.A.events.filter(
      (e) => e.event === 'swarm.create' && e.label === 'personalSend'
    )
    expect(sends).toHaveLength(1)
    expect(sends[0].bootstrap).toEqual(net.bootstrap)
    expect(
      net.tracers.C.events.some(
        (e) => e.event === 'conn.open' && e.label === 'personalSwarm'
      )
    ).toBe(true)
  })

  test('an envelope to a device that went offline after announcing is not delivered', async () => {
    net = await createNetwork({ peers: ['A', 'C'] })
    const { A, C } = net.peers
    const topicC = await C.personalInit()
    // Announced on the DHT first, so A's lookup can find C's record.
    const personal = C.created.find((c) => c.label === 'personalSwarm')
    await personal.instance.flush()
    await C.personalClose()
    const started = Date.now()
    const result = await A.personalSend(topicC, hex(16))
    expect(result).toEqual({ ok: false, reason: 'lookup-timeout' })
    expect(Date.now() - started).toBeGreaterThanOrEqual(29000)
    expect(C.envelopes).toEqual([])
  }, 90000)

  test('bad input is refused before any swarm is built', async () => {
    net = await createNetwork({ peers: ['A'] })
    const { A } = net.peers
    const topic = hex(32)
    expect(await A.personalSend('', hex(4))).toEqual({
      ok: false,
      reason: 'missing-args'
    })
    expect(await A.personalSend('zz', hex(4))).toEqual({
      ok: false,
      reason: 'invalid-topic'
    })
    expect(await A.personalSend(topic, 'abc')).toEqual({
      ok: false,
      reason: 'invalid-envelope'
    })
    expect(await A.personalSend(topic, hex(64 * 1024 + 1))).toEqual({
      ok: false,
      reason: 'envelope-too-large'
    })
    expect(
      net.tracers.A.events.filter(
        (e) => e.event === 'swarm.create' && e.label === 'personalSend'
      )
    ).toEqual([])
  })
})
