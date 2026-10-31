import fs from 'fs'
import os from 'os'
import path from 'path'

import { converge, createNetwork, shareVault, waitFor } from './harness.js'
import { short } from './tracer.js'

describe('connection attempts', () => {
  let net = null
  let artifacts = null
  const previous = process.env.LOCKWRIGHT_NET_ARTIFACTS

  beforeEach(() => {
    artifacts = fs.mkdtempSync(path.join(os.tmpdir(), 'attempts-'))
    process.env.LOCKWRIGHT_NET_ARTIFACTS = artifacts
  })

  afterEach(async () => {
    await net?.destroy()
    net = null
    if (previous === undefined) delete process.env.LOCKWRIGHT_NET_ARTIFACTS
    else process.env.LOCKWRIGHT_NET_ARTIFACTS = previous
    fs.rmSync(artifacts, { recursive: true, force: true })
  })

  test('B cannot reach A: the timeline shows B trying and why it failed', async () => {
    net = await createNetwork({ peers: ['A', 'B'] })
    const { A } = net.peers
    await shareVault(net)
    await A.add('note/1', { text: 'before' })
    await converge(net.list, 'note/1')
    const keyA = short(A.instance.swarm.keyPair.publicKey)

    await A.goOffline()
    const failed = (e) =>
      e.event === 'conn.fail' && e.label === 'vault' && e.remote === keyA
    await waitFor(() => net.tracers.B.events.some(failed), {
      label: 'B traced a failed attempt at A',
      timeout: 20000
    })
    // The swarm's own counters, sampled on change.
    const sampled = (e) =>
      e.event === 'swarm.stats' &&
      e.label === 'vault' &&
      e.connects.client.attempted >= 2
    await waitFor(
      () =>
        net.tracers.B.events.some(sampled) &&
        net.tracers.B.events.some(
          (e) =>
            e.event === 'swarm.peers' &&
            e.label === 'vault' &&
            e.peers.some((p) => p.remote === keyA && p.attempts >= 1)
        ),
      { label: 'B sampled its attempts at A' }
    )

    const { timeline } = await net.destroy({ keep: true })
    const b = timeline.events.filter((e) => e.peer === 'B')
    const offline = timeline.events.find((e) => e.event === 'peer.offline').wall
    const after = b.filter((e) => e.wall >= offline)
    expect(after).toContainEqual(
      expect.objectContaining({
        event: 'conn.attempt',
        label: 'vault',
        remote: keyA,
        relayed: false
      })
    )
    const fail = after.find(failed)
    expect(fail.code).toEqual(expect.stringMatching(/^[A-Z_]+$/))
    expect(typeof fail.ms).toBe('number')
    expect(b.some(sampled)).toBe(true)
    expect(b.some((e) => e.event === 'dht.stats')).toBe(true)
    const txt = fs.readFileSync(timeline.txt, 'utf8')
    expect(txt).toMatch(
      new RegExp(
        `\\bB\\s+conn\\.fail\\s+label="vault" remote="${keyA}" code="${fail.code}"`
      )
    )
    expect(fs.existsSync(timeline.html)).toBe(true)
    fs.rmSync(net.dir, { recursive: true, force: true })
  })
})
