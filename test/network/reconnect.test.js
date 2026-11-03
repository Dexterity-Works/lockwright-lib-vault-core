import { createNetwork, shareVault, sleep, waitFor } from './harness.js'

const allNotes = async (peer, n) => {
  const rows = await peer.list('note/')
  if (rows.length !== n) {
    const have = rows.map((r) => r.i).sort((a, b) => a - b)
    throw new Error(
      `${peer.id} has ${rows.length}/${n} notes (base length ${peer.instance.base.length}): ${have.join(',')}`
    )
  }
  return rows.map((r) => r.i).sort((a, b) => a - b)
}

const total = 40
const first = 5
const expected = Array.from({ length: total }, (_, i) => i)

// A writes `first` notes, B receives them, then `cut(B)` takes B off the
// network, A writes the rest, `heal(B)` brings B back and B must converge.
const dropAndHeal = async (net, { cut, heal, readable = true }) => {
  const { A, B } = net.peers
  await shareVault(net)
  for (let i = 0; i < first; i++) await A.add(`note/${i}`, { i })
  await waitFor(async () => (await B.list('note/')).length === first, {
    label: 'B received the first notes'
  })
  await cut(B)
  for (let i = first; i < total; i++) await A.add(`note/${i}`, { i })
  await sleep(300)
  // A closed vault cannot be read while it is down.
  if (readable) expect((await B.list('note/')).length).toBe(first)
  await heal(B)
  expect(
    await waitFor(() => allNotes(B, total), { label: 'B caught up' })
  ).toEqual(expected)
  await B.add('note/from-b', { i: total })
  await waitFor(async () => (await A.get('note/from-b')) !== null, {
    label: 'A hears B again'
  })
}

describe('reconnect after a drop', () => {
  let net = null

  afterEach(async () => {
    await net?.destroy()
    net = null
  })

  test('B goes offline mid-sync and comes back (suspend, resume)', async () => {
    net = await createNetwork({ peers: ['A', 'B'] })
    await dropAndHeal(net, {
      cut: (B) => B.goOffline(),
      heal: (B) => B.goOnline()
    })
  })

  test('B closes its vault mid-sync and opens it again', async () => {
    net = await createNetwork({ peers: ['A', 'B'] })
    const { B } = net.peers
    let before
    await dropAndHeal(net, {
      cut: async (b) => {
        before = b.instance.swarm
        await b.closeVault()
      },
      heal: (b) => b.openVault(),
      readable: false
    })
    expect(B.instance.swarm).not.toBe(before)
    expect(before.destroyed).toBe(true)
  })

  // Finding 1 (PROGRESS-network.md): when B's swarm died before the vault
  // closed, the reopened Autobase can come back with its view behind the
  // system (view 6 where it had 12, indexedLength 30), and the notes B had
  // received before the restart are gone from reads for good. Seen in
  // roughly 1 run in 10 to 20; 2 in 15 with an immediate restart. Autobase
  // 7.28.1 / Autopass 3.3.0 behaviour, not ADR 0014, so it stays a repro:
  // LOCKWRIGHT_FINDINGS=1 runs it with enough rounds to fail.
  const findings = process.env.LOCKWRIGHT_FINDINGS === '1' ? test : test.skip
  findings(
    "Finding 1: B's swarm is destroyed, then the vault restarts (repro)",
    async () => {
      for (let round = 0; round < 25; round++) {
        const round_ = await createNetwork({ peers: ['A', 'B'], name: 'f1' })
        try {
          const { A, B } = round_.peers
          await shareVault(round_)
          for (let i = 0; i < first; i++) await A.add(`note/${i}`, { i })
          await waitFor(async () => (await B.list('note/')).length === first, {
            label: 'B received the first notes'
          })
          await B.instance.swarm.destroy()
          await B.restartVault()
          await waitFor(() => allNotes(B, first), {
            timeout: 5000,
            label: `round ${round}: B still has its notes after the restart`
          })
        } finally {
          await round_.destroy()
        }
      }
    },
    600000
  )
})
