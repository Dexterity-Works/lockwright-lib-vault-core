// A partition test that fails on purpose, for a sample report.html:
//   LOCKWRIGHT_NET_ARTIFACTS=test-artifacts pnpm exec jest \
//     --config jest.network.config.js --runInBand \
//     --testMatch '**/test/network/fixtures/partition.network.js'
// A starts an epoch and goes offline, B keeps failing to reach it, A comes
// back and kicks C, then B goes offline and the test waits for a note B
// cannot get.
import {
  converge,
  createNetwork,
  shareVault,
  sleep,
  waitFor
} from '../harness.js'

describe('sample partition', () => {
  let net = null
  afterEach(async () => {
    await net?.destroy()
  })
  test('B reads a note A wrote while B was offline', async () => {
    net = await createNetwork({ peers: ['A', 'B', 'C'] })
    const { A, B } = net.peers
    await shareVault(net)
    await A.ensureEpoch({ start: true })
    await A.add('note/1', { text: 'before' })
    await converge(net.list, 'note/1')

    await A.goOffline()
    await B.add('note/2', { text: 'while A is away' })
    await sleep(4000)
    await A.goOnline()
    await converge(net.list, 'note/2')
    await A.kick('device-C')

    await B.goOffline()
    await A.add('note/3', { text: 'B is away' })
    await waitFor(async () => (await B.get('note/3')) !== null, {
      label: 'B reads note/3',
      timeout: 3000
    })
  })
})
