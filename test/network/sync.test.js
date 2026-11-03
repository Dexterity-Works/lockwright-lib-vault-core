import crypto from 'crypto'

import { converge, createNetwork, shareVault, waitFor } from './harness.js'

describe('vault sync over a local testnet', () => {
  let net = null

  afterEach(async () => {
    await net?.destroy()
    net = null
  })

  test('records and files written on A land on B and C', async () => {
    net = await createNetwork({ peers: ['A', 'B', 'C'] })
    const { A, B, C } = net.peers
    await shareVault(net)

    const file = crypto.randomBytes(64 * 1024)
    await A.add('note/1', { text: 'first' })
    await A.add('record/r1', {
      id: 'r1',
      type: 'login',
      data: { title: 'Login', username: 'u', websites: ['https://a.test'] }
    })
    await A.add('record/r1/file/f1', { name: 'f1.bin' }, file, 'f1.bin')

    expect(await converge(net.list, 'note/1')).toMatchObject({ text: 'first' })
    const record = await converge(net.list, 'record/r1')
    expect(record).toMatchObject({ id: 'r1', data: { title: 'Login' } })
    for (const peer of [B, C]) {
      const bytes = await waitFor(() => peer.getFile('record/r1/file/f1'), {
        label: `${peer.id} has the file`
      })
      expect(Buffer.from(bytes).equals(file)).toBe(true)
    }

    await B.add('note/2', { text: 'from B' })
    expect(await converge(net.list, 'note/2')).toMatchObject({ text: 'from B' })

    await C.remove('note/1')
    await waitFor(async () => (await A.get('note/1')) === null, {
      label: 'A sees the removal'
    })
    await waitFor(async () => (await B.get('note/1')) === null, {
      label: 'B sees the removal'
    })
  })
})
