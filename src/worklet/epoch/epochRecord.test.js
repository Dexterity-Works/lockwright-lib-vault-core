import sodium from 'sodium-native'

import {
  buildEpochRecord,
  resolveEpochs,
  verifyEpochRecord,
  verifySignature
} from './epochRecord.js'

const keyPair = () => {
  const publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

const at = (record) => ({ key: `epoch/${record?.id}`, value: record })

describe('epochRecord', () => {
  const a = keyPair()
  const b = keyPair()
  const outsider = keyPair()
  const hex = (kp) => kp.publicKey.toString('hex')
  const roster = [{ id: 'A', masterTopic: hex(a) }]
  const members = {
    B: { topic: hex(b), box: 'sealed-b' },
    A: { topic: hex(a), box: 'sealed-a' }
  }
  const check = { n: 'bm9uY2U=', c: 'Y2lwaGVy' }
  const build = (opts) =>
    buildEpochRecord({
      seq: 1,
      prev: null,
      members,
      check,
      personalKeyPair: a,
      ...opts
    })

  it('builds a signed record that verifies against the roster', () => {
    const record = build()

    expect(record.id).toMatch(/^[0-9a-f]{32}$/)
    expect(record.by).toBe(a.publicKey.toString('hex'))
    expect(Object.keys(record.members)).toEqual(['A', 'B'])
    expect(verifyEpochRecord(record, roster)).toBe(true)
  })

  it('fails when any canonical field changes', () => {
    const record = build()
    const edits = [
      { id: 'ff'.repeat(16) },
      { seq: 2 },
      { prev: 'aa'.repeat(16) },
      { createdAt: record.createdAt + 1 },
      { members: { ...record.members, C: { topic: hex(b), box: 'c' } } },
      { members: { ...record.members, A: { topic: hex(a), box: 'other' } } },
      { members: { ...record.members, A: { topic: hex(b), box: 'sealed-a' } } },
      { check: { ...check, c: 'b3RoZXI=' } },
      { check: { ...check, n: 'b3RoZXI=' } }
    ]

    for (const edit of edits) {
      expect(verifyEpochRecord({ ...record, ...edit }, roster)).toBe(false)
    }
  })

  it('fails when the author is not in the roster', () => {
    const record = build({ personalKeyPair: outsider })

    expect(verifyEpochRecord(record, roster)).toBe(false)
    expect(verifyEpochRecord(build(), [{ id: 'A' }])).toBe(false)
  })

  it('resolves the highest seq with an id tie-break and drops invalid records', () => {
    const one = build({ id: '01'.repeat(16) })
    const twoLow = build({ id: '0a'.repeat(16), seq: 2 })
    const twoHigh = build({ id: '0b'.repeat(16), seq: 2 })
    const forged = build({
      id: '0c'.repeat(16),
      seq: 9,
      personalKeyPair: outsider
    })
    const broken = { ...build({ id: '0d'.repeat(16) }), seq: 10 }

    const { valid, latest } = resolveEpochs(
      [twoHigh, forged, one, broken, twoLow, null, 'junk'].map(at),
      roster
    )

    expect(valid.map((r) => r.id)).toEqual([one.id, twoLow.id, twoHigh.id])
    expect(latest).toBe(twoHigh)
    expect(resolveEpochs([], roster).latest).toBeNull()
  })

  it('skips roster rows whose masterTopic is not a string', () => {
    const record = build()
    const odd = [{ masterTopic: 5 }, { masterTopic: {} }, null, ...roster]

    expect(verifyEpochRecord(record, odd)).toBe(true)
    expect(verifyEpochRecord(record, null)).toBe(false)
    expect(resolveEpochs([at(record)], odd).latest).toBe(record)
  })

  it('ignores a record stored under another epoch key', () => {
    const real = build({ id: '0a'.repeat(16) })
    const shadow = build({ id: real.id, seq: 5 })

    const { valid } = resolveEpochs(
      [at(real), { key: `epoch/${'0f'.repeat(16)}`, value: shadow }],
      roster
    )
    expect(valid).toEqual([real])
  })

  it('drops every record of an id that appears twice, in either order', () => {
    const id = '0a'.repeat(16)
    const first = build({ id })
    const second = build({ id, seq: 2 })
    const other = build({ id: '0b'.repeat(16) })

    for (const order of [
      [first, second, other],
      [second, first, other]
    ]) {
      expect(resolveEpochs(order.map(at), roster).valid).toEqual([other])
    }
  })

  it('rejects malformed records, even when they are signed as they are', () => {
    const id = '0a'.repeat(16)
    const topic = hex(a)
    // Each record is signed over its own odd shape, so only the shape check
    // can turn it away. RegExp.test would accept ['<hex>'] as '<hex>'.
    const signed = [
      build({ id: [id] }),
      build({ prev: [id] }),
      build({ seq: '1' }),
      build({ seq: 0 }),
      build({ seq: 1.5 }),
      build({ createdAt: '1' }),
      build({ members: { A: { topic: [topic], box: 'x' } } }),
      build({ members: { A: { topic, box: 7 } } }),
      build({ members: { A: { topic: 'zz'.repeat(32), box: 'x' } } }),
      build({ check: { n: 1, c: 'x' } }),
      build({ check: { n: 'x', c: ['x'] } })
    ]
    const record = build({ id })
    const edited = [
      { ...record, v: 2 },
      { ...record, check: undefined },
      { ...record, check: { ...record.check, x: 'y' } },
      { ...record, by: [record.by] },
      { ...record, by: 'zz'.repeat(32) },
      { ...record, sig: [record.sig] },
      { ...record, sig: record.sig.slice(2) },
      { ...record, members: undefined },
      { ...record, members: [] },
      { ...record, members: { A: null } }
    ]

    for (const bad of [...signed, ...edited]) {
      expect(verifySignature(bad)).toBe(false)
      expect(verifyEpochRecord(bad, roster)).toBe(false)
      expect(resolveEpochs([at(bad)], roster).signed).toEqual([])
    }
    expect(verifySignature(record)).toBe(true)
  })

  it('rejects fields the signature does not cover, at either level', () => {
    const record = build()
    const extraMember = {
      ...record,
      members: { ...record.members, A: { ...record.members.A, note: 'x' } }
    }

    for (const bad of [{ ...record, note: 'x' }, extraMember]) {
      expect(verifySignature(bad)).toBe(false)
      expect(resolveEpochs([at(bad)], roster).signed).toEqual([])
    }
  })

  it('rejects a record signed by a key that is not a valid Ed25519 point', () => {
    const record = build()
    for (const by of [
      '00'.repeat(32),
      '01' + '00'.repeat(31),
      'ff'.repeat(32)
    ]) {
      expect(verifySignature({ ...record, by })).toBe(false)
    }
  })

  it('accepts authors through the members of accepted epochs', () => {
    const c = keyPair()
    const byA = build({
      id: '01'.repeat(16),
      members: {
        A: { topic: hex(a), box: 'x' },
        C: { topic: hex(c), box: 'x' }
      }
    })
    const byC = build({
      id: '02'.repeat(16),
      seq: 2,
      members: { B: { topic: hex(b), box: 'x' } },
      personalKeyPair: c
    })
    const byOutsider = build({
      id: '03'.repeat(16),
      seq: 9,
      personalKeyPair: outsider
    })
    const entries = [byOutsider, byC, byA].map(at)

    const onlyB = resolveEpochs(entries, [{ id: 'B', masterTopic: hex(b) }])
    expect(onlyB.latest).toBeNull()
    expect(onlyB.signed.map((r) => r.id)).toEqual([
      byA.id,
      byC.id,
      byOutsider.id
    ])
    expect(onlyB.highSeq).toBe(9)

    const withA = resolveEpochs(entries, roster)
    expect(withA.valid.map((r) => r.id)).toEqual([byA.id, byC.id])
    expect(withA.latest).toBe(byC)
  })
})
