import sodium from 'sodium-native'

import {
  buildEpochRecord,
  resolveEpochs,
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
    expect(verifySignature(record)).toBe(true)
    expect(resolveEpochs([at(record)], roster).latest).toBe(record)
  })

  it('signs members as pairs in code-point order, integer-like ids too', () => {
    const topic = hex(b)
    // UTF-16 order puts the astral id (surrogates D83D DE00) before U+FF5E.
    const astral = '\u{1F600}'
    const bmp = '\uFF5E'
    const record = build({
      members: {
        9: { topic, box: 'x' },
        10: { topic, box: 'y' },
        [astral]: { topic, box: 'a' },
        [bmp]: { topic, box: 'b' },
        B: { topic, box: 'z' }
      }
    })
    const { v, id, seq, prev, createdAt, by, check: c } = record
    // JSON.stringify of an object would put 9 before 10.
    const canonical = JSON.stringify({
      v,
      id,
      seq,
      prev,
      createdAt,
      by,
      members: [
        ['10', { topic, box: 'y' }],
        ['9', { topic, box: 'x' }],
        ['B', { topic, box: 'z' }],
        [bmp, { topic, box: 'b' }],
        [astral, { topic, box: 'a' }]
      ],
      check: c
    })

    expect(
      sodium.crypto_sign_verify_detached(
        Buffer.from(record.sig, 'hex'),
        Buffer.from(canonical),
        a.publicKey
      )
    ).toBe(true)
    expect(verifySignature(record)).toBe(true)
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
      expect(verifySignature({ ...record, ...edit })).toBe(false)
    }
  })

  it('fails when the author is not in the roster', () => {
    const record = build({ personalKeyPair: outsider })

    expect(resolveEpochs([at(record)], roster).latest).toBeNull()
    expect(resolveEpochs([at(build())], [{ id: 'A' }]).latest).toBeNull()
  })

  it('resolves the highest seq with an id tie-break and drops invalid records', () => {
    const one = build({ id: '01'.repeat(16) })
    const twoLow = build({ id: '0a'.repeat(16), seq: 2, prev: one.id })
    const twoHigh = build({ id: '0b'.repeat(16), seq: 2, prev: one.id })
    const forged = build({
      id: '0c'.repeat(16),
      seq: 3,
      prev: twoHigh.id,
      personalKeyPair: outsider
    })
    const broken = { ...build({ id: '0d'.repeat(16) }), seq: 10 }

    const { accepted, latest } = resolveEpochs(
      [twoHigh, forged, one, broken, twoLow, null, 'junk'].map(at),
      roster
    )

    expect(accepted.map((r) => r.id)).toEqual([one.id, twoLow.id, twoHigh.id])
    expect(latest).toBe(twoHigh)
    expect(resolveEpochs([], roster).latest).toBeNull()
  })

  it('skips roster rows whose masterTopic is not a string', () => {
    const record = build()
    const odd = [{ masterTopic: 5 }, { masterTopic: {} }, null, ...roster]

    expect(resolveEpochs([at(record)], odd).latest).toBe(record)
    expect(resolveEpochs([at(record)], null).latest).toBeNull()
  })

  it('ignores a record stored under another epoch key', () => {
    const real = build({ id: '0a'.repeat(16) })
    const shadow = build({ id: real.id, createdAt: real.createdAt + 1 })

    const { accepted } = resolveEpochs(
      [at(real), { key: `epoch/${'0f'.repeat(16)}`, value: shadow }],
      roster
    )
    expect(accepted).toEqual([real])
  })

  it('drops every record of an id that appears twice, in either order', () => {
    const id = '0a'.repeat(16)
    const first = build({ id })
    const second = build({ id, createdAt: first.createdAt + 1 })
    const other = build({ id: '0b'.repeat(16) })

    for (const order of [
      [first, second, other],
      [second, first, other]
    ]) {
      expect(resolveEpochs(order.map(at), roster).accepted).toEqual([other])
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
      expect(resolveEpochs([at(bad)], roster).valid).toEqual([])
    }
    expect(verifySignature(record)).toBe(true)
  })

  it('applies the device id rule to member ids', () => {
    const member = { topic: hex(b), box: 'x' }
    // Each signed over its own ids, so only the id rule turns them away.
    for (const id of ['', '\uD800']) {
      const record = build({ members: { [id]: member } })
      expect(verifySignature(record)).toBe(false)
      expect(verifySignature(JSON.parse(JSON.stringify(record)))).toBe(false)
    }
    // __proto__ is an ordinary own key once stored.
    const proto = JSON.parse(
      JSON.stringify(build({ members: { ['__proto__']: member } }))
    )
    expect(Object.keys(proto.members)).toEqual(['__proto__'])
    expect(verifySignature(proto)).toBe(true)
  })

  it('rejects fields the signature does not cover, at either level', () => {
    const record = build()
    const extraMember = {
      ...record,
      members: { ...record.members, A: { ...record.members.A, note: 'x' } }
    }

    for (const bad of [{ ...record, note: 'x' }, extraMember]) {
      expect(verifySignature(bad)).toBe(false)
      expect(resolveEpochs([at(bad)], roster).valid).toEqual([])
    }
  })

  it('accepts only records that chain to a valid record one seq below', () => {
    const one = build({ id: '01'.repeat(16) })
    const two = build({ id: '02'.repeat(16), seq: 2, prev: one.id })
    const three = build({ id: '03'.repeat(16), seq: 3, prev: two.id })
    const unchained = [
      build({ id: '0a'.repeat(16), seq: 2 }),
      build({ id: '0b'.repeat(16), seq: 3, prev: one.id }),
      build({ id: '0c'.repeat(16), seq: 1, prev: one.id }),
      build({ id: '0d'.repeat(16), seq: 2, prev: 'ee'.repeat(16) }),
      build({ id: '0e'.repeat(16), seq: Number.MAX_SAFE_INTEGER }),
      // Chains to a record that does not chain.
      build({ id: '0f'.repeat(16), seq: 3, prev: '0d'.repeat(16) })
    ]

    const { valid, accepted, latest } = resolveEpochs(
      [three, ...unchained, two, one].map(at),
      roster
    )
    expect(accepted.map((r) => r.id)).toEqual([one.id, two.id, three.id])
    expect(latest).toBe(three)
    // The chain gates the write epoch only: every key stays openable.
    expect(valid).toHaveLength(9)
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

  it('accepts only records whose author has a roster row', () => {
    // B is a member of A's epoch, which no longer makes B an author.
    const byA = build({ id: '01'.repeat(16) })
    const byB = build({
      id: '02'.repeat(16),
      seq: 2,
      prev: byA.id,
      personalKeyPair: b
    })
    const entries = [byB, byA].map(at)

    const withA = resolveEpochs(entries, roster)
    expect(withA.valid).toEqual([byA, byB])
    expect(withA.accepted).toEqual([byA])
    expect(withA.latest).toBe(byA)

    const onlyB = resolveEpochs(entries, [{ id: 'B', masterTopic: hex(b) }])
    expect(onlyB.accepted).toEqual([byB])
    expect(resolveEpochs(entries, []).latest).toBeNull()
  })
})
