import sodium from 'sodium-native'

import {
  buildEpochRecord,
  resolveEpochs,
  verifyEpochRecord
} from './epochRecord.js'

const keyPair = () => {
  const publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

describe('epochRecord', () => {
  const a = keyPair()
  const outsider = keyPair()
  const roster = [{ id: 'A', masterTopic: a.publicKey.toString('hex') }]
  const members = { B: 'sealed-b', A: 'sealed-a' }
  const build = (opts) =>
    buildEpochRecord({
      seq: 1,
      prev: null,
      members,
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
      { members: { ...record.members, C: 'sealed-c' } },
      { members: { ...record.members, A: 'other' } }
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
      [twoHigh, forged, one, broken, twoLow, null, 'junk'],
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
    expect(resolveEpochs([record], odd).latest).toBe(record)
  })
})
