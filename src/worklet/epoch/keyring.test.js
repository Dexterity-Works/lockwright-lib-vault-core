import sodium from 'sodium-native'

import {
  canSealTo,
  EpochDecryptError,
  EpochKeyUnavailableError,
  decryptValue,
  encryptValue,
  generateEpochKey,
  isEnvelope,
  openRing,
  sealRing
} from './keyring.js'

const keyPair = () => {
  const publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

const member = (id, kp) => ({ id, masterTopic: kp.publicKey.toString('hex') })

const editEnvelope = (envelope, edit) =>
  JSON.stringify({ ...JSON.parse(envelope), ...edit })

describe('keyring', () => {
  const a = keyPair()
  const b = keyPair()
  const ring = { e1: generateEpochKey(), e2: generateEpochKey() }

  it('seals a ring to each member and opens it with their key pair', () => {
    const sealed = sealRing(ring, [member('A', a), member('B', b)])

    expect(Object.keys(sealed).sort()).toEqual(['A', 'B'])
    expect(openRing(sealed.A, a)).toEqual(ring)
    expect(openRing(sealed.B, b)).toEqual(ring)
  })

  it('returns null when the ring is opened with the wrong key pair', () => {
    const sealed = sealRing(ring, [member('A', a)])

    expect(openRing(sealed.A, b)).toBeNull()
    expect(openRing('not base64 at all', a)).toBeNull()
  })

  it('round trips a value and a file under an epoch key', () => {
    const { envelope, file } = encryptValue(
      'e2',
      ring.e2,
      '{"secret":1}',
      Buffer.from('file bytes')
    )

    expect(isEnvelope(envelope)).toBe(true)
    expect(envelope).not.toContain('secret')
    expect(file.toString()).not.toContain('file bytes')

    const out = decryptValue(envelope, ring, file)
    expect(out.value).toBe('{"secret":1}')
    expect(out.file.toString()).toBe('file bytes')
  })

  it('tells plaintext values from envelopes', () => {
    expect(isEnvelope('{"title":"x"}')).toBe(false)
    expect(isEnvelope('not json')).toBe(false)
    expect(isEnvelope(null)).toBe(false)
    expect(isEnvelope({ $enc: 1 })).toBe(true)
  })

  it('throws EpochKeyUnavailableError when the ring lacks the epoch', () => {
    const { envelope } = encryptValue('e3', generateEpochKey(), 'v')

    expect(() => decryptValue(envelope, ring)).toThrow(EpochKeyUnavailableError)
  })

  it('throws EpochDecryptError on a tampered e, c, or swapped nonce', () => {
    const { envelope, file } = encryptValue(
      'e1',
      ring.e1,
      'v',
      Buffer.from('f')
    )
    const parsed = JSON.parse(envelope)
    const other = JSON.parse(encryptValue('e1', ring.e1, 'v').envelope)
    const flipped = Buffer.from(parsed.c, 'base64')
    flipped[0] ^= 1

    const tampered = [
      editEnvelope(envelope, { e: 'e2' }),
      editEnvelope(envelope, { c: flipped.toString('base64') }),
      editEnvelope(envelope, { n: parsed.fn, fn: parsed.n }),
      editEnvelope(envelope, { n: other.n })
    ]

    for (const bad of tampered) {
      expect(() => decryptValue(bad, ring, file)).toThrow(EpochDecryptError)
    }
  })

  it('skips members whose masterTopic is not a usable Ed25519 key', () => {
    const lowOrder = '01' + '00'.repeat(31)
    const zeros = '00'.repeat(32)
    const sealed = sealRing(ring, [
      { id: 'L', masterTopic: lowOrder },
      member('A', a),
      { id: 'Z', masterTopic: zeros }
    ])

    expect(Object.keys(sealed)).toEqual(['A'])
    expect(openRing(sealed.A, a)).toEqual(ring)
    expect(canSealTo(lowOrder)).toBe(false)
    expect(canSealTo(zeros)).toBe(false)
    expect(canSealTo(5)).toBe(false)
    expect(canSealTo(a.publicKey.toString('hex'))).toBe(true)
  })
})
