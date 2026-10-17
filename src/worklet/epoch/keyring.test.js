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

// Seals any JSON, not only a key map, the way sealRing would.
const sealAs = (json, kp) => {
  const message = Buffer.from(JSON.stringify(json))
  const curvePk = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES)
  sodium.crypto_sign_ed25519_pk_to_curve25519(curvePk, kp.publicKey)
  const box = Buffer.alloc(message.length + sodium.crypto_box_SEALBYTES)
  sodium.crypto_box_seal(box, message, curvePk)
  return box.toString('base64')
}

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

  it('refuses epoch keys that are not exactly 32 bytes of base64', () => {
    const fake = '!'.repeat(43) + '='
    const good = encryptValue('e1', ring.e1, 'v').envelope

    expect(() => encryptValue('e1', fake, 'v')).toThrow(EpochDecryptError)
    expect(() => decryptValue(good, { e1: fake })).toThrow(EpochDecryptError)
    expect(() => encryptValue('e1', ring.e1.slice(0, -1), 'v')).toThrow(
      EpochDecryptError
    )
  })

  it('refuses a key whose unused base64 bits are set', () => {
    // 43 characters carry 258 bits; the last 2 are padding. Setting them
    // spells the same 32 bytes another way.
    const chars =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    const last = chars.indexOf(ring.e1[42])
    const alias = `${ring.e1.slice(0, 42)}${chars[last ^ 1]}=`
    expect(Buffer.from(alias, 'base64')).toEqual(Buffer.from(ring.e1, 'base64'))

    expect(() => encryptValue('e1', alias, 'v')).toThrow(EpochDecryptError)
    const sealed = sealRing({ e1: ring.e1, e9: alias }, [member('A', a)])
    expect(openRing(sealed.A, a)).toEqual({ e1: ring.e1 })
  })

  it('drops ring entries that are not valid epoch keys when opening', () => {
    const sealed = sealRing(
      { e1: ring.e1, bad: '!'.repeat(43) + '=', short: 'AAAA' },
      [member('A', a)]
    )

    expect(openRing(sealed.A, a)).toEqual({ e1: ring.e1 })
  })

  it('throws EpochDecryptError, never a TypeError, on malformed envelopes', () => {
    const withFile = encryptValue('e1', ring.e1, 'v', Buffer.from('f'))
    const plain = encryptValue('e1', ring.e1, 'v').envelope
    const flippedFile = Buffer.from(withFile.file)
    flippedFile[0] ^= 1
    const cases = [
      [editEnvelope(plain, { n: 123 }), ring, null],
      [editEnvelope(withFile.envelope, { fn: {} }), ring, withFile.file],
      [editEnvelope(plain, { e: 7 }), ring, null],
      [editEnvelope(plain, { e: null }), ring, null],
      [plain, null, null],
      [editEnvelope(plain, { n: 'AAAA' }), ring, null],
      [
        editEnvelope(plain, { c: Buffer.alloc(10).toString('base64') }),
        ring,
        null
      ],
      [
        editEnvelope(plain, { fn: JSON.parse(withFile.envelope).fn }),
        ring,
        null
      ],
      [plain, ring, withFile.file],
      [withFile.envelope, ring, flippedFile]
    ]

    for (const [envelope, keys, file] of cases) {
      expect(() => decryptValue(envelope, keys, file)).toThrow(
        EpochDecryptError
      )
    }
  })

  it('throws EpochDecryptError on bad base64, non-string c, or the wrong key', () => {
    const plain = encryptValue('e1', ring.e1, 'v').envelope
    const cases = [
      [editEnvelope(plain, { c: 5 }), ring],
      [editEnvelope(plain, { c: ['AAAA'] }), ring],
      [editEnvelope(plain, { c: '!!!!' }), ring],
      [editEnvelope(plain, { n: '!!!!' }), ring],
      // A valid key, but not the one this epoch was sealed with.
      [plain, { e1: ring.e2 }],
      ['[]', ring],
      ['{"$enc":"1"}', ring]
    ]

    for (const [envelope, keys] of cases) {
      expect(() => decryptValue(envelope, keys)).toThrow(EpochDecryptError)
    }
    expect(() => decryptValue(plain, { e1: 42 })).toThrow(
      EpochKeyUnavailableError
    )
  })

  it('opens no ring from a box that is not a sealed key map', () => {
    expect(openRing(sealAs([ring.e1], a), a)).toBeNull()
    expect(openRing(sealAs('just a string', a), a)).toBeNull()
    expect(openRing(sealAs(null, a), a)).toBeNull()
    expect(openRing(123, a)).toBeNull()
    expect(openRing(Buffer.alloc(8).toString('base64'), a)).toBeNull()
  })
})
