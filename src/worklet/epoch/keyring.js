import Hypercore from 'hypercore'
import sodium from 'sodium-native'

export class EpochKeyUnavailableError extends Error {
  constructor(epochId) {
    super(`No key for epoch ${epochId}`)
    this.name = 'EpochKeyUnavailableError'
    this.epochId = epochId
  }
}

/** The latest epoch is sealed to someone outside the roster, or missing. */
export class EpochRotationPendingError extends Error {
  constructor() {
    super('The vault epoch must rotate before this write')
    this.name = 'EpochRotationPendingError'
  }
}

/** Epoch records are appended by a rotation only, never by add or remove. */
export class EpochRecordWriteError extends Error {
  constructor(key) {
    super(`Only an epoch rotation may write ${key}`)
    this.name = 'EpochRecordWriteError'
    this.key = key
  }
}

/**
 * @param {Error} error thrown by a write
 * @returns {string} words the UI can show for an epoch error, else the
 *   error's own message
 */
export const writeErrorMessage = (error) =>
  error instanceof EpochKeyUnavailableError
    ? 'Vault key not available yet: another device must rotate it'
    : error instanceof EpochRotationPendingError
      ? 'Vault key must rotate first: wait for a device that can rotate it'
      : error.message

export class EpochDecryptError extends Error {
  constructor(message = 'Epoch envelope failed to decrypt') {
    super(message)
    this.name = 'EpochDecryptError'
  }
}

const free = (...buffers) => {
  for (const buffer of buffers) {
    sodium.sodium_memzero(buffer)
    sodium.sodium_free(buffer)
  }
}

// Best effort only: ring keys also live as base64 JS strings (the same
// accepted exposure as the string key in encryptVaultWithKey), so zeroing
// these sodium_malloc buffers cannot clear every copy.
const secureFrom = (string, encoding) => {
  const buffer = sodium.sodium_malloc(Buffer.byteLength(string, encoding))
  buffer.write(string, encoding)
  return buffer
}

// 32 bytes in canonical base64: decoding and encoding again gives the same
// string. Buffer.byteLength only counts characters, so '!'.repeat(43) + '='
// would pass a length check and decode to sodium_malloc's fill, and a set
// padding bit would spell one key several ways.
const isEpochKey = (key) => {
  if (typeof key !== 'string') return false
  const bytes = Buffer.from(key, 'base64')
  try {
    return (
      bytes.length === sodium.crypto_secretbox_KEYBYTES &&
      bytes.toString('base64') === key
    )
  } finally {
    bytes.fill(0)
  }
}

/**
 * @returns {string} 32-byte secretbox key, base64
 */
export const generateEpochKey = () => {
  const key = sodium.sodium_malloc(sodium.crypto_secretbox_KEYBYTES)
  try {
    sodium.randombytes_buf(key)
    return key.toString('base64')
  } finally {
    free(key)
  }
}

const MASTER_TOPIC = /^[0-9a-f]{64}$/i

// Null when masterTopic is not an Ed25519 key that converts to Curve25519
// (low-order points, all zeros, wrong shape).
const toCurvePublicKey = (masterTopic) => {
  if (typeof masterTopic !== 'string' || !MASTER_TOPIC.test(masterTopic)) {
    return null
  }
  const curvePk = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES)
  try {
    sodium.crypto_sign_ed25519_pk_to_curve25519(
      curvePk,
      Buffer.from(masterTopic, 'hex')
    )
    return curvePk
  } catch {
    return null
  }
}

/**
 * @param {unknown} masterTopic
 * @returns {boolean} whether a ring can be sealed to this device key
 */
export const canSealTo = (masterTopic) => toCurvePublicKey(masterTopic) !== null

/**
 * Members whose key cannot be sealed to are left out of the result.
 * @param {Record<string, string>} ring epochId -> key b64
 * @param {Array<{ id: string, masterTopic: string }>} members
 * @returns {Record<string, string>} deviceId -> sealed box b64, with no
 *   prototype, so a device id such as `__proto__` is an own key
 */
export const sealRing = (ring, members) => {
  const message = secureFrom(JSON.stringify(ring), 'utf8')
  try {
    const sealed = Object.create(null)
    for (const { id, masterTopic } of members) {
      const curvePk = toCurvePublicKey(masterTopic)
      if (!curvePk) continue
      const box = Buffer.alloc(message.length + sodium.crypto_box_SEALBYTES)
      sodium.crypto_box_seal(box, message, curvePk)
      sealed[id] = box.toString('base64')
    }
    return sealed
  } finally {
    free(message)
  }
}

/**
 * @param {string} sealedB64
 * @param {{ publicKey: Buffer, secretKey: Buffer }} personalKeyPair
 * @returns {Record<string, string> | null} with no prototype
 */
export const openRing = (sealedB64, personalKeyPair) => {
  if (typeof sealedB64 !== 'string') return null
  const box = Buffer.from(sealedB64, 'base64')
  if (box.length <= sodium.crypto_box_SEALBYTES) return null

  const curvePk = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES)
  const curveSk = sodium.sodium_malloc(sodium.crypto_box_SECRETKEYBYTES)
  const plain = sodium.sodium_malloc(box.length - sodium.crypto_box_SEALBYTES)
  try {
    sodium.crypto_sign_ed25519_pk_to_curve25519(
      curvePk,
      personalKeyPair.publicKey
    )
    sodium.crypto_sign_ed25519_sk_to_curve25519(
      curveSk,
      personalKeyPair.secretKey
    )
    if (!sodium.crypto_box_seal_open(plain, box, curvePk, curveSk)) return null

    const parsed = JSON.parse(plain.toString('utf8'))
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return null
    }
    const ring = Object.create(null)
    for (const [epochId, key] of Object.entries(parsed)) {
      if (isEpochKey(key)) ring[epochId] = key
    }
    return ring
  } catch {
    return null
  } finally {
    free(curveSk, plain)
  }
}

/**
 * @param {unknown} value Autopass value string or parsed object
 * @returns {boolean}
 */
export const isEnvelope = (value) => {
  let parsed = value
  if (typeof value === 'string') {
    try {
      parsed = JSON.parse(value)
    } catch {
      return false
    }
  }
  return !!parsed && typeof parsed === 'object' && parsed.$enc === 1
}

const seal = (bytes, key) => {
  const nonce = Buffer.alloc(sodium.crypto_secretbox_NONCEBYTES)
  sodium.randombytes_buf(nonce)
  const ciphertext = Buffer.alloc(
    bytes.length + sodium.crypto_secretbox_MACBYTES
  )
  sodium.crypto_secretbox_easy(ciphertext, bytes, nonce, key)
  return { nonce, ciphertext }
}

const open = (ciphertext, nonceB64, key) => {
  if (typeof nonceB64 !== 'string' || !Buffer.isBuffer(ciphertext)) {
    throw new EpochDecryptError()
  }
  const nonce = Buffer.from(nonceB64, 'base64')
  if (
    nonce.length !== sodium.crypto_secretbox_NONCEBYTES ||
    ciphertext.length < sodium.crypto_secretbox_MACBYTES
  ) {
    throw new EpochDecryptError()
  }
  const plain = sodium.sodium_malloc(
    ciphertext.length - sodium.crypto_secretbox_MACBYTES
  )
  if (!sodium.crypto_secretbox_open_easy(plain, ciphertext, nonce, key)) {
    free(plain)
    throw new EpochDecryptError()
  }
  return plain
}

const readKey = (keyB64) => {
  if (!isEpochKey(keyB64)) {
    throw new EpochDecryptError('Epoch key is not 32 bytes of base64')
  }
  const key = sodium.sodium_malloc(sodium.crypto_secretbox_KEYBYTES)
  key.write(keyB64, 'base64')
  return key
}

/**
 * @param {string} epochId
 * @param {string} keyB64
 * @param {string} plaintext
 * @param {Buffer} [fileBuffer]
 * @returns {{ envelope: string, file?: Buffer }}
 * @throws {EpochDecryptError} when keyB64 is not an epoch key. The ring
 *   holds checked keys only, so this does not happen in practice; readKey
 *   shares the error type with the decrypt path on purpose.
 */
export const encryptValue = (epochId, keyB64, plaintext, fileBuffer) => {
  const key = readKey(keyB64)
  const message = secureFrom(plaintext, 'utf8')
  try {
    const value = seal(message, key)
    const envelope = {
      $enc: 1,
      e: epochId,
      n: value.nonce.toString('base64'),
      c: value.ciphertext.toString('base64')
    }
    if (!fileBuffer) return { envelope: JSON.stringify(envelope) }

    const file = seal(fileBuffer, key)
    envelope.fn = file.nonce.toString('base64')
    return { envelope: JSON.stringify(envelope), file: file.ciphertext }
  } finally {
    free(key, message)
  }
}

/**
 * @param {string | object} envelope
 * @param {Record<string, string>} ring
 * @param {Buffer | null} [fileBuffer]
 * @returns {{ value: string, file?: Buffer }}
 * @throws {EpochKeyUnavailableError | EpochDecryptError}
 */
export const decryptValue = (envelope, ring, fileBuffer) => {
  let parsed = envelope
  if (typeof envelope === 'string') {
    try {
      parsed = JSON.parse(envelope)
    } catch {
      throw new EpochDecryptError('Envelope is not JSON')
    }
  }
  if (
    !isEnvelope(parsed) ||
    typeof parsed.c !== 'string' ||
    typeof parsed.n !== 'string' ||
    typeof parsed.e !== 'string' ||
    (parsed.fn !== undefined && typeof parsed.fn !== 'string')
  ) {
    throw new EpochDecryptError('Not an epoch envelope')
  }
  if (!ring || typeof ring !== 'object') {
    throw new EpochDecryptError('No epoch keyring')
  }
  const keyB64 = Object.hasOwn(ring, parsed.e) ? ring[parsed.e] : undefined
  if (typeof keyB64 !== 'string') throw new EpochKeyUnavailableError(parsed.e)
  if (!parsed.fn !== !fileBuffer) {
    throw new EpochDecryptError('Envelope and attached file disagree')
  }

  const key = readKey(keyB64)
  let plain = null
  try {
    plain = open(Buffer.from(parsed.c, 'base64'), parsed.n, key)
    const value = plain.toString('utf8')
    if (!fileBuffer) return { value }

    const filePlain = open(fileBuffer, parsed.fn, key)
    try {
      return { value, file: Buffer.from(filePlain) }
    } finally {
      free(filePlain)
    }
  } finally {
    free(key)
    if (plain) free(plain)
  }
}

/** Plaintext of every epoch record's `check`. */
export const EPOCH_CHECK_CONSTANT = 'lockwright/epoch-check/v1'

/**
 * Key commitment for an epoch record: the constant sealed under its key.
 * @param {string} keyB64
 * @returns {{ n: string, c: string }}
 */
export const sealCheck = (keyB64) => {
  const key = readKey(keyB64)
  try {
    const { nonce, ciphertext } = seal(Buffer.from(EPOCH_CHECK_CONSTANT), key)
    return { n: nonce.toString('base64'), c: ciphertext.toString('base64') }
  } finally {
    free(key)
  }
}

/**
 * @param {{ n: string, c: string }} check
 * @param {unknown} keyB64
 * @returns {boolean} whether keyB64 is the key the check was sealed under
 */
export const opensCheck = (check, keyB64) => {
  if (!isEpochKey(keyB64) || typeof check?.c !== 'string') return false
  const key = readKey(keyB64)
  let plain = null
  try {
    plain = open(Buffer.from(check.c, 'base64'), check.n, key)
    return plain.toString('utf8') === EPOCH_CHECK_CONSTANT
  } catch {
    return false
  } finally {
    free(key)
    if (plain) free(plain)
  }
}

/** Domain prefix of a device row signature. */
export const DEVICE_ROW_CONSTANT = 'lockwright/device-row/v1'

const isLowerHex = (value, length) =>
  typeof value === 'string' &&
  value.length === length &&
  /^[0-9a-f]+$/.test(value)

// Null when a field has the wrong shape. The masterTopic is signed as the
// row spells it.
const deviceRowMessage = ({ vaultKeyHex, id, masterTopic, writerKey }) =>
  isLowerHex(vaultKeyHex, 64) &&
  typeof id === 'string' &&
  typeof masterTopic === 'string' &&
  MASTER_TOPIC.test(masterTopic) &&
  isLowerHex(writerKey, 64)
    ? Buffer.from(
        DEVICE_ROW_CONSTANT +
          JSON.stringify([vaultKeyHex, id, masterTopic, writerKey])
      )
    : null

/**
 * Signs a roster row as its writer, with the Hypercore writer key pair.
 * @param {{ secretKey: Buffer, vaultKeyHex: string, id: string,
 *   masterTopic: string, writerKey: string }} opts
 * @returns {string | null} detached Ed25519 signature hex, or null when a
 *   field has the wrong shape
 */
export const signDeviceRow = ({
  secretKey,
  vaultKeyHex,
  id,
  masterTopic,
  writerKey
}) => {
  const message = deviceRowMessage({ vaultKeyHex, id, masterTopic, writerKey })
  if (
    !message ||
    !Buffer.isBuffer(secretKey) ||
    secretKey.length !== sodium.crypto_sign_SECRETKEYBYTES
  ) {
    return null
  }
  const sig = Buffer.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(sig, message, secretKey)
  return sig.toString('hex')
}

/**
 * Whether the row's writer signed it for this vault. A writer key is the
 * hash of its core's manifest, not the signer's public key, so the row
 * carries `writerPublicKey` and it must hash to `writerKey`.
 * @param {unknown} row parsed `device/` value
 * @param {string} vaultKeyHex
 * @returns {boolean}
 */
export const verifyDeviceRow = (row, vaultKeyHex) => {
  if (!row || typeof row !== 'object') return false
  const { id, masterTopic, writerKey, writerPublicKey, sig } = row
  const message = deviceRowMessage({ vaultKeyHex, id, masterTopic, writerKey })
  if (!message || !isLowerHex(writerPublicKey, 64) || !isLowerHex(sig, 128)) {
    return false
  }
  try {
    const publicKey = Buffer.from(writerPublicKey, 'hex')
    return (
      Hypercore.key(publicKey).toString('hex') === writerKey &&
      sodium.crypto_sign_verify_detached(
        Buffer.from(sig, 'hex'),
        message,
        publicKey
      )
    )
  } catch {
    return false
  }
}
