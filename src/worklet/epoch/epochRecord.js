import sodium from 'sodium-native'

const HEX_32 = /^[0-9a-f]{32}$/
const HEX_64 = /^[0-9a-f]{64}$/
const HEX_128 = /^[0-9a-f]{128}$/

const sortMembers = (members) =>
  Object.fromEntries(
    Object.keys(members)
      .sort()
      .map((id) => [id, members[id]])
  )

const canonicalBytes = ({ id, seq, prev, createdAt, by, members }) =>
  Buffer.from(
    JSON.stringify({
      id,
      seq,
      prev,
      createdAt,
      by,
      members: sortMembers(members)
    })
  )

/**
 * @returns {string} 16 random bytes, hex
 */
export const generateEpochId = () => {
  const id = Buffer.alloc(16)
  sodium.randombytes_buf(id)
  return id.toString('hex')
}

/**
 * @param {{
 *   id?: string
 *   seq: number
 *   prev: string | null
 *   members: Record<string, string>
 *   personalKeyPair: { publicKey: Buffer, secretKey: Buffer }
 *   createdAt?: number
 * }} opts
 */
export const buildEpochRecord = ({
  id = generateEpochId(),
  seq,
  prev,
  members,
  personalKeyPair,
  createdAt = Date.now()
}) => {
  const record = {
    id,
    seq,
    prev,
    createdAt,
    by: personalKeyPair.publicKey.toString('hex'),
    members: sortMembers(members)
  }
  const sig = Buffer.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(
    sig,
    canonicalBytes(record),
    personalKeyPair.secretKey
  )
  return { ...record, sig: sig.toString('hex') }
}

const isWellFormed = (record) =>
  !!record &&
  typeof record === 'object' &&
  HEX_32.test(record.id) &&
  Number.isSafeInteger(record.seq) &&
  record.seq >= 1 &&
  (record.prev === null || HEX_32.test(record.prev)) &&
  Number.isFinite(record.createdAt) &&
  HEX_64.test(record.by) &&
  !!record.members &&
  typeof record.members === 'object' &&
  !Array.isArray(record.members) &&
  Object.values(record.members).every((box) => typeof box === 'string') &&
  HEX_128.test(record.sig)

/**
 * Valid when `by` is the masterTopic of a roster row and `sig` verifies.
 *
 * @param {object} record
 * @param {Array<{ masterTopic?: string }>} roster
 * @returns {boolean}
 */
export const verifyEpochRecord = (record, roster) => {
  if (!isWellFormed(record) || !Array.isArray(roster)) return false
  const authorInRoster = roster.some(
    (row) =>
      typeof row?.masterTopic === 'string' &&
      row.masterTopic.toLowerCase() === record.by
  )
  if (!authorInRoster) return false
  try {
    return sodium.crypto_sign_verify_detached(
      Buffer.from(record.sig, 'hex'),
      canonicalBytes(record),
      Buffer.from(record.by, 'hex')
    )
  } catch {
    return false
  }
}

const compare = (a, b) =>
  a.seq - b.seq || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)

/**
 * The signature does not cover the storage key, so a record only counts at
 * `epoch/<its id>`, and an id claimed twice is dropped entirely.
 *
 * @param {Array<{ key: string, value: unknown }>} entries
 * @param {Array<{ masterTopic?: string }>} roster
 * @returns {{ valid: object[], latest: object | null }}
 */
export const resolveEpochs = (entries, roster) => {
  const byId = new Map()
  for (const { key, value: record } of entries) {
    if (key !== `epoch/${record?.id}`) continue
    if (!verifyEpochRecord(record, roster)) continue
    byId.set(record.id, byId.has(record.id) ? null : record)
  }
  const valid = [...byId.values()].filter(Boolean).sort(compare)
  return { valid, latest: valid.at(-1) ?? null }
}
