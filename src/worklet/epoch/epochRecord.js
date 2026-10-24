import sodium from 'sodium-native'

// A bare RegExp.test would stringify ['<hex>'] and accept it.
const isHex = (value, length) =>
  typeof value === 'string' &&
  value.length === length &&
  /^[0-9a-f]+$/.test(value)

const VERSION = 1

/**
 * A device id is a non-empty, well-formed string: a lone surrogate would
 * sort as U+FFFD in the member order. Storage already turns one in a row
 * key into U+FFFD, so for roster ids the surrogate check is extra defence.
 * @param {unknown} id
 * @returns {boolean}
 */
export const isDeviceId = (id) =>
  typeof id === 'string' && id.length > 0 && id.isWellFormed()

// UTF-8 byte order is code-point order.
const byCodePoint = (a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b))

// An array, because JSON.stringify writes integer-like object keys first
// and in numeric order, whatever order they were added in.
const memberPairs = (members) =>
  Object.keys(members)
    .sort(byCodePoint)
    .map((id) => [id, { topic: members[id].topic, box: members[id].box }])

// `vault` is not stored: a record signed for one vault never verifies in
// another, where its author may also be a member.
const canonicalBytes = (
  { v, id, seq, prev, createdAt, by, members, check },
  vault
) =>
  Buffer.from(
    JSON.stringify({
      vault,
      v,
      id,
      seq,
      prev,
      createdAt,
      by,
      members: memberPairs(members),
      check: { n: check.n, c: check.c }
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
 *   members: Record<string, { topic: string, box: string }>
 *   check: { n: string, c: string }
 *   personalKeyPair: { publicKey: Buffer, secretKey: Buffer }
 *   createdAt?: number
 *   vault?: string | null
 * }} opts `vault`: the vault's Autobase key, hex
 */
export const buildEpochRecord = ({
  vault = null,
  id = generateEpochId(),
  seq,
  prev,
  members,
  check,
  personalKeyPair,
  createdAt = Date.now()
}) => {
  const record = {
    v: VERSION,
    id,
    seq,
    prev,
    createdAt,
    by: personalKeyPair.publicKey.toString('hex'),
    members: Object.assign(
      Object.create(null),
      Object.fromEntries(memberPairs(members))
    ),
    check: { n: check.n, c: check.c }
  }
  const sig = Buffer.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(
    sig,
    canonicalBytes(record, vault),
    personalKeyPair.secretKey
  )
  return { ...record, sig: sig.toString('hex') }
}

// Only signed fields: anything else would ride along unsigned.
const RECORD_FIELDS = [
  'v',
  'id',
  'seq',
  'prev',
  'createdAt',
  'by',
  'members',
  'check',
  'sig'
]
const MEMBER_FIELDS = ['topic', 'box']
const CHECK_FIELDS = ['n', 'c']

const hasOnly = (object, fields) =>
  Object.keys(object).every((field) => fields.includes(field))

const isMember = (member) =>
  !!member &&
  typeof member === 'object' &&
  hasOnly(member, MEMBER_FIELDS) &&
  isHex(member.topic, 64) &&
  typeof member.box === 'string'

const isObject = (value) =>
  !!value && typeof value === 'object' && !Array.isArray(value)

const isCheck = (check) =>
  isObject(check) &&
  hasOnly(check, CHECK_FIELDS) &&
  typeof check.n === 'string' &&
  typeof check.c === 'string'

const isWellFormed = (record) =>
  !!record &&
  typeof record === 'object' &&
  hasOnly(record, RECORD_FIELDS) &&
  record.v === VERSION &&
  isHex(record.id, 32) &&
  Number.isSafeInteger(record.seq) &&
  record.seq >= 1 &&
  (record.prev === null || isHex(record.prev, 32)) &&
  Number.isFinite(record.createdAt) &&
  isHex(record.by, 64) &&
  !!record.members &&
  typeof record.members === 'object' &&
  !Array.isArray(record.members) &&
  Object.keys(record.members).every(isDeviceId) &&
  Object.values(record.members).every(isMember) &&
  isCheck(record.check) &&
  isHex(record.sig, 128)

/**
 * Well-formed and signed by its `by` key. Says nothing about whether the
 * author may write epochs; see resolveEpochs.
 *
 * @param {unknown} record
 * @param {string | null} [vault] the vault's Autobase key, hex
 * @returns {boolean}
 */
export const verifySignature = (record, vault = null) => {
  if (!isWellFormed(record)) return false
  try {
    return sodium.crypto_sign_verify_detached(
      Buffer.from(record.sig, 'hex'),
      canonicalBytes(record, vault),
      Buffer.from(record.by, 'hex')
    )
  } catch {
    return false
  }
}

const rosterTopics = (roster) =>
  Array.isArray(roster)
    ? roster
        .map((row) => row?.masterTopic)
        .filter((topic) => typeof topic === 'string')
        .map((topic) => topic.toLowerCase())
    : []

const compare = (a, b) =>
  a.seq - b.seq || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)

/**
 * `valid`: every record that is well-formed, signed by its `by` key,
 * stored at `epoch/<its id>`, and the only one with its id. Rings are
 * opened from these whether they chain or not, so losing or rewriting one
 * record never costs the keys of the others.
 *
 * `accepted`: valid records that chain (seq 1 with no prev, or one more
 * than the chained record its prev names) and whose author is the
 * masterTopic of a current roster row. `latest` is the highest of these,
 * so a removed device's epochs, even ones it wrote while still a member,
 * never come back.
 *
 * @param {Array<{ key: string, value: unknown }>} entries
 * @param {Array<{ masterTopic?: string }>} roster
 * @param {{ verify?: (record: unknown, entry: object) => boolean }} [opts]
 * @returns {{ valid: object[], accepted: object[], latest: object | null }}
 */
export const resolveEpochs = (
  entries,
  roster,
  { verify = (record) => verifySignature(record) } = {}
) => {
  const byId = new Map()
  for (const entry of entries) {
    const { key, value: record } = entry
    if (key !== `epoch/${record?.id}`) continue
    if (!verify(record, entry)) continue
    byId.set(record.id, byId.has(record.id) ? null : record)
  }
  const valid = [...byId.values()].filter(Boolean).sort(compare)
  // A prev always has the lower seq, so one pass in seq order settles the
  // chain, and no seq can jump ahead of the records below it.
  const chained = new Map()
  for (const record of valid) {
    const prev = record.prev === null ? null : chained.get(record.prev)
    const linked =
      record.prev === null ? record.seq === 1 : record.seq === prev?.seq + 1
    if (linked) chained.set(record.id, record)
  }

  const authors = new Set(rosterTopics(roster))
  const accepted = [...chained.values()].filter((record) =>
    authors.has(record.by)
  )
  return { valid, accepted, latest: accepted.at(-1) ?? null }
}
