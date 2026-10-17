import sodium from 'sodium-native'

const HEX_32 = /^[0-9a-f]{32}$/
const HEX_64 = /^[0-9a-f]{64}$/
const HEX_128 = /^[0-9a-f]{128}$/

// v2: each member carries the topic its box is sealed to, so authorship can
// be traced through epochs after the author left the roster.
const VERSION = 2

const sortMembers = (members) =>
  Object.fromEntries(
    Object.keys(members)
      .sort()
      .map((id) => [id, { topic: members[id].topic, box: members[id].box }])
  )

const canonicalBytes = ({ v, id, seq, prev, createdAt, by, members }) =>
  Buffer.from(
    JSON.stringify({
      v,
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
 *   members: Record<string, { topic: string, box: string }>
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
    v: VERSION,
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

const isMember = (member) =>
  !!member &&
  typeof member === 'object' &&
  HEX_64.test(member.topic) &&
  typeof member.box === 'string'

const isWellFormed = (record) =>
  !!record &&
  typeof record === 'object' &&
  record.v === VERSION &&
  HEX_32.test(record.id) &&
  Number.isSafeInteger(record.seq) &&
  record.seq >= 1 &&
  (record.prev === null || HEX_32.test(record.prev)) &&
  Number.isFinite(record.createdAt) &&
  HEX_64.test(record.by) &&
  !!record.members &&
  typeof record.members === 'object' &&
  !Array.isArray(record.members) &&
  Object.values(record.members).every(isMember) &&
  HEX_128.test(record.sig)

/**
 * Well-formed and signed by its `by` key. Says nothing about whether the
 * author may write epochs; see resolveEpochs.
 *
 * @param {unknown} record
 * @returns {boolean}
 */
export const verifySignature = (record) => {
  if (!isWellFormed(record)) return false
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

const rosterTopics = (roster) =>
  Array.isArray(roster)
    ? roster
        .map((row) => row?.masterTopic)
        .filter((topic) => typeof topic === 'string')
        .map((topic) => topic.toLowerCase())
    : []

/**
 * Valid when signed and `by` is the masterTopic of a roster row.
 *
 * @param {object} record
 * @param {Array<{ masterTopic?: string }>} roster
 * @returns {boolean}
 */
export const verifyEpochRecord = (record, roster) =>
  verifySignature(record) && rosterTopics(roster).includes(record.by)

const compare = (a, b) =>
  a.seq - b.seq || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)

/**
 * `signed`: every record that is well-formed, signed, stored at
 * `epoch/<its id>`, and the only one with its id. Rings are opened from
 * these, and `highSeq` is their highest seq.
 *
 * `valid`: signed records whose author is trusted. Roster members are
 * trusted, and so is every member listed in a trusted record, to a fixpoint.
 * `latest` is the highest of these, so an epoch outlives its author's row.
 *
 * @param {Array<{ key: string, value: unknown }>} entries
 * @param {Array<{ masterTopic?: string }>} roster
 * @param {{ verify?: (record: unknown) => boolean }} [opts]
 * @returns {{ signed: object[], valid: object[], latest: object | null, highSeq: number }}
 */
export const resolveEpochs = (
  entries,
  roster,
  { verify = verifySignature } = {}
) => {
  const byId = new Map()
  for (const { key, value: record } of entries) {
    if (key !== `epoch/${record?.id}`) continue
    if (!verify(record)) continue
    byId.set(record.id, byId.has(record.id) ? null : record)
  }
  const signed = [...byId.values()].filter(Boolean).sort(compare)

  const trusted = new Set(rosterTopics(roster))
  const accepted = new Set()
  let grew = true
  while (grew) {
    grew = false
    for (const record of signed) {
      if (accepted.has(record) || !trusted.has(record.by)) continue
      accepted.add(record)
      grew = true
      for (const { topic } of Object.values(record.members)) trusted.add(topic)
    }
  }

  const valid = signed.filter((record) => accepted.has(record))
  return {
    signed,
    valid,
    latest: valid.at(-1) ?? null,
    highSeq: signed.at(-1)?.seq ?? 0
  }
}
