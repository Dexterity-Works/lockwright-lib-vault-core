import {
  generateEpochId,
  buildEpochRecord,
  resolveEpochs
} from './epochRecord.js'
import {
  EpochKeyUnavailableError,
  decryptValue,
  encryptValue,
  generateEpochKey,
  isEnvelope,
  openRing,
  sealRing
} from './keyring.js'

const RECORDS = '@autopass/records'
const MASTER_TOPIC = /^[0-9a-f]{64}$/i
const noopLogger = { warn: () => {} }

/** Keys that stay plaintext once the vault has an epoch. */
export const isPlaintextKey = (key) =>
  key === 'vault' || key.startsWith('device/') || key.startsWith('epoch/')

// HyperDB range over one key prefix: '0' is the character after '/'.
const prefixRange = (prefix) => ({
  gte: { key: prefix },
  lt: { key: `${prefix.slice(0, -1)}0` }
})

const sameSet = (a, b) => a.length === b.length && a.every((x) => b.includes(x))

/**
 * Adapter over an Autopass instance that encrypts values under the latest
 * membership epoch and decrypts with every epoch key this device can open.
 *
 * @param {{
 *   instance: import('autopass')
 *   getPersonalKeyPair: () => Promise<{ publicKey: Buffer, secretKey: Buffer }>
 *   logger?: { warn: (message: string, details?: object) => void }
 * }} opts
 */
export const createEpochStore = ({
  instance,
  getPersonalKeyPair,
  logger = noopLogger
}) => {
  let roster = []
  let epochs = { valid: [], latest: null }
  const ring = {}
  const openedRecords = new Set()
  const loggedKeys = new Set()
  let updates = 0
  let refreshedAt = -1
  let refreshing = Promise.resolve()
  let ensuring = null

  instance.on('update', () => {
    updates++
  })

  const logOnce = (key, message, details) => {
    if (loggedKeys.has(key)) return
    loggedKeys.add(key)
    logger.warn(message, { key, ...details })
  }

  const readPrefix = async (prefix) => {
    const rows = []
    for await (const record of instance.base.view.find(
      RECORDS,
      prefixRange(prefix)
    )) {
      try {
        rows.push({ key: record.key, value: JSON.parse(record.value) })
      } catch {
        logOnce(record.key, 'epochStore: unparsable row')
      }
    }
    return rows
  }

  const readRoster = async () =>
    (await readPrefix('device/'))
      .filter(({ value }) => value && typeof value === 'object')
      .map(({ key, value }) => ({ ...value, id: value.id ?? key.slice(7) }))

  const doRefresh = async () => {
    const startedAt = updates
    const keyPair = await getPersonalKeyPair()
    const nextRoster = await readRoster()
    const records = await readPrefix('epoch/')
    const next = resolveEpochs(
      records.map(({ value }) => value),
      nextRoster
    )

    for (const { key, value } of records) {
      if (!next.valid.includes(value)) {
        logOnce(key, 'epochStore: ignoring invalid epoch record')
      }
    }

    for (const record of next.valid) {
      const cacheKey = `${record.id}:${record.sig}`
      if (openedRecords.has(cacheKey)) continue
      openedRecords.add(cacheKey)
      for (const sealed of Object.values(record.members)) {
        const opened = openRing(sealed, keyPair)
        if (!opened) continue
        for (const [epochId, key] of Object.entries(opened)) {
          if (!(epochId in ring)) ring[epochId] = key
        }
        break
      }
    }

    roster = nextRoster
    epochs = next
    refreshedAt = startedAt
  }

  /** Re-read the roster and epoch records, opening any new rings. */
  const refresh = () => {
    refreshing = refreshing.then(doRefresh, doRefresh)
    return refreshing
  }

  const ensureFresh = () => (refreshedAt === updates ? refreshing : refresh())

  // Throws EpochKeyUnavailableError / EpochDecryptError for unreadable values.
  const decodeRecord = async (key, record, retried = false) => {
    if (isPlaintextKey(key) || !isEnvelope(record.value)) {
      return { value: record.value, file: record.file ?? null }
    }
    try {
      const out = decryptValue(record.value, ring, record.file || null)
      return { value: out.value, file: out.file ?? null }
    } catch (err) {
      // Retry once only when the view moved since the last refresh, so a
      // revoked device does not rescan per unreadable record.
      const stale = refreshedAt !== updates
      if (retried || !stale || !(err instanceof EpochKeyUnavailableError)) {
        throw err
      }
      await refresh()
      return decodeRecord(key, record, true)
    }
  }

  const readOrNull = async (key, record) => {
    try {
      return await decodeRecord(key, record)
    } catch (err) {
      logOnce(key, 'epochStore: unreadable record', { error: err.name })
      return null
    }
  }

  const add = async (key, value, file) => {
    // Always re-resolve before a write: a stale epoch would leak the value
    // to a device that was just removed.
    await refresh()
    const { latest } = epochs
    if (!latest || isPlaintextKey(key)) return instance.add(key, value, file)

    if (!ring[latest.id]) throw new EpochKeyUnavailableError(latest.id)
    const sealed = encryptValue(latest.id, ring[latest.id], value, file)
    return instance.add(key, sealed.envelope, sealed.file)
  }

  const get = async (key) => {
    await ensureFresh()
    const record = await instance.get(key)
    return record && readOrNull(key, record)
  }

  const find = async ({ gte, lte, gt, lt, limit, reverse } = {}) => {
    await ensureFresh()
    const results = []
    for await (const record of instance.base.view.find(RECORDS, {
      gte,
      lte,
      gt,
      lt,
      limit,
      reverse
    })) {
      const decoded = await readOrNull(record.key, record)
      if (decoded) results.push({ key: record.key, ...decoded })
    }
    return results
  }

  const remove = (key) => instance.remove(key)

  const coverage = () => {
    const sealable = new Map()
    const uncovered = []
    for (const row of roster) {
      if (
        typeof row.masterTopic === 'string' &&
        MASTER_TOPIC.test(row.masterTopic)
      ) {
        if (!sealable.has(row.id)) {
          sealable.set(row.id, { id: row.id, masterTopic: row.masterTopic })
        }
      } else {
        uncovered.push(row.id)
      }
    }
    return { sealable: [...sealable.values()], uncovered }
  }

  const isMe = (masterTopic, keyPair) =>
    masterTopic?.toLowerCase() === keyPair.publicKey.toString('hex')

  const rotate = async (sealable, uncovered, keyPair) => {
    const { latest } = epochs
    const id = generateEpochId()
    const key = generateEpochKey()
    const record = buildEpochRecord({
      id,
      seq: latest ? latest.seq + 1 : 1,
      prev: latest ? latest.id : null,
      members: sealRing({ ...ring, [id]: key }, sealable),
      personalKeyPair: keyPair
    })
    await instance.add(`epoch/${id}`, JSON.stringify(record))
    ring[id] = key
    await refresh()
    return {
      rotated: true,
      id,
      seq: record.seq,
      members: Object.keys(record.members),
      uncovered
    }
  }

  const doEnsureEpoch = async ({ start = false } = {}) => {
    await refresh()
    const keyPair = await getPersonalKeyPair()
    const { sealable, uncovered } = coverage()
    const skip = (reason) => ({ rotated: false, reason, uncovered })

    if (!instance.base.writable) return skip('not-writable')
    if (!sealable.some((row) => isMe(row.masterTopic, keyPair))) {
      return skip('self-not-in-roster')
    }
    const { latest } = epochs
    if (!latest)
      return start ? rotate(sealable, uncovered, keyPair) : skip('legacy')
    // A device that cannot open the latest ring would seal a ring without
    // the history; leave the rotation to a member that holds it.
    if (!ring[latest.id]) return skip('pending')
    if (
      sameSet(
        Object.keys(latest.members),
        sealable.map((row) => row.id)
      )
    ) {
      return skip('current')
    }
    return rotate(sealable, uncovered, keyPair)
  }

  /**
   * @param {{ start?: boolean }} [opts]
   */
  const ensureEpoch = (opts) => {
    if (!ensuring) {
      ensuring = doEnsureEpoch(opts).finally(() => {
        ensuring = null
      })
    }
    return ensuring
  }

  const status = async () => {
    await ensureFresh()
    const keyPair = await getPersonalKeyPair()
    const { latest } = epochs
    const canRead = !latest || !!ring[latest.id]
    return {
      epoch: latest ? latest.id : null,
      seq: latest ? latest.seq : 0,
      legacy: !latest,
      canRead,
      revoked:
        !!latest &&
        !canRead &&
        !roster.some((row) => isMe(row.masterTopic, keyPair)),
      members: latest ? Object.keys(latest.members).sort() : [],
      uncovered: coverage().uncovered
    }
  }

  return { add, get, find, remove, refresh, ensureEpoch, status }
}
