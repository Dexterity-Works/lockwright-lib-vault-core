import {
  generateEpochId,
  buildEpochRecord,
  resolveEpochs
} from './epochRecord.js'
import {
  canSealTo,
  EpochKeyUnavailableError,
  EpochRecordWriteError,
  EpochRotationPendingError,
  decryptValue,
  encryptValue,
  generateEpochKey,
  isEnvelope,
  openRing,
  sealRing
} from './keyring.js'

const RECORDS = '@autopass/records'
const noopLogger = { warn: () => {} }

/** Keys that stay plaintext once the vault has an epoch. */
export const isPlaintextKey = (key) =>
  key === 'vault' || key.startsWith('device/') || key.startsWith('epoch/')

// HyperDB range over one key prefix: '0' is the character after '/'.
const prefixRange = (prefix) => ({
  gte: { key: prefix },
  lt: { key: `${prefix.slice(0, -1)}0` }
})

const refuseEpochKey = (key) => {
  if (typeof key === 'string' && key.startsWith('epoch/')) {
    throw new EpochRecordWriteError(key)
  }
}

const sameSet = (a, b) => a.length === b.length && a.every((x) => b.includes(x))

/**
 * Adapter over an Autopass instance that encrypts values under the latest
 * membership epoch and decrypts with every epoch key this device can open.
 *
 * @param {{
 *   instance: import('autopass')
 *   getPersonalKeyPair: () => Promise<{ publicKey: Buffer, secretKey: Buffer }>
 *   vaultId?: string | null
 *   logger?: { warn: (message: string, details?: object) => void }
 * }} opts
 */
export const createEpochStore = ({
  instance,
  getPersonalKeyPair,
  vaultId = null,
  logger = noopLogger
}) => {
  let roster = []
  let epochs = { signed: [], valid: [], latest: null, highSeq: 0 }
  const ring = Object.create(null)
  const openedRecords = new Set()
  const loggedKeys = new Set()
  let updates = 0
  let refreshedAt = -1
  let refreshing = Promise.resolve()
  let ensuring = null
  /** @type {{ start: boolean, promise: Promise<object> } | null} */
  let queued = null
  // A start that could not run (kick while not writable, say) stays owed:
  // the roster rows are gone, so nothing else would start the epoch.
  let startOwed = false

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
      .map(({ key, value }) => ({
        ...value,
        id: value.id ?? key.slice(7),
        // Anything but a usable key string counts as no masterTopic.
        masterTopic: canSealTo(value.masterTopic)
          ? value.masterTopic
          : undefined
      }))

  const doRefresh = async () => {
    const startedAt = updates
    const keyPair = await getPersonalKeyPair()
    const nextRoster = await readRoster()
    const records = await readPrefix('epoch/')
    const next = resolveEpochs(records, nextRoster)

    for (const { key, value } of records) {
      if (!next.signed.includes(value)) {
        logOnce(key, 'epochStore: ignoring invalid epoch record')
      }
    }

    // Any signed record may hold a box for me, even one whose author is no
    // longer trusted: opening it never hurts.
    const myTopic = keyPair.publicKey.toString('hex')
    for (const record of next.signed) {
      const cacheKey = `${record.id}:${record.sig}`
      if (openedRecords.has(cacheKey)) continue
      openedRecords.add(cacheKey)
      for (const { topic, box } of Object.values(record.members)) {
        if (topic !== myTopic) continue
        const opened = openRing(box, keyPair)
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
    refuseEpochKey(key)
    // Always re-resolve before a write: a stale epoch would leak the value
    // to a device that was just removed.
    await refresh()
    if (isPlaintextKey(key) || !epochs.signed.length) {
      return instance.add(key, value, file)
    }

    if (isStale()) {
      const keyPair = await getPersonalKeyPair()
      const canRotate =
        instance.base.writable &&
        coverage().sealable.some((row) => isMe(row.masterTopic, keyPair))
      if (canRotate) await ensureEpoch({ start: true })
      if (isStale()) throw new EpochRotationPendingError()
    }

    const { latest } = epochs
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

  const remove = async (key) => {
    refuseEpochKey(key)
    return instance.remove(key)
  }

  const coverage = () => {
    const sealable = new Map()
    const sealedWriters = new Set()
    const rest = []
    for (const row of roster) {
      if (canSealTo(row.masterTopic)) {
        if (!sealable.has(row.id)) {
          sealable.set(row.id, { id: row.id, masterTopic: row.masterTopic })
        }
        if (row.writerKey) sealedWriters.add(row.writerKey)
      } else {
        rest.push(row)
      }
    }
    // A row without masterTopic that shares a writer with a sealable row is
    // a stale copy of a device that already has a key.
    const uncovered = rest
      .filter((row) => !row.writerKey || !sealedWriters.has(row.writerKey))
      .map((row) => row.id)
    return { sealable: [...sealable.values()], uncovered }
  }

  const memberPairs = (record) =>
    Object.entries(record.members).map(([id, { topic }]) => `${id}:${topic}`)

  const sealablePairs = (sealable) =>
    sealable.map((row) => `${row.id}:${row.masterTopic.toLowerCase()}`)

  // Never write under an epoch sealed to someone outside the roster. Once a
  // signed epoch exists, a missing latest means a rotation is owed too.
  const isStale = () => {
    const { latest, signed } = epochs
    if (!signed.length) return false
    if (!latest) return true
    const allowed = sealablePairs(coverage().sealable)
    return !memberPairs(latest).every((pair) => allowed.includes(pair))
  }

  const isMe = (masterTopic, keyPair) =>
    typeof masterTopic === 'string' &&
    masterTopic.toLowerCase() === keyPair.publicKey.toString('hex')

  const rotate = async (sealable, uncovered, keyPair) => {
    const { latest, highSeq } = epochs
    const id = generateEpochId()
    const key = generateEpochKey()
    const boxes = sealRing({ ...ring, [id]: key }, sealable)
    const members = {}
    for (const row of sealable) {
      if (boxes[row.id]) {
        members[row.id] = {
          topic: row.masterTopic.toLowerCase(),
          box: boxes[row.id]
        }
      }
    }
    // Seq comes from every signed record, so latest never moves backwards.
    const record = buildEpochRecord({
      id,
      seq: highSeq + 1,
      prev: latest ? latest.id : null,
      members,
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
    const { latest, signed } = epochs
    if (!signed.length) {
      return start ? rotate(sealable, uncovered, keyPair) : skip('legacy')
    }
    // No trusted latest while signed epochs exist: a rotation is owed.
    if (!latest) return rotate(sealable, uncovered, keyPair)
    // A device that cannot open the latest ring would seal a ring without
    // the history; leave the rotation to a member that holds it.
    if (!ring[latest.id]) return skip('pending')
    if (sameSet(memberPairs(latest), sealablePairs(sealable))) {
      return skip('current')
    }
    return rotate(sealable, uncovered, keyPair)
  }

  const runEnsure = (start) => {
    const owed = start || startOwed
    const run = doEnsureEpoch({ start: owed })
      .then(
        (result) => {
          const settled =
            result.rotated ||
            result.reason === 'current' ||
            result.reason === 'pending'
          startOwed = settled ? false : owed
          return result
        },
        (error) => {
          if (owed) startOwed = true
          throw error
        }
      )
      .finally(() => {
        if (ensuring === run) ensuring = null
      })
    ensuring = run
    return run
  }

  /**
   * One run at a time. Callers that arrive during a run share exactly one
   * follow-up run, which starts an epoch if any of them asked to.
   * @param {{ start?: boolean }} [opts]
   */
  const ensureEpoch = ({ start = false } = {}) => {
    if (queued) {
      queued.start ||= start
      return queued.promise
    }
    if (!ensuring) return runEnsure(start)
    const next = { start }
    next.promise = ensuring
      .catch(() => {})
      .then(() => {
        queued = null
        return runEnsure(next.start)
      })
    queued = next
    return next.promise
  }

  const status = async () => {
    await ensureFresh()
    const keyPair = await getPersonalKeyPair()
    const { latest, signed } = epochs
    const legacy = !signed.length
    const canRead = legacy || (!!latest && !!ring[latest.id])
    return {
      vaultId,
      epoch: latest ? latest.id : null,
      seq: latest ? latest.seq : 0,
      legacy,
      canRead,
      // Only a device that once held a key and wrote here was let go. A
      // legacy row, a joiner whose row has not landed yet, or a kicked
      // device pairing again on a fresh store is waiting, not revoked.
      revoked:
        !!latest &&
        !canRead &&
        Object.keys(ring).length > 0 &&
        instance.base.local?.length > 0 &&
        !roster.some((row) => isMe(row.masterTopic, keyPair)),
      members: latest ? Object.keys(latest.members).sort() : [],
      uncovered: coverage().uncovered
    }
  }

  return { add, get, find, remove, refresh, ensureEpoch, status }
}
