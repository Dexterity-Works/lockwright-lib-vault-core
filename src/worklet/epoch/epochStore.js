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
  opensCheck,
  sealCheck,
  sealRing
} from './keyring.js'

const RECORDS = '@autopass/records'
// Local core userData, so an owed start survives a restart.
const START_OWED = 'lockwright/epoch-start-owed'
const noopLogger = { warn: () => {} }
// The owed start could not be read, so nobody knows whether it is owed.
const OWED_UNREAD = Symbol('owed start unread')

/**
 * Keys that stay plaintext once the vault has an epoch. `vault-ext` is
 * migration metadata, and a device that cannot read records must still see it.
 */
export const isPlaintextKey = (key) =>
  key === 'vault' ||
  key === 'vault-ext' ||
  key.startsWith('device/') ||
  key.startsWith('epoch/')

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
  let epochs = { signed: [], accepted: [], latest: null }
  // epochId -> key b64, only keys that open their record's check.
  let ring = Object.create(null)
  // epochId -> every key b64 an opened box offered for it.
  const offered = new Map()
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
  // Null until read from the local core.
  let startOwed = null

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

  const offer = (epochId, key) => {
    if (!offered.has(epochId)) offered.set(epochId, new Set())
    offered.get(epochId).add(key)
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

    // Any signed record may hold a box for me, whoever wrote it: a key it
    // offers counts only once it opens the check of the epoch it names.
    const myTopic = keyPair.publicKey.toString('hex')
    for (const record of next.signed) {
      const cacheKey = `${record.id}:${record.sig}`
      if (openedRecords.has(cacheKey)) continue
      openedRecords.add(cacheKey)
      for (const { topic, box } of Object.values(record.members)) {
        if (topic !== myTopic) continue
        const opened = openRing(box, keyPair)
        if (!opened) continue
        for (const [epochId, key] of Object.entries(opened)) offer(epochId, key)
        break
      }
    }
    const nextRing = Object.create(null)
    for (const record of next.signed) {
      for (const key of offered.get(record.id) ?? []) {
        if (opensCheck(record.check, key)) {
          nextRing[record.id] = key
          break
        }
      }
    }

    ring = nextRing
    roster = nextRoster
    epochs = next
    refreshedAt = startedAt
  }

  // A failed refresh leaves the store stale, so the next read tries again
  // instead of replaying the rejection until the next update.
  const tryRefresh = async () => {
    try {
      await doRefresh()
    } catch (error) {
      refreshedAt = -1
      throw error
    }
  }

  /** Re-read the roster and epoch records, opening any new rings. */
  const refresh = () => {
    refreshing = refreshing.then(tryRefresh, tryRefresh)
    return refreshing
  }

  const ensureFresh = () => (refreshedAt === updates ? refreshing : refresh())

  // Throws EpochKeyUnavailableError / EpochDecryptError for unreadable values.
  // `pass` is shared by every row of one get or find call, so the call
  // refreshes at most once however many rows it cannot read.
  const decodeRecord = async (key, record, pass) => {
    if (isPlaintextKey(key) || !isEnvelope(record.value)) {
      return { value: record.value, file: record.file ?? null }
    }
    try {
      const out = decryptValue(record.value, ring, record.file || null)
      return { value: out.value, file: out.file ?? null }
    } catch (err) {
      // Retry only when the view moved since the last refresh.
      const stale = refreshedAt !== updates
      if (
        pass.retried ||
        !stale ||
        !(err instanceof EpochKeyUnavailableError)
      ) {
        throw err
      }
      pass.retried = true
      await refresh()
      return decodeRecord(key, record, pass)
    }
  }

  const readOrNull = async (key, record, pass = { retried: false }) => {
    try {
      return await decodeRecord(key, record, pass)
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

  /**
   * Rows this device cannot read are left out and reported to onUnreadable.
   * @param {{ gte?, lte?, gt?, lt?, limit?: number, reverse?: boolean,
   *   onUnreadable?: (key: string) => void }} [opts]
   */
  const find = async ({
    gte,
    lte,
    gt,
    lt,
    limit,
    reverse,
    onUnreadable
  } = {}) => {
    await ensureFresh()
    const results = []
    // Unreadable rows do not count toward the limit, so read the view
    // unbounded and stop once enough rows decoded.
    const max = limit ?? Infinity
    const pass = { retried: false }
    for await (const record of instance.base.view.find(RECORDS, {
      gte,
      lte,
      gt,
      lt,
      reverse
    })) {
      if (results.length >= max) break
      const decoded = await readOrNull(record.key, record, pass)
      if (decoded) results.push({ key: record.key, ...decoded })
      else onUnreadable?.(record.key)
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

  // Null when the appended record did not resolve as the latest epoch.
  const rotate = async (sealable, uncovered, keyPair) => {
    const { latest } = epochs
    const seq = latest ? latest.seq + 1 : 1
    if (!Number.isSafeInteger(seq)) {
      throw new Error(`Epoch seq ${seq} is not a safe integer`)
    }
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
    const record = buildEpochRecord({
      id,
      seq,
      prev: latest ? latest.id : null,
      members,
      check: sealCheck(key),
      personalKeyPair: keyPair
    })
    offer(id, key)
    await instance.add(`epoch/${id}`, JSON.stringify(record))
    await refresh()
    if (epochs.latest?.id !== id) return null
    return {
      rotated: true,
      id,
      seq: record.seq,
      members: Object.keys(record.members),
      uncovered
    }
  }

  const doEnsureEpoch = async ({ start = false } = {}, retried = false) => {
    await refresh()
    const keyPair = await getPersonalKeyPair()
    const { sealable, uncovered } = coverage()
    const skip = (reason) => ({ rotated: false, reason, uncovered })
    const rotateNow = async () => {
      const result = await rotate(sealable, uncovered, keyPair)
      if (result) return result
      // Another epoch resolved above the one just appended: judge that one.
      if (retried) throw new Error('Epoch rotation did not resolve as latest')
      return doEnsureEpoch({ start }, true)
    }

    if (!instance.base.writable) return skip('not-writable')
    if (!sealable.some((row) => isMe(row.masterTopic, keyPair))) {
      return skip('self-not-in-roster')
    }
    const { latest, signed } = epochs
    if (!signed.length) {
      return start ? rotateNow() : skip('legacy')
    }
    // No epoch by a roster member while signed epochs exist: a rotation is
    // owed.
    if (!latest) return rotateNow()
    // A device that cannot open the latest ring would seal a ring without
    // the history; leave the rotation to a member that holds it.
    if (!ring[latest.id]) return skip('pending')
    if (sameSet(memberPairs(latest), sealablePairs(sealable))) {
      return skip('current')
    }
    return rotateNow()
  }

  const readStartOwed = async () => {
    if (startOwed !== null) return startOwed
    try {
      const stored = await instance.base.local.getUserData(START_OWED)
      startOwed = stored?.toString() === '1'
      return startOwed
    } catch (error) {
      logger.warn('epochStore: could not read the owed start', {
        error: error?.name
      })
      return OWED_UNREAD
    }
  }

  const writeStartOwed = async (owed) => {
    if (owed === startOwed) return
    startOwed = owed
    try {
      await instance.base.local.setUserData(
        START_OWED,
        Buffer.from(owed ? '1' : '0')
      )
    } catch (error) {
      logger.warn('epochStore: could not persist the owed start', {
        error: error?.name
      })
    }
  }

  const runEnsure = (start) => {
    const run = (async () => {
      const stored = start || (await readStartOwed())
      const owed = stored === true
      let result
      try {
        result = await doEnsureEpoch({ start: owed })
      } catch (error) {
        if (owed) await writeStartOwed(true)
        throw error
      }
      const settled =
        result.rotated ||
        result.reason === 'current' ||
        result.reason === 'pending'
      // A run that could not read the flag must not overwrite it.
      if (stored !== OWED_UNREAD) await writeStartOwed(settled ? false : owed)
      return result
    })().finally(() => {
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

  // My row is the one with my masterTopic, or with my writer key when it
  // has none (a legacy or not yet healed row).
  const isMyRow = (row, keyPair) => {
    if (isMe(row.masterTopic, keyPair)) return true
    const writerKey = instance.writerKey?.toString('hex')
    return (
      !!writerKey &&
      typeof row.writerKey === 'string' &&
      row.writerKey.toLowerCase() === writerKey
    )
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
        !roster.some((row) => isMyRow(row, keyPair)),
      members: latest ? Object.keys(latest.members).sort() : [],
      uncovered: coverage().uncovered
    }
  }

  return { add, get, find, remove, refresh, ensureEpoch, status }
}
