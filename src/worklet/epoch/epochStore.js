import {
  generateEpochId,
  buildEpochRecord,
  isDeviceId,
  resolveEpochs,
  verifySignature
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
  sealRing,
  signDeviceRow,
  verifyDeviceRow
} from './keyring.js'

const RECORDS = '@autopass/records'
// Local core userData, so an owed start survives a restart.
const START_OWED = 'lockwright/epoch-start-owed'
// Local core userData: this device saw an epoch row, so the vault never
// goes back to plaintext, even once every epoch row is gone.
const EPOCH_SEEN = 'lockwright/epoch-seen'
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

// A rotation whose retry was overtaken by another epoch too.
class RotationOvertakenError extends Error {
  constructor() {
    super('Epoch rotation did not resolve as latest')
    this.name = 'RotationOvertakenError'
  }
}

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
  let epochs = { valid: [], accepted: [], latest: null }
  // No row under `epoch/` at all, valid or not, and none ever seen here:
  // plaintext mode.
  let legacy = true
  let epochSeen = false
  let epochSeenRead = false
  // epochId -> key b64, only keys that open their record's check.
  let ring = Object.create(null)
  // epochId -> every key b64 an opened box offered for it.
  const offered = new Map()
  // `${id}:${sig}` -> the ring my box in that record held, or null.
  const openedBoxes = new Map()
  // `${key}:${sig}` -> { raw, ok }. The raw value is part of the hit, so a
  // row rewritten under the same key with a copied sig is verified again.
  const verified = new Map()
  // `${id}:${sig}:${key}` -> whether the key opens that record's check. The
  // sig covers the check, so a record rewritten under its id is checked again.
  const checked = new Map()
  const loggedKeys = new Set()
  let updates = 0
  let refreshedAt = -1
  let refreshing = Promise.resolve()
  let ensuring = null
  /** @type {{ start: boolean, promise: Promise<object> } | null} */
  let queued = null
  // A start that could not run (kick while not writable, say) stays owed:
  // the roster rows are gone, so nothing else would start the epoch.
  // What the local core holds: null until read, and again once a write
  // failed.
  let startOwed = null
  // Owed here but not yet written: the next run writes it again.
  let unsavedOwed = false

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
        rows.push({
          key: record.key,
          value: JSON.parse(record.value),
          raw: record.value
        })
      } catch {
        // Kept, so an unparsable epoch row still ends plaintext mode.
        rows.push({ key: record.key, value: null, raw: record.value })
        logOnce(record.key, 'epochStore: unparsable row')
      }
    }
    return rows
  }

  const offer = (epochId, key) => {
    if (!offered.has(epochId)) offered.set(epochId, new Set())
    offered.get(epochId).add(key)
  }

  const bound = (rows) => rows.filter((row) => row.bound)

  const isWriterKey = (key) =>
    typeof key === 'string' && /^[0-9a-f]{64}$/.test(key)

  /**
   * Well-formed `device/` rows. A row is the device its key names, and must
   * say so in `id`: lib-vault lists and sweeps rows by `value.id`, so a row
   * without it could not be kicked. A malformed row is not sealed to, not an
   * author, and not uncovered.
   *
   * A row is `bound` when its writer signed it for this vault (see
   * verifyDeviceRow) and `base.system` holds that writer, present and not
   * removed. Autopass stores a row whoever appended it, and Autobase can
   * order a removed writer's concurrent append before the removal, so only a
   * bound row is sealed to or counts as an author. An unbound row is
   * uncovered: an older build's unsigned row, or one a kicked device planted
   * under its own or another writer key. A row whose writer was removed is
   * `removed`: it is not bound while its writer stays removed, and a writer
   * added again binds again, so it is not uncovered either. Residual: a
   * planted row with no writerKey or an unknown one is still listed as
   * uncovered under the name it carries. Rows have no prototype, so a field
   * the row lacks never comes from Object.prototype.
   */
  const readRoster = async () => {
    const rows = (await readPrefix('device/'))
      .map(({ key, value, raw }) => ({
        id: key.slice('device/'.length),
        value,
        raw
      }))
      .filter(
        ({ id, value }) =>
          isDeviceId(id) &&
          !!value &&
          typeof value === 'object' &&
          value.id === id
      )
    // One system lookup per writer key: whether it is removed, or null for
    // a writer the system never added.
    const writerKeys = [
      ...new Set(rows.map(({ value }) => value.writerKey).filter(isWriterKey))
    ]
    const removed = new Map(
      await Promise.all(
        writerKeys.map(async (writerKey) => {
          const info = await instance.base.system?.get(
            Buffer.from(writerKey, 'hex')
          )
          return [writerKey, info ? info.isRemoved === true : null]
        })
      )
    )
    const vaultKeyHex = instance.base.key?.toString('hex')
    return rows.map(({ id, value, raw }) => {
      const signed = verifyDeviceRow(value, vaultKeyHex)
      return Object.assign(Object.create(null), value, {
        id,
        // Anything but a usable key string counts as no masterTopic.
        masterTopic: canSealTo(value.masterTopic)
          ? value.masterTopic
          : undefined,
        bound: signed && removed.get(value.writerKey) === false,
        removed: removed.get(value.writerKey) === true,
        signed,
        raw
      })
    })
  }

  const vaultKeyHex = () => instance.base.key?.toString('hex') ?? null

  const verifyOnce = (record, { key, raw }) => {
    const cacheKey = `${key}:${record?.sig}`
    const hit = verified.get(cacheKey)
    if (hit?.raw === raw) return hit.ok
    const ok = verifySignature(record, vaultKeyHex())
    verified.set(cacheKey, { raw, ok })
    return ok
  }

  const doRefresh = async () => {
    const startedAt = updates
    const keyPair = await getPersonalKeyPair()
    const nextRoster = await readRoster()
    const records = await readPrefix('epoch/')
    const next = resolveEpochs(records, bound(nextRoster), {
      verify: verifyOnce
    })

    const valid = new Set(next.valid)
    for (const { key, value } of records) {
      if (!valid.has(value)) {
        logOnce(key, 'epochStore: ignoring invalid epoch record')
      }
    }

    // Any valid record may hold a box for me, whoever wrote it: a key it
    // offers counts only once it opens the check of the epoch it names.
    const myTopic = keyPair.publicKey.toString('hex')
    for (const record of next.valid) {
      const cacheKey = `${record.id}:${record.sig}`
      if (openedBoxes.has(cacheKey)) continue
      openedBoxes.set(cacheKey, null)
      for (const { topic, box } of Object.values(record.members)) {
        if (topic !== myTopic) continue
        const opened = openRing(box, keyPair)
        if (!opened) continue
        for (const [epochId, key] of Object.entries(opened)) offer(epochId, key)
        openedBoxes.set(cacheKey, opened)
        break
      }
    }
    const nextRing = Object.create(null)
    for (const record of next.valid) {
      for (const key of offered.get(record.id) ?? []) {
        const cacheKey = `${record.id}:${record.sig}:${key}`
        if (!checked.has(cacheKey)) {
          checked.set(cacheKey, opensCheck(record.check, key))
        }
        if (checked.get(cacheKey)) {
          nextRing[record.id] = key
          break
        }
      }
    }

    if (records.length > 0 && !epochSeen) {
      epochSeen = true
      // Not awaited: this run already holds the flag in memory.
      instance.base.local
        .setUserData(EPOCH_SEEN, Buffer.from('1'))
        .catch((error) => {
          logger.warn('epochStore: could not persist the epoch mode', {
            error: error?.name
          })
        })
    } else if (!epochSeen && !epochSeenRead) {
      // A read that fails fails the refresh: guessing plaintext would leak.
      const stored = await instance.base.local.getUserData(EPOCH_SEEN)
      epochSeen = stored?.toString() === '1'
      epochSeenRead = true
    }

    ring = nextRing
    roster = nextRoster
    epochs = next
    legacy = !epochSeen
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

  // Already fresh: another caller's refresh failing does not make this
  // read fail.
  const ensureFresh = () =>
    refreshedAt === updates ? refreshing.catch(() => {}) : refresh()

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

  // My writer signs a device row that names it; any other row is stored
  // as given and stays unbound.
  const signRow = (key, value) => {
    if (!key.startsWith('device/') || !instance.base.writable) return value
    let row
    try {
      row = JSON.parse(value)
    } catch {
      return value
    }
    const { local } = instance.base
    if (
      !row ||
      typeof row !== 'object' ||
      row.writerKey !== instance.writerKey?.toString('hex') ||
      !local?.keyPair
    ) {
      return value
    }
    const sig = signDeviceRow({
      secretKey: local.keyPair.secretKey,
      vaultKeyHex: instance.base.key?.toString('hex'),
      id: row.id,
      masterTopic: row.masterTopic,
      writerKey: row.writerKey
    })
    if (!sig) return value
    return JSON.stringify({
      ...row,
      writerPublicKey: local.keyPair.publicKey.toString('hex'),
      sig
    })
  }

  /**
   * Values under `vault`, `vault-ext`, `device/` and `epoch/` stay
   * plaintext; anything else is sealed under the latest epoch once one
   * exists. A `device/` row whose `writerKey` is this device's writer is
   * signed first, when the base is writable, so it binds (see readRoster).
   */
  const add = async (key, value, file) => {
    refuseEpochKey(key)
    // Always re-resolve before a write: a stale epoch would leak the value
    // to a device that was just removed.
    await refresh()
    if (isPlaintextKey(key) || legacy) {
      return instance.add(key, signRow(key, value), file)
    }

    if (isStale()) {
      const keyPair = await getPersonalKeyPair()
      const canRotate =
        instance.base.writable &&
        coverage().sealable.some((row) => isMe(row.masterTopic, keyPair))
      if (canRotate) {
        try {
          await ensureEpoch({ start: true })
        } catch (error) {
          // Whoever won may have left latest current: judge it below.
          if (!(error instanceof RotationOvertakenError)) throw error
        }
      }
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
      if (row.bound && canSealTo(row.masterTopic)) {
        if (!sealable.has(row.id)) {
          sealable.set(row.id, { id: row.id, masterTopic: row.masterTopic })
        }
        if (row.writerKey) sealedWriters.add(row.writerKey)
      } else {
        rest.push(row)
      }
    }
    // An unsealable row that shares a writer with a sealable row is a stale
    // copy of a device that already has a key, or a row planted under a
    // member's writer key. A removed writer's row is not listed: a kicked
    // device could put a name of its choosing into every later warning.
    const uncovered = rest
      .filter(
        (row) =>
          !row.removed && (!row.writerKey || !sealedWriters.has(row.writerKey))
      )
      .map((row) => row.id)
    return { sealable: [...sealable.values()], uncovered }
  }

  const memberPairs = (record) =>
    Object.entries(record.members).map(([id, { topic }]) => `${id}:${topic}`)

  const sealablePairs = (sealable) =>
    sealable.map((row) => `${row.id}:${row.masterTopic.toLowerCase()}`)

  // A record above latest by a current author, whose key I hold and
  // latest's box for me lacks: the chain under it broke (a deleted or
  // rewritten record), so latest is older than the history and its key may
  // have reached a removed device through the missing record's box.
  const skippedAhead = (latest) => {
    const box = openedBoxes.get(`${latest.id}:${latest.sig}`)
    const authors = new Set(
      bound(roster).flatMap((row) => row.masterTopic?.toLowerCase() ?? [])
    )
    return epochs.valid.some(
      (record) =>
        record.seq > latest.seq &&
        authors.has(record.by) &&
        Object.hasOwn(ring, record.id) &&
        box?.[record.id] !== ring[record.id]
    )
  }

  // Never write under an epoch sealed to someone outside the roster. Once an
  // epoch row exists, a missing latest means a rotation is owed too.
  const isStale = () => {
    if (legacy) return false
    const { latest } = epochs
    if (!latest) return true
    if (skippedAhead(latest)) return true
    const allowed = sealablePairs(coverage().sealable)
    return !memberPairs(latest).every((pair) => allowed.includes(pair))
  }

  // A key I hold that latest's box for me lacks: its author sealed a
  // partial ring (a chain restarted by a joiner, say), so the other members
  // may lack it too. Only keys of epochs I wrote, or whose author left, or
  // whose record did not seal to every member of latest, count: another
  // current member carries its own, but not to a device that joined after
  // it. Otherwise both sides of a same-seq race hold the other's key and
  // rotate forever.
  const holdsMoreThan = (latest, keyPair) => {
    // openRing gives a box with no prototype.
    const box = openedBoxes.get(`${latest.id}:${latest.sig}`)
    const me = keyPair.publicKey.toString('hex')
    const authors = new Set(
      bound(roster).flatMap((row) => row.masterTopic?.toLowerCase() ?? [])
    )
    return epochs.valid.some(
      (record) =>
        Object.hasOwn(ring, record.id) &&
        box?.[record.id] !== ring[record.id] &&
        (record.by === me ||
          !authors.has(record.by) ||
          Object.keys(latest.members).some(
            (d) => !Object.hasOwn(record.members, d)
          ))
    )
  }

  const isMe = (masterTopic, keyPair) =>
    typeof masterTopic === 'string' &&
    masterTopic.toLowerCase() === keyPair.publicKey.toString('hex')

  // Null when the appended record did not resolve as the latest epoch.
  const rotate = async (sealable, uncovered, keyPair) => {
    const { latest } = epochs
    // Latest chains from seq 1, so its seq counts records: always safe.
    const seq = latest ? latest.seq + 1 : 1
    const id = generateEpochId()
    const key = generateEpochKey()
    const boxes = sealRing(
      Object.assign(Object.create(null), ring, { [id]: key }),
      sealable
    )
    const members = Object.create(null)
    for (const row of sealable) {
      if (Object.hasOwn(boxes, row.id)) {
        members[row.id] = {
          topic: row.masterTopic.toLowerCase(),
          box: boxes[row.id]
        }
      }
    }
    const record = buildEpochRecord({
      vault: vaultKeyHex(),
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

  // `${id}\n${raw}` of my rows already re-signed, so a row that stays
  // unsigned is written once, not on every run.
  const resigned = new Set()

  // My rows (by masterTopic) with my writer key whose signature does not
  // verify, an older build's say, are written again, signed. A row that
  // changed since the refresh read it (a heal, say) is left for the next
  // run, so its newer content is not overwritten. Returns whether it wrote.
  const resignMyRows = async () => {
    if (!instance.base.writable) return false
    const keyPair = await getPersonalKeyPair()
    const writerKey = instance.writerKey?.toString('hex')
    let wrote = false
    for (const row of roster) {
      if (
        row.signed ||
        row.writerKey !== writerKey ||
        !isMe(row.masterTopic, keyPair)
      ) {
        continue
      }
      const key = `device/${row.id}`
      const state = `${row.id}\n${row.raw}`
      if (resigned.has(state)) continue
      if ((await instance.get(key))?.value !== row.raw) continue
      resigned.add(state)
      try {
        await instance.add(key, signRow(key, row.raw))
        wrote = true
      } catch (error) {
        // Not written: the next run tries again. The run goes on, so one row
        // that cannot be written never blocks a rotation.
        resigned.delete(state)
        logger.warn('epochStore: could not re-sign my roster row', {
          error: error?.name
        })
      }
    }
    return wrote
  }

  const doEnsureEpoch = async ({ start = false } = {}, retried = false) => {
    await refresh()
    if (await resignMyRows()) await refresh()
    const keyPair = await getPersonalKeyPair()
    const { sealable, uncovered } = coverage()
    const skip = (reason) => ({ rotated: false, reason, uncovered })
    const rotateNow = async () => {
      const result = await rotate(sealable, uncovered, keyPair)
      if (result) return result
      // Another epoch resolved above the one just appended: judge that one.
      if (retried) throw new RotationOvertakenError()
      return doEnsureEpoch({ start }, true)
    }

    if (!instance.base.writable) return skip('not-writable')
    if (!sealable.some((row) => isMe(row.masterTopic, keyPair))) {
      return skip('self-not-in-roster')
    }
    if (legacy) return start ? rotateNow() : skip('legacy')
    const { latest } = epochs
    // No chained epoch by a roster member while epoch rows exist: a
    // rotation is owed.
    if (!latest) return rotateNow()
    // A device that cannot open the latest ring would seal a ring without
    // the history; leave the rotation to a member that holds it.
    if (!ring[latest.id]) return skip('pending')
    if (
      sameSet(memberPairs(latest), sealablePairs(sealable)) &&
      !holdsMoreThan(latest, keyPair) &&
      !skippedAhead(latest)
    ) {
      return skip('current')
    }
    return rotateNow()
  }

  const readStartOwed = async () => {
    if (unsavedOwed) return true
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
    try {
      await instance.base.local.setUserData(
        START_OWED,
        Buffer.from(owed ? '1' : '0')
      )
      startOwed = owed
      unsavedOwed = false
    } catch (error) {
      startOwed = null
      unsavedOwed = owed
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
    const { latest, valid } = epochs
    // While a rotation is owed there is no latest to open: every record is
    // readable once the ring opens every epoch there is.
    const canRead =
      legacy ||
      (latest ? !!ring[latest.id] : valid.every((record) => ring[record.id]))
    return {
      vaultId,
      epoch: latest ? latest.id : null,
      seq: latest ? latest.seq : 0,
      legacy,
      canRead,
      // Only a device that once held a key and wrote here was let go. A
      // legacy row, a joiner whose row has not landed yet, or a kicked
      // device pairing again on a fresh store is waiting, not revoked. A row
      // left behind for a removed writer does not keep a kicked device from
      // learning it was revoked.
      revoked:
        !!latest &&
        !canRead &&
        Object.keys(ring).length > 0 &&
        instance.base.local?.length > 0 &&
        !roster.some((row) => !row.removed && isMyRow(row, keyPair)),
      members: latest ? Object.keys(latest.members).sort() : [],
      uncovered: coverage().uncovered
    }
  }

  // On open, once the first refresh read the roster.
  refresh()
    .then(resignMyRows)
    .catch((error) => {
      logger.warn('epochStore: could not re-sign my roster row', {
        error: error?.name
      })
    })

  return { add, get, find, remove, refresh, ensureEpoch, status }
}
