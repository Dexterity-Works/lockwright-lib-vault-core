/** @typedef {import('bare')} */ /* global Bare */
import Autopass from 'autopass'
import b4a from 'b4a'
import fs from 'bare-fs'
import barePath from 'bare-path'
import BlindEncryptionSodium from 'blind-encryption-sodium'
import Corestore from 'corestore'
import sodium from 'sodium-native'

import { createEpochStore } from './epoch/epochStore'
import {
  EpochKeyUnavailableError,
  EpochRotationPendingError,
  writeErrorMessage
} from './epoch/keyring'
import { getForbiddenRoots } from './getForbiddenRoots'
import {
  generateTOTP,
  generateHOTP,
  parseOtpInput,
  filterDuplicateRecords,
  toExportableOtpRecords
} from './otp/index'
import { PearPassPairer } from './pearpassPairer'
import { RateLimiter } from './rateLimiter'
import { workletLogger } from './utils/workletLogger'
import { OTP_TYPE } from '../constants/otpType'
import { getConfig, networkCreated, networkOptions } from './utils/swarm'
import { validateAndSanitizePath } from './validateAndSanitizePath'
import { defaultMirrorKeys } from '../constants/defaultBlindMirrors'
import {
  VAULT_EXT_KEY,
  SCHEMA_V2,
  isV1RecordKey,
  isV2RecordKey,
  isV1FileKey,
  isV2FileKey,
  parseRecordIdFromKey,
  parseFileKey,
  recordKeyV1,
  recordKeyV2,
  fileKeyV1,
  v1FileKeyToV2,
  mergeV1IntoV2,
  convertV1RecordToV2,
  projectV2ToV1,
  migrateToSchema2,
  reconcileDualStore,
  writeRecordV2AndProjectV1,
  getRawRecordPreferV2,
  deepEqualJson
} from './utils/recordNamespaces'

let STORAGE_PATH = null
let JOB_STORAGE_PATH = null

const JOB_FILE_NAME = 'jobs.enc'
const JOB_FILE_MAGIC = 'PPJQ'
const JOB_FILE_HEADER_SIZE = 16
const JOB_FILE_NONCE_SIZE = sodium.crypto_secretbox_NONCEBYTES

let CORE_STORE_OPTIONS = {
  readOnly: false,
  suspend: true
}

let encryptionInstance
let isEncryptionInitialized = false

let vaultsInstance
let isVaultsInitialized = false

// Separate from the writer keypair so signMessage can't forge hypercore
// block signatures. Derived from the store so it persists across restarts.
let personalKeyPair = null

let activeVaultInstance
let isActiveVaultInitialized = false
/** @type {ReturnType<typeof createEpochStore> | null} */
let epochStore = null
let activeVaultUpdateListener = null

let listeningVaultId = null
let lastActiveVaultId = null
let lastActiveVaultEncryptionKey = null
let lastOnUpdateCallback = null

/** @type {{ ready: boolean, inProgress: boolean, deferred: boolean, migratedToSchema: number|null, error: string|null, lastResult: object|null, progress: { done: number, total: number }|null }} */
let vaultMigrationStatus = {
  ready: false,
  inProgress: false,
  deferred: false,
  migratedToSchema: null,
  error: null,
  lastResult: null,
  progress: null
}
// The migration waits for this device to read or write the latest epoch:
// runEpochSync runs it again once it can.
let migrationDeferred = false
// The latest epoch, read before its listing, of a run that ended incomplete
// with rows it could not read. runEpochSync runs it again on a new latest
// epoch it can open, since a rotation may carry their key: once per
// rotation, not per update. A key that is truly lost costs one full rerun
// per rotation. A key that only a losing fork record carries, with no new
// latest, waits for the next open.
let skippedAtEpoch
const EPOCH_KEY_PENDING = 'epoch-key-pending'

/** @type {Set<string>} */
let previousV1RecordIds = new Set()

/** @type {ReturnType<typeof setTimeout>|null} */
let reconcileDebounceTimer = null
const RECONCILE_DEBOUNCE_MS = 100

/** @type {((status: object) => void) | null} */
let epochStatusListener = null
let lastEpochStatusJson = null
/** @type {Promise<void> | null} */
let epochSync = null
/** @type {{ ensure: boolean } | null} */
let epochSyncNext = null

const pearpassPairer = new PearPassPairer()
const rateLimiter = new RateLimiter()

/**
 * UI can wait on migrate completeness before listing records.
 * `deferred`: waiting until this device can read or write the epoch. `error`
 * is then `EPOCH_KEY_PENDING`, so a gate that fails open on
 * `error && !inProgress` does not wait out its timeout; the resume clears
 * both.
 * @returns {{ ready: boolean, inProgress: boolean, deferred: boolean, migratedToSchema: number|null, error: string|null, lastResult: object|null, progress: { done: number, total: number }|null }}
 */
export const getVaultMigrationStatus = () => ({ ...vaultMigrationStatus })

/**
 * @param {string} path
 * @returns {Promise<void>}
 * */
export const setStoragePath = async (path) => {
  const sanitizedPath = validateAndSanitizePath(path)

  // Block access to restricted system directories
  const forbiddenRoots = getForbiddenRoots()
  const isWindows = Bare.platform === 'win32'

  for (const root of forbiddenRoots) {
    // Windows paths are case-insensitive
    const normalizedRoot = isWindows ? root.toLowerCase() : root
    const normalizedPath = isWindows
      ? sanitizedPath.toLowerCase()
      : sanitizedPath
    const separator = isWindows ? '\\' : '/'

    if (
      normalizedPath === normalizedRoot ||
      normalizedPath.startsWith(normalizedRoot + separator)
    ) {
      throw new Error('Storage path points to a restricted system directory')
    }
  }

  STORAGE_PATH = sanitizedPath
}

export const setCoreStoreOptions = (coreStoreOptions) => {
  CORE_STORE_OPTIONS = {
    readOnly: false,
    ...coreStoreOptions
  }
}

/**
 * @returns {boolean}
 **/
export const getIsVaultsInitialized = () => isVaultsInitialized

/**
 * @returns {boolean}
 **/
export const getIsEncryptionInitialized = () => isEncryptionInitialized

/**
 * @returns {boolean}
 **/
export const getIsActiveVaultInitialized = () => isActiveVaultInitialized

/**
 * @returns {Autopass}
 */
export const getActiveVaultInstance = () => activeVaultInstance

/**
 * @returns {Autopass}
 **/
export const getVaultsInstance = () => vaultsInstance

/**
 * @returns {Autopass}
 **/
export const getEncryptionInstance = () => encryptionInstance

/**
 * Suspend all running Autopass instances to stop background I/O.
 * @returns {Promise<void>}
 */
export const suspendAllInstances = async () => {
  if (activeVaultInstance) {
    workletLogger.log('Suspending active vault instance')
    await activeVaultInstance.suspend?.()
  }
  if (vaultsInstance) {
    workletLogger.log('Suspending vaults instance')
    await vaultsInstance.suspend?.()
  }
  if (encryptionInstance) {
    workletLogger.log('Suspending encryption instance')
    await encryptionInstance.suspend?.()
  }
}

/**
 * Resume all Autopass instances after background.
 * @returns {Promise<void>}
 */
export const resumeAllInstances = async () => {
  const tasks = []

  tasks.push(activeVaultInstance?.resume?.())
  tasks.push(vaultsInstance?.resume?.())
  tasks.push(encryptionInstance?.resume?.())

  await Promise.allSettled(tasks)
}

/**
 * @returns {void}
 */
const clearRestartCache = () => {
  lastActiveVaultId = null
  lastActiveVaultEncryptionKey = null
  lastOnUpdateCallback = null
}

/**
 * @param {{ clearRestartCache?: boolean }} [options]
 * @returns {Promise<void>}
 */
export const closeActiveVaultInstance = async (options) => {
  if (reconcileDebounceTimer) {
    clearTimeout(reconcileDebounceTimer)
    reconcileDebounceTimer = null
  }

  activeVaultInstance.removeAllListeners()

  await activeVaultInstance.close()

  activeVaultInstance = null
  isActiveVaultInitialized = false
  epochStore = null
  activeVaultUpdateListener = null
  lastEpochStatusJson = null
  // reset listener marker so future initListener can rebind
  listeningVaultId = null
  previousV1RecordIds = new Set()
  migrationDeferred = false
  skippedAtEpoch = undefined
  vaultMigrationStatus = {
    ready: false,
    inProgress: false,
    deferred: false,
    migratedToSchema: null,
    error: null,
    lastResult: null,
    progress: null
  }

  if (options?.clearRestartCache) {
    clearRestartCache()
  }
}

/**
 *
 * @param {Autopass} instance
 * @param {Function} filterFn
 * @returns
 */
export const collectValuesByFilter = async (instance, filterFn) => {
  const stream = await instance.list()
  const results = []

  return new Promise((resolve, reject) => {
    stream.on('data', ({ key, value }) => {
      if (!value) {
        return
      }

      const parsedValue = JSON.parse(value)

      if (!parsedValue) {
        return
      }

      if (!filterFn) {
        results.push(parsedValue)
        return
      }

      if (filterFn(key)) {
        results.push(parsedValue)
      }
    })

    stream.on('end', () => resolve(results))

    stream.on('error', (error) => reject(error))
  })
}

/**
 * Active vault entries with parsed values, decrypted by the epoch store.
 * Records the store cannot read are left out and passed to onUnreadable.
 * @param {Function} [filterFn]
 * @param {(key: string) => void} [onUnreadable]
 * @param {ReturnType<typeof createEpochStore>} [store]
 * @returns {Promise<Array<{ key: string, value: any }>>}
 */
const collectActiveVaultEntries = async (
  filterFn,
  onUnreadable,
  store = epochStore
) => {
  const results = []
  for (const { key, value } of await store.find({ onUnreadable })) {
    if (!value || (filterFn && !filterFn(key))) continue

    let parsedValue
    try {
      parsedValue = JSON.parse(value)
    } catch (err) {
      workletLogger.error('collectActiveVaultEntries: failed to parse record', {
        key,
        err
      })
      continue
    }

    if (parsedValue) results.push({ key, value: parsedValue })
  }
  return results
}

/**
 * Every record merged by id across v1 and v2, v2 first. An id whose v2 row
 * this device cannot read is left out: its v1 copy may be stale, and a save
 * from it would seal over the v2 content. A v1 record with no v2 row stays.
 * @returns {Promise<object[]>}
 */
const listMergedRecords = async () => {
  const hidden = new Set()
  const entries = await collectActiveVaultEntries(
    (key) => isV1RecordKey(key) || isV2RecordKey(key),
    (key) => {
      if (isV2RecordKey(key)) hidden.add(parseRecordIdFromKey(key))
    }
  )
  const byId = new Map()
  for (const { key, value } of entries) {
    const id = parseRecordIdFromKey(key)
    if (id && isV1RecordKey(key) && !byId.has(id)) byId.set(id, value)
  }
  for (const { key, value } of entries) {
    const id = parseRecordIdFromKey(key)
    if (id && isV2RecordKey(key)) byId.set(id, value)
  }
  for (const id of hidden) byId.delete(id)
  return [...byId.values()]
}

const recordIdOfKey = (key) =>
  parseRecordIdFromKey(key) ?? parseFileKey(key)?.recordId ?? null

const ACTIVE_VAULT_CHANGED = 'Active vault changed'

/**
 * `listEntries` leaves out rows this device cannot read and collects them:
 * `unreadableKeys` holds their keys, `skipIds` their record ids. Treating
 * such a row as missing would seal stale content over it.
 * Bound to the store active when it is made: a write after another vault
 * opened throws instead of landing in that vault.
 * @param {ReturnType<typeof createEpochStore>} [store]
 * @returns {import('./utils/recordNamespaces.js').VaultAdapter & { unreadableKeys: Set<string> }}
 */
const createActiveVaultAdapter = (store = epochStore) => {
  const unreadableKeys = new Set()
  const skipIds = new Set()
  const assertActive = () => {
    if (store !== epochStore) throw new Error(ACTIVE_VAULT_CHANGED)
  }
  return {
    getJson: async (key) => {
      const res = await store.get(key)
      if (!res || !res.value) return null
      return JSON.parse(res.value)
    },
    getWithFile: async (key) => {
      const res = await store.get(key)
      if (!res) return { value: null, file: null }
      let value = null
      if (res.value) {
        try {
          value = JSON.parse(res.value)
        } catch {
          value = {}
        }
      }
      return { value, file: res.file || null }
    },
    addJson: async (key, data, file = null) => {
      assertActive()
      await store.add(key, JSON.stringify(data), file || undefined)
    },
    remove: async (key) => {
      assertActive()
      await store.remove(key)
    },
    listEntries: async () =>
      collectActiveVaultEntries(
        undefined,
        (key) => {
          unreadableKeys.add(key)
          const id = recordIdOfKey(key)
          if (id) skipIds.add(id)
        },
        store
      ),
    unreadableKeys,
    skipIds
  }
}

/**
 * @param {string} key
 * @returns {Promise<boolean>} whether the row exists but cannot be read here
 */
const isUnreadableRow = async (key, store = epochStore) => {
  let unreadable = false
  await store.find({
    gte: { key },
    lte: { key },
    onUnreadable: () => {
      unreadable = true
    }
  })
  return unreadable
}

/**
 * The record for an id, v2 first. Null when its v2 row exists but cannot be
 * read here: the v1 copy may be stale, and a write based on it would seal
 * over v2 content this device never saw.
 * @param {string} recordId
 * @returns {Promise<{ record: object, key: string, schema: 1|2 }|null>}
 */
const getReadableRecord = async (recordId) => {
  if (await isUnreadableRow(recordKeyV2(recordId))) return null
  return getRawRecordPreferV2(createActiveVaultAdapter(), recordId)
}

// Ids seen before and in `skipIds` now stay, as in runIncrementalReconcile,
// so a v1 delete made while their rows were unreadable is still mirrored.
const refreshPreviousV1RecordIds = async (skipIds, store) => {
  const entries = await collectActiveVaultEntries(
    isV1RecordKey,
    undefined,
    store
  )
  if (store !== epochStore) return
  const kept = [...previousV1RecordIds].filter((id) => skipIds.has(id))
  previousV1RecordIds = new Set([
    ...entries.map(({ key }) => parseRecordIdFromKey(key)).filter(Boolean),
    ...kept
  ])
}

// Runs over `store` only. Once another vault opened it stops and leaves
// the shared migration state to that vault.
const runVaultMigration = async (store = epochStore) => {
  const switched = () => store !== epochStore
  skippedAtEpoch = undefined
  vaultMigrationStatus = {
    ...vaultMigrationStatus,
    ready: false,
    inProgress: true,
    deferred: false,
    error: null
  }

  try {
    // Read before the listing: a key that lands after it would make rows
    // the listing skipped look permanently unreadable.
    const { canRead, epoch } = await store.status()
    const adapter = createActiveVaultAdapter(store)
    const result = await migrateToSchema2(adapter, {
      onProgress: (progress) => {
        if (switched()) return
        vaultMigrationStatus = {
          ...vaultMigrationStatus,
          progress
        }
      }
    })
    await refreshPreviousV1RecordIds(adapter.skipIds, store)
    if (switched()) return

    const skipped =
      !(result.complete || result.alreadyMigrated) && adapter.skipIds.size > 0
    if (skipped) skippedAtEpoch = epoch
    // Rows it skipped under a latest epoch it cannot open yet: nothing was
    // written, so no write threw. Under a readable latest epoch it ends as
    // incomplete instead. Both reads: a key can land during the listing, or
    // an epoch without me.
    if (skipped && (!canRead || !(await store.status()).canRead)) {
      if (switched()) return
      migrationDeferred = true
      vaultMigrationStatus = {
        ready: false,
        inProgress: false,
        deferred: true,
        migratedToSchema: null,
        error: EPOCH_KEY_PENDING,
        lastResult: result
      }
      return
    }

    const vaultExt = (await adapter.getJson(VAULT_EXT_KEY)) || {}
    if (switched()) return
    vaultMigrationStatus = {
      ready: result.complete || result.alreadyMigrated,
      inProgress: false,
      deferred: false,
      migratedToSchema:
        Number(vaultExt.migratedToSchema) >= SCHEMA_V2
          ? SCHEMA_V2
          : (vaultExt.migratedToSchema ?? null),
      error:
        result.complete || result.alreadyMigrated
          ? null
          : 'Migration incomplete',
      lastResult: result,
      progress: vaultMigrationStatus.progress
    }
  } catch (error) {
    if (switched()) return
    // A device not yet in the latest epoch, or one that cannot rotate an
    // epoch that still lists a removed device, cannot write yet.
    migrationDeferred =
      error instanceof EpochKeyUnavailableError ||
      error instanceof EpochRotationPendingError
    if (!migrationDeferred) {
      workletLogger.error('runVaultMigration failed', error)
    }
    vaultMigrationStatus = {
      ready: false,
      inProgress: false,
      deferred: migrationDeferred,
      migratedToSchema: null,
      error: migrationDeferred
        ? EPOCH_KEY_PENDING
        : error?.message || String(error),
      lastResult: null
    }
    throw error
  }
}

const runIncrementalReconcile = async () => {
  if (!isActiveVaultInitialized || !activeVaultInstance) return

  const store = epochStore
  const listing = createActiveVaultAdapter(store)
  const vaultExt = (await listing.getJson(VAULT_EXT_KEY)) || {}
  const { canRead } = await store.status()
  const entries = await listing.listEntries()
  const adapter = { ...listing, listEntries: async () => entries }
  // A v1 record this device cannot read looks deleted; mirroring that
  // would delete a v2 record it never saw change. reconcileDualStore skips
  // such records through skipIds; only a latest epoch it cannot open
  // blocks every delete.
  const result = await reconcileDualStore(adapter, {
    previousV1Ids: previousV1RecordIds,
    blockV1DeleteMirror: vaultExt.blockV1DeleteMirror === true || !canRead
  })
  if (store !== epochStore) return
  // Keep the ids seen before but skipped now, so a v1 delete made meanwhile
  // is mirrored once this device can read the record again.
  const kept = canRead
    ? [...previousV1RecordIds].filter((id) => listing.skipIds.has(id))
    : previousV1RecordIds
  previousV1RecordIds = new Set([...result.previousV1Ids, ...kept])
}

const scheduleIncrementalReconcile = (after) => {
  if (reconcileDebounceTimer) {
    clearTimeout(reconcileDebounceTimer)
  }

  reconcileDebounceTimer = setTimeout(() => {
    reconcileDebounceTimer = null
    runIncrementalReconcile()
      .catch((error) => {
        workletLogger.error('incremental reconcile failed', error)
      })
      .finally(() => {
        after?.()
      })
  }, RECONCILE_DEBOUNCE_MS)
}

const runEpochSync = async ({ ensure }) => {
  const store = epochStore
  if (!store) return
  // A failed rotation still leaves a status worth pushing: revoked or
  // uncovered devices must not wait for the next rotation that works.
  if (ensure && activeVaultInstance?.base?.writable) {
    try {
      await store.ensureEpoch({ start: false })
    } catch (error) {
      workletLogger.error('epoch rotation failed', error)
    }
  }
  try {
    const resume = async () => {
      if (!migrationDeferred && skippedAtEpoch === undefined) return false
      const { canRead, epoch } = await store.status()
      return canRead && (migrationDeferred || epoch !== skippedAtEpoch)
    }
    if (
      (await resume()) &&
      store === epochStore &&
      activeVaultInstance?.base?.writable
    ) {
      // Cleared first, because the migration sets them again when the run
      // defers or skips rows. A device that can read and write but still
      // cannot rotate (its own row is gone, say) defers again and reruns on
      // each update; the run stops at its first write, so that is accepted.
      migrationDeferred = false
      skippedAtEpoch = undefined
      // runVaultMigration logs and records its own failure.
      await runVaultMigration(store).catch(() => {})
    }
    // Read after the resume: a rotation the migration made, or one that
    // landed meanwhile, is pushed now, not on the next update.
    const status = await store.status()
    const {
      vaultId,
      epoch,
      seq,
      legacy,
      canRead,
      revoked,
      members,
      uncovered
    } = status
    const json = JSON.stringify({
      vaultId,
      epoch,
      seq,
      legacy,
      canRead,
      revoked,
      members,
      uncovered
    })
    if (store !== epochStore || json === lastEpochStatusJson) return
    if (!epochStatusListener) return
    // Recorded only once delivered, so a missing or failing listener gets
    // the same status on the next update.
    epochStatusListener(status)
    lastEpochStatusJson = json
  } catch (error) {
    workletLogger.error('epoch sync failed', error)
  }
}

/**
 * Keep the epoch current and push its status when it changed. One run at a
 * time; a burst of updates during a run collapses into one more run.
 * @param {{ ensure: boolean }} opts
 * @returns {Promise<void>}
 */
const syncEpoch = ({ ensure }) => {
  if (epochSync) {
    epochSyncNext = { ensure: ensure || !!epochSyncNext?.ensure }
    return epochSync
  }
  epochSync = (async () => {
    let next = { ensure }
    while (next) {
      epochSyncNext = null
      await runEpochSync(next)
      next = epochSyncNext
    }
  })().finally(() => {
    epochSync = null
  })
  return epochSync
}

/**
 * @param {((status: object) => void) | null} listener
 */
export const setEpochStatusListener = (listener) => {
  epochStatusListener = listener
}

/**
 * Remove v2 file keys for a record id, including rows this device cannot
 * read: leaving those would orphan their sealed files.
 * @param {string} recordId
 * @returns {Promise<void>}
 */
const removeV2FilesForRecord = async (recordId) => {
  const prefix = `${recordKeyV2(recordId)}/file/`
  const keys = []
  const readable = await epochStore.find({
    gte: { key: prefix },
    lt: { key: `${prefix.slice(0, -1)}0` },
    onUnreadable: (key) => keys.push(key)
  })
  for (const { key } of readable) keys.push(key)
  for (const key of keys) {
    const parsed = parseFileKey(key)
    if (parsed?.schema === 2 && parsed.recordId === recordId) {
      await epochStore.remove(key)
    }
  }
}

/**
 * @param {string} path
 * @returns {string}
 */
export const buildPath = (path) => {
  if (!STORAGE_PATH) {
    throw new Error('Storage path not set')
  }

  // Join and resolve the path (handles traversal sequences like ..)
  const resolved = barePath.join(STORAGE_PATH, path)

  // Normalize both paths for comparison (handles trailing slashes, etc.)
  const normalizedRoot = barePath.normalize(STORAGE_PATH)
  const normalizedResolved = barePath.normalize(resolved)

  // Ensure the resolved path is within the storage root
  // Allow exact match or subdirectories
  if (
    normalizedResolved !== normalizedRoot &&
    !normalizedResolved.startsWith(normalizedRoot + barePath.sep)
  ) {
    throw new Error('Resolved path escapes storage root')
  }

  return normalizedResolved
}

/**
 * @param {Object} params
 * @param {string} params.path
 * @param {string | undefined} params.encryptionKey
 * @param {string | undefined} params.hashedPassword
 * @returns {Promise<Autopass>}
 */
export const initInstance = async ({ path, hashedPassword, encryptionKey }) => {
  try {
    const fullPath = buildPath(path)

    // Pre-create the directory tree Corestore needs. Without this there's a
    // race during Corestore.ready() on cold installs (notably on iOS App Group
    // containers): RocksDB's non-recursive mkdir on `db/` can run before
    // DeviceFile's recursive mkdir creates the parent, causing ENOENT with
    // "While mkdir if missing: <path>/db: No such file or directory".
    await fs.promises.mkdir(barePath.join(fullPath, 'db'), { recursive: true })

    const store = new Corestore(fullPath, CORE_STORE_OPTIONS)

    if (!store) {
      throw new Error('Error creating store')
    }

    const conf = await getConfig(store)

    const instance = networkCreated(
      'autopass',
      new Autopass(
        store,
        networkOptions({
          encryptionKey: encryptionKey
            ? Buffer.from(encryptionKey, 'base64')
            : undefined,
          blindEncryption: hashedPassword
            ? new BlindEncryptionSodium(b4a.alloc(32, hashedPassword, 'utf-8'))
            : undefined,
          relayThrough: conf.current.blindRelays
        })
      )
    )

    await instance.ready()

    return instance
  } catch (error) {
    throw new Error(`Error initializing instance: ${error.message}`)
  }
}

/**
 * @param {Object} params
 * @param {string} params.path
 * @param {string | undefined} params.encryptionKey
 * @param {string} params.newHashedPassword
 * @param {string} params.currentHashedPassword
 * @returns {Promise<Autopass>}
 */
export const initInstanceWithNewBlindEncryption = async ({
  path,
  encryptionKey,
  newHashedPassword,
  currentHashedPassword
}) => {
  try {
    if (!currentHashedPassword || !newHashedPassword) {
      throw new Error('Old and new hashed passwords are required')
    }

    const fullPath = buildPath(path)

    // Same rationale as initInstance — pre-create Corestore's directory tree
    // to avoid an ENOENT race during Corestore.ready() on cold installs.
    await fs.promises.mkdir(barePath.join(fullPath, 'db'), { recursive: true })

    const store = new Corestore(fullPath, CORE_STORE_OPTIONS)

    if (!store) {
      throw new Error('Error creating store')
    }

    const conf = await getConfig(store)

    const instance = networkCreated(
      'autopass',
      new Autopass(
        store,
        networkOptions({
          encryptionKey: encryptionKey
            ? Buffer.from(encryptionKey, 'base64')
            : undefined,
          blindEncryption: new BlindEncryptionSodium(
            b4a.alloc(32, newHashedPassword, 'utf-8'),
            b4a.alloc(32, currentHashedPassword, 'utf-8')
          ),
          relayThrough: conf.current.blindRelays
        })
      )
    )

    await instance.ready()

    return instance
  } catch (error) {
    throw new Error(
      `Error initializing instance with new blind encryption: ${error.message}`
    )
  }
}

// Serialise concurrent activeVaultInit calls. Without this, two callers
// targeting the same vault (e.g. the desktop renderer and the extension both
// auto-switching after a delete) race on the Corestore lock and the loser
// gets "File descriptor could not be locked".
/** @type {Promise<Autopass> | null} */
let activeVaultInitInFlight = null

/**
 * @param {Object} params
 * @param {string} params.id
 * @param {string | undefined} params.encryptionKey
 * @returns {Promise<Autopass>}
 */
export const initActiveVaultInstance = async ({ id, encryptionKey }) => {
  if (
    isActiveVaultInitialized &&
    lastActiveVaultId === id &&
    activeVaultInstance
  ) {
    return activeVaultInstance
  }

  if (activeVaultInitInFlight) {
    await activeVaultInitInFlight.catch(() => {})
    if (
      isActiveVaultInitialized &&
      lastActiveVaultId === id &&
      activeVaultInstance
    ) {
      return activeVaultInstance
    }
  }

  activeVaultInitInFlight = (async () => {
    if (activeVaultInstance) {
      await closeActiveVaultInstance()
    }

    isActiveVaultInitialized = false

    const hashedPassword = await getHashedPassword()

    activeVaultInstance = await initInstance({
      path: `vault/${id}`,
      encryptionKey,
      hashedPassword
    })
    epochStore = createEpochStore({
      instance: activeVaultInstance,
      getPersonalKeyPair,
      vaultId: id,
      logger: workletLogger
    })

    isActiveVaultInitialized = true

    // cache last init params for restart
    lastActiveVaultId = id
    lastActiveVaultEncryptionKey = encryptionKey

    // First launch (no watermark): convert records + copy files once; later opens no-op.
    try {
      await runVaultMigration()
    } catch (error) {
      // Open anyway so the device can show its epoch status; runEpochSync
      // runs the migration again once it can write.
      if (!migrationDeferred) throw error
      workletLogger.warn('vault migration deferred: cannot write the epoch', {
        error: error.name
      })
    }

    if (lastOnUpdateCallback) {
      lastOnUpdateCallback()
    }

    // Autobase.update() waits on missing writer cores over Hyperswarm.
    // Unlock must not. Flush in background so autofill still sees disk.
    void activeVaultInstance.base.update().catch((error) => {
      workletLogger.error('activeVault Autobase update failed', error)
    })

    void syncEpoch({ ensure: false })

    return activeVaultInstance
  })()

  try {
    return await activeVaultInitInFlight
  } finally {
    activeVaultInitInFlight = null
  }
}

/**
 * @returns {Promise<void>}
 */
export const rateLimitInit = async () => {
  if (!isEncryptionInitialized) {
    return
  }

  await rateLimiter.setStorage({
    get: encryptionGet,
    add: encryptionAdd
  })
}

/**
 * @returns {Promise<void>}
 */
export const rateLimitRecordFailure = async () => {
  await rateLimiter.recordFailure()
}

/**
 * @returns {Promise<{ isLocked: boolean, lockoutRemainingMs: number, remainingAttempts: number }>}
 */
export const getRateLimitStatus = async () => {
  await rateLimitInit()
  return await rateLimiter.getStatus()
}

/**
 * * @returns {Promise<void>}
 */
export const resetRateLimit = async () => {
  await rateLimiter.reset()
}

/**
 * @param {Object} params
 * @param {string | undefined} params.encryptionKey
 * @param {string | undefined} params.hashedPassword
 * @returns {Promise<void>}
 */
export const masterVaultInit = async ({ encryptionKey, hashedPassword }) => {
  isVaultsInitialized = false

  vaultsInstance = await initInstance({
    path: 'vaults',
    encryptionKey,
    hashedPassword
  })

  isVaultsInitialized = true
}

/**
 * @param {Object} params
 * @param {string | undefined} params.encryptionKey
 * @param {string} params.newHashedPassword
 * @param {string} params.currentHashedPassword
 * @returns {Promise<void>}
 */
export const masterVaultInitWithNewBlindEncryption = async ({
  encryptionKey,
  newHashedPassword,
  currentHashedPassword
}) => {
  isVaultsInitialized = false

  vaultsInstance = await initInstanceWithNewBlindEncryption({
    path: 'vaults',
    encryptionKey,
    newHashedPassword,
    currentHashedPassword
  })

  isVaultsInitialized = true
}

/**
 * @returns {Promise<void>}
 */
export const encryptionInit = async () => {
  isEncryptionInitialized = false

  encryptionInstance = await initInstance({
    path: 'encryption'
  })

  await encryptionInstance.base.update()

  isEncryptionInitialized = true
}

/**
 * @param {string} key
 * @returns {Promise<any>}
 */
export const encryptionGet = async (key) => {
  if (!isEncryptionInitialized) {
    throw new Error('Encryption not initialised')
  }

  const res = await encryptionInstance.get(key)
  const { value } = res || {}
  const parsedRes = value ? JSON.parse(value) : null

  return parsedRes
}

/**
 * @param {string} key
 * @param {any} data
 * @returns {Promise<void>}
 */
export const encryptionAdd = async (key, data) => {
  if (!isEncryptionInitialized) {
    throw new Error('Encryption not initialised')
  }

  await encryptionInstance.add(key, JSON.stringify(data))
  await encryptionInstance.base.update()
  await encryptionInstance.base.view.flush()

  const storage = encryptionInstance.store?.storage

  if (storage?.db?.flush) {
    await storage.db.flush()
  }

  if (storage?.flush) {
    await storage.flush()
  }
}

/**
 * @returns {Promise<void>}
 */
export const encryptionClose = async () => {
  await encryptionInstance.close()

  encryptionInstance = null
  isEncryptionInitialized = false
}

/**
 * @returns {Promise<void>}
 */
export const closeVaultsInstance = async () => {
  await vaultsInstance.close()

  vaultsInstance = null
  isVaultsInitialized = false
  personalKeyPair = null
}

/**
 * @returns {Promise<{ publicKey: Buffer, secretKey: Buffer }>}
 */
export const getPersonalKeyPair = async () => {
  if (personalKeyPair) return personalKeyPair
  if (!isVaultsInitialized) {
    throw new Error('getPersonalKeyPair: master vault not initialised')
  }
  personalKeyPair = await vaultsInstance.store.createKeyPair(
    'pearpass-personal-id'
  )
  return personalKeyPair
}

/**
 * @param {string} key
 * @param {any} data
 * @param {Buffer} file
 * @returns {Promise<void>}
 */
export const activeVaultAdd = async (key, data, file, fileName) => {
  if (!isActiveVaultInitialized) {
    throw new Error('Vault not initialised')
  }
  // Every write of this call goes to the vault it started in: a switch
  // mid-save would seal this record's twin into the other vault.
  const store = epochStore
  const write = (...args) => {
    if (store !== epochStore) throw new Error(ACTIVE_VAULT_CHANGED)
    return store.add(...args)
  }
  const getRaw = async (k) => {
    const res = await store.get(k)
    return res?.value ? JSON.parse(res.value) : null
  }
  try {
    await store.add(key, JSON.stringify(data), file)

    // Local dual-write / projection (companion namespace). Uses the store directly to avoid recursion.
    if (isV1RecordKey(key)) {
      const id = parseRecordIdFromKey(key)
      // A v2 twin this device cannot read is not missing: rebuilding it
      // from v1 would seal over content it never saw.
      if (id && !(await isUnreadableRow(recordKeyV2(id), store))) {
        const existingV2 = await getRaw(recordKeyV2(id))
        const nextV2 =
          mergeV1IntoV2(data, existingV2) ||
          (!existingV2 ? convertV1RecordToV2(data) : null)
        if (nextV2 && !deepEqualJson(nextV2, existingV2)) {
          await write(recordKeyV2(id), JSON.stringify(nextV2))
        }
      }
    } else if (isV2RecordKey(key)) {
      const id = parseRecordIdFromKey(key)
      if (id) {
        const asV2 =
          data?.schema === SCHEMA_V2 ? data : convertV1RecordToV2(data)
        if (asV2 !== data) {
          await write(key, JSON.stringify(asV2), file)
        }
        const projected = projectV2ToV1(asV2)
        const existingV1 = await getRaw(recordKeyV1(id))
        if (!existingV1 || !deepEqualJson(existingV1, projected)) {
          await write(recordKeyV1(id), JSON.stringify(projected))
        }
      }
    } else if (isV1FileKey(key)) {
      const v2Key = v1FileKeyToV2(key)
      if (v2Key) {
        const existing = await store.get(v2Key)
        if (!existing?.file) {
          await write(
            v2Key,
            JSON.stringify(data && typeof data === 'object' ? data : {}),
            file
          )
        }
      }
    } else if (isV2FileKey(key)) {
      const parsed = parseFileKey(key)
      if (parsed) {
        const v1Key = fileKeyV1(parsed.recordId, parsed.fileId)
        const existing = await store.get(v1Key)
        if (!existing?.file) {
          await write(
            v1Key,
            JSON.stringify(data && typeof data === 'object' ? data : {}),
            file
          )
        }
      }
    }
  } catch (error) {
    const err = new Error(writeErrorMessage(error))
    if (fileName) {
      err.details = { fileName }
    }
    throw err
  }
}

/**
 * @param {string} key
 * @returns {Promise<void>}
 */
export const vaultsGet = async (key) => {
  if (!isVaultsInitialized) {
    throw new Error('Vaults not initialised')
  }

  const res = await vaultsInstance.get(key)

  const { value, file } = res || {}
  const parsedValue = JSON.parse(value)

  if (file) {
    Object.defineProperty(parsedValue, 'file', {
      value: file,
      enumerable: true
    })
  }
  return parsedValue
}

/**
 * @param {string} key
 * @param {any} data
 * @returns {Promise<void>}
 */
export const vaultsAdd = async (key, data) => {
  if (!isVaultsInitialized) {
    throw new Error('Vault not initialised')
  }

  await vaultsInstance.add(key, JSON.stringify(data))
}

/**
 * @param {string} key
 * @returns {Promise<void>}
 */
export const vaultsRemove = async (key) => {
  if (!isVaultsInitialized) {
    throw new Error('Vaults not initialised')
  }
  if (!key) throw new Error('vaultsRemove: key is required')

  await vaultsInstance.remove(key)
}

/**
 * @param {string} messageHex
 * @returns {Promise<string>} hex signature
 */
export const signMessage = async (messageHex) => {
  if (!isVaultsInitialized) {
    throw new Error('Vaults not initialised')
  }
  const message = b4a.from(messageHex, 'hex')
  // Epoch records are signed with the same key under this prefix.
  if (b4a.toString(message.subarray(0, 11)) === 'lockwright/') {
    throw new Error('signMessage: bytes in the reserved signing domain')
  }
  const { secretKey } = await getPersonalKeyPair()
  const signature = b4a.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(signature, message, secretKey)
  return b4a.toString(signature, 'hex')
}

/**
 * @param {string} messageHex
 * @param {string} signatureHex
 * @param {string} publicKeyHex
 * @returns {boolean}
 */
export const verifySignature = (messageHex, signatureHex, publicKeyHex) => {
  try {
    const message = b4a.from(messageHex, 'hex')
    const signature = b4a.from(signatureHex, 'hex')
    const publicKey = b4a.from(publicKeyHex, 'hex')
    return sodium.crypto_sign_verify_detached(signature, message, publicKey)
  } catch {
    return false
  }
}

/**
 * @param {{ gte?: { key: string }, lt?: { key: string } }} options
 * @returns {Promise<Array<{ key: string, value: any }>>}
 */
export const vaultsFind = async (options = {}) => {
  if (!isVaultsInitialized) {
    throw new Error('Vaults not initialised')
  }

  const stream = await vaultsInstance.list()
  const gteKey = options?.gte?.key
  const ltKey = options?.lt?.key

  return new Promise((resolve, reject) => {
    const results = []
    stream.on('data', ({ key, value }) => {
      if (!value) return
      if (gteKey && key < gteKey) return
      if (ltKey && key >= ltKey) return
      try {
        const parsedValue = JSON.parse(value)
        results.push({ key, value: parsedValue })
      } catch (err) {
        workletLogger.error('vaultsFind: failed to parse record', { key, err })
      }
    })
    stream.on('end', () => resolve(results))
    stream.on('error', (err) => reject(err))
  })
}

/**
 * Removes a vault from this device: closes the active instance if it owns the
 * vault, drops the master entry, and wipes the on-disk autobase directory.
 * Departure announcements to peers are handled by the lib-vault leave-vault
 * action (personal-swarm) before this is called.
 *
 * @param {string} vaultId
 * @returns {Promise<void>}
 */
export const removeVault = async (vaultId) => {
  if (!vaultId) {
    throw new Error('vaultId is required')
  }
  if (!isVaultsInitialized) {
    throw new Error('Vaults not initialised')
  }

  if (lastActiveVaultId === vaultId) {
    if (isActiveVaultInitialized) {
      // Close before wipe — Windows file locks would otherwise block rm.
      await closeActiveVaultInstance({ clearRestartCache: true })
    } else {
      clearRestartCache()
    }
  }

  // Wipe disk first, with retries. Only drop the master entry once the files
  // are gone, so a partial failure leaves the vault re-openable. The backoff
  // is sized for Windows: handle release after close() can take 100+ ms,
  // longer with Defender or indexer activity touching the autobase dir.
  const fullPath = buildPath(`vault/${vaultId}`)
  const RETRY_DELAYS_MS = [250, 500, 1000]
  let lastErr
  for (let attempt = 0; attempt < RETRY_DELAYS_MS.length + 1; attempt++) {
    try {
      await fs.promises.rm(fullPath, { recursive: true, force: true })
      lastErr = null
      break
    } catch (err) {
      lastErr = err
      const delay = RETRY_DELAYS_MS[attempt]
      if (delay !== undefined) {
        await new Promise((resolve) => setTimeout(resolve, delay))
      }
    }
  }
  if (lastErr) throw lastErr

  await vaultsInstance.remove(`vault/${vaultId}`)
}

/**
 * @param {string} key
 * @returns {Promise<Buffer|null>}
 */
export const activeVaultGetFile = async (key) => {
  if (!isActiveVaultInitialized) {
    throw new Error('Vault not initialised')
  }

  const res = await epochStore.get(key)
  return res?.file || null
}

/**
 * @param {string} key
 * @returns {Promise<void>}
 */
export const activeVaultRemoveFile = async (key) => {
  if (!isActiveVaultInitialized) {
    throw new Error('Vault not initialised')
  }

  await epochStore.remove(key)
}

/**
 * @param {string} recordId
 * @returns {Promise<void>}
 */
export const vaultRemove = async (key) => {
  if (!isActiveVaultInitialized) {
    throw new Error('Vault not initialised')
  }

  await epochStore.remove(key)

  const vaultExt = (await activeVaultGetRaw(VAULT_EXT_KEY)) || {}
  const blockV1DeleteMirror = vaultExt.blockV1DeleteMirror === true

  if (isV1RecordKey(key)) {
    if (!blockV1DeleteMirror) {
      const id = parseRecordIdFromKey(key)
      if (id) {
        await epochStore.remove(recordKeyV2(id))
        await removeV2FilesForRecord(id)
      }
    }
  } else if (isV2RecordKey(key)) {
    const id = parseRecordIdFromKey(key)
    if (id) {
      await epochStore.remove(recordKeyV1(id))
    }
  } else if (isV1FileKey(key)) {
    if (!blockV1DeleteMirror) {
      const v2Key = v1FileKeyToV2(key)
      if (v2Key) {
        await epochStore.remove(v2Key)
      }
    }
  } else if (isV2FileKey(key)) {
    const parsed = parseFileKey(key)
    if (parsed) {
      await epochStore.remove(fileKeyV1(parsed.recordId, parsed.fileId))
    }
  }
}

/**
 * Drops a writer from the active vault's autobase. After replication, the
 * removed writer can no longer append to the vault.
 * @param {string} writerKey - hex writer key of the peer to remove
 * @returns {Promise<void>}
 */
export const vaultRemoveWriter = async (writerKey) => {
  if (!isActiveVaultInitialized) {
    throw new Error('Vault not initialised')
  }
  if (!writerKey) {
    throw new Error('writerKey is required')
  }

  // Owed before the removal lands: a lock between it and the kick's
  // ensureEpoch({ start: true }) must not leave the vault legacy. A flag
  // that cannot be written throws here, before the removal.
  await epochStore?.oweStart()

  // autopass.removeWriter passes the key straight to b4a.from(), which
  // defaults to UTF-8 for strings. We store/transport writerKey as hex,
  // so decode here to the raw 32-byte ed25519 public key autobase needs.
  await activeVaultInstance.removeWriter(b4a.from(writerKey, 'hex'))
}

/**
 * @returns {Promise<Array<any>>}
 */
export const vaultsList = async (filterKey) => {
  if (!isVaultsInitialized) {
    throw new Error('Vaults not initialised')
  }

  return collectValuesByFilter(
    vaultsInstance,
    filterKey ? (key) => key?.startsWith(filterKey) : undefined
  )
}

/**
 * @returns {Promise<Array<any>>}
 */
export const activeVaultList = async (filterKey, options = {}) => {
  if (!isActiveVaultInitialized) {
    throw new Error('Vault not initialised')
  }

  const includeOtpCodes = options.includeOtpCodes !== false
  const enrich = (record) => enrichRecordForClient(record, { includeOtpCodes })

  // App login list: prefer v2 when present (merge namespaces by id).
  if (filterKey === 'record/' || filterKey === 'record-v2/') {
    return (await listMergedRecords()).map(enrich)
  }

  const results = (
    await collectActiveVaultEntries(
      filterKey ? (key) => key?.startsWith(filterKey) : undefined
    )
  ).map(({ value }) => value)

  if (filterKey?.startsWith('record/') || filterKey?.startsWith('record-v2/')) {
    return results.map(enrich)
  }

  return results
}

/**
 * @returns {string}
 */
export const activeVaultGetWriterKey = () => {
  if (!isActiveVaultInitialized) {
    throw new Error('Vault not initialised')
  }
  return b4a.toString(activeVaultInstance.writerKey, 'hex')
}

/**
 * Rotate the vault epoch when the roster changed, or start the first one.
 * @param {{ start?: boolean }} [options]
 * @returns {Promise<object>} the epoch store's rotation result
 */
export const activeVaultEnsureEpoch = async ({ start = false } = {}) => {
  if (!isActiveVaultInitialized || !epochStore) {
    throw new Error('Vault not initialised')
  }
  return epochStore.ensureEpoch({ start })
}

/**
 * @returns {Promise<object>} the epoch status of the active vault
 */
export const activeVaultGetEpochStatus = async () => {
  if (!isActiveVaultInitialized || !epochStore) {
    throw new Error('Vault not initialised')
  }
  return epochStore.status()
}

/**
 * @param {{
 *   gte?: { key: string },
 *   lte?: { key: string },
 *   gt?:  { key: string },
 *   lt?:  { key: string },
 *   limit?: number,
 *   reverse?: boolean
 * }} options
 * @returns {Promise<Array<{ key: string, value: any }>>}
 */
export const activeVaultFind = async ({
  gte,
  lte,
  gt,
  lt,
  limit = 1000,
  reverse
} = {}) => {
  if (!isActiveVaultInitialized) {
    throw new Error('Vault not initialised')
  }

  const records = await epochStore.find({ gte, lte, gt, lt, limit, reverse })

  const results = []
  for (const record of records) {
    if (!record?.value) continue
    let value
    try {
      value = JSON.parse(record.value)
    } catch (err) {
      workletLogger.error('activeVaultFind: failed to parse record', {
        key: record.key,
        err
      })
      continue
    }
    if (
      record.key?.startsWith('record/') ||
      record.key?.startsWith('record-v2/')
    ) {
      results.push({ key: record.key, value: enrichRecordForClient(value) })
    } else {
      results.push({ key: record.key, value })
    }
  }
  return results
}

/**
 * @param {string} key
 * @returns {Promise<void>}
 */
export const activeVaultGet = async (key) => {
  if (!isActiveVaultInitialized) {
    throw new Error('Vault not initialised')
  }

  const recordId = parseRecordIdFromKey(key)
  if (recordId) {
    const found = await getReadableRecord(recordId)
    if (!found) {
      return null
    }
    return enrichRecordForClient(found.record)
  }

  const res = await epochStore.get(key)

  if (!res || !res.value) {
    return null
  }

  const { value, file } = res || {}
  const parsedValue = JSON.parse(value)

  if (file) {
    Object.defineProperty(parsedValue, 'file', {
      value: file,
      enumerable: true
    })
  }

  return parsedValue
}

/**
 * @returns {Promise<string>}
 */
export const createInvite = async () => {
  await activeVaultInstance.deleteInvite()
  const inviteCode = await activeVaultInstance.createInvite()

  const response = await epochStore.get('vault')
  const { value: vault } = response || {}
  if (!vault) {
    throw new Error('Vault not found')
  }

  const parsedVault = JSON.parse(vault)

  const vaultId = parsedVault.id

  return `${vaultId}/${inviteCode}`
}

/**
 * @returns {Promise<void>}
 */
export const deleteInvite = async () => {
  await activeVaultInstance.deleteInvite()

  const response = await epochStore.get('vault')
  const { value: vault } = response || {}

  if (!vault) {
    throw new Error('Vault not found')
  }
}

/**
 * @param {string} inviteCode
 * @returns {Promise<{ vaultId: string, encryptionKey: string }>}
 */
export const pairActiveVault = async (inviteCode) => {
  const wasActive = isActiveVaultInitialized

  try {
    const [vaultId, inviteKey] = inviteCode.split('/')
    if (isActiveVaultInitialized) {
      await closeActiveVaultInstance()
    }

    const encryptionKey = await pearpassPairer.pairInstance(
      buildPath(`vault/${vaultId}`),
      inviteKey
    )
    return { vaultId, encryptionKey }
  } catch (error) {
    if (wasActive) {
      try {
        await restartActiveVault()
      } catch {
        throw new Error(`Pairing failed: ${error.message}`)
      }
    }
    throw new Error(`Pairing failed: ${error.message}`)
  }
}

export const cancelPairActiveVault = async () => {
  await pearpassPairer.cancelPairing()
}

/**
 * @param {{
 *  vaultId: string
 *   onUpdate: () => void
 * }} options
 */
export const initListener = async ({ vaultId, onUpdate }) => {
  if (vaultId === listeningVaultId) {
    return
  }

  // Only drop our own listener: the epoch store listens to 'update' too.
  if (activeVaultUpdateListener) {
    activeVaultInstance.removeListener('update', activeVaultUpdateListener)
  }

  activeVaultUpdateListener = () => {
    // Peer/echo updates: incremental reconcile before UI refetch (no full remigrate).
    scheduleIncrementalReconcile(() => {
      onUpdate?.()
      void syncEpoch({ ensure: true })
    })
  }
  activeVaultInstance.on('update', activeVaultUpdateListener)

  listeningVaultId = vaultId
  lastOnUpdateCallback = onUpdate
}

/**
 * @returns {Promise<void>}
 */
export const restartActiveVault = async () => {
  if (!lastActiveVaultId) {
    throw new Error('[restartActiveVault]: No previous active vault to restart')
  }

  if (isActiveVaultInitialized) {
    await closeActiveVaultInstance()
  }

  await initActiveVaultInstance({
    id: lastActiveVaultId,
    encryptionKey: lastActiveVaultEncryptionKey
  })

  if (lastOnUpdateCallback) {
    await initListener({
      vaultId: lastActiveVaultId,
      onUpdate: lastOnUpdateCallback
    })
  }
}

/**
 * @returns {Promise<void>}
 */
export const closeAllInstances = async () => {
  if (isActiveVaultInitialized) {
    await closeActiveVaultInstance()
  }

  if (isVaultsInitialized) {
    await closeVaultsInstance()
  }

  if (isEncryptionInitialized) {
    await encryptionClose()
  }

  clearRestartCache()
}

/**
 * Blind mirrors management
 */

/**
 * @returns {Promise<Array<{key: string, isDefault: boolean}>>}
 */
export const getBlindMirrors = async () => {
  if (!isActiveVaultInitialized) {
    throw new Error('[getBlindMirrors]: Vault not initialised')
  }

  const mirrors = await activeVaultInstance.getMirror()
  const mirrorsArray = Array.isArray(mirrors) ? mirrors : []

  try {
    const metadata = await activeVaultGet('mirror-metadata')

    const isDefault = metadata?.isDefault ?? false

    const enrichedMirrors = mirrorsArray.map((mirror) => ({
      ...mirror,
      isDefault
    }))

    return enrichedMirrors
  } catch (error) {
    throw new Error(
      `[getBlindMirrors]: Failed to get mirror metadata: ${error?.message || 'Unexpected error'}`
    )
  }
}

/**
 * @param {boolean} isDefault
 * @returns {Promise<void>}
 */
const setMirrorMetadata = async (isDefault) => {
  await activeVaultAdd('mirror-metadata', { isDefault })
}

/**
 * @param {Array<string>} mirrors
 * @returns {Promise<void>}
 */
export const addBlindMirrors = async (mirrors) => {
  if (!isActiveVaultInitialized) {
    throw new Error('[addBlindMirrors]: Vault not initialised')
  }

  if (!Array.isArray(mirrors) || mirrors.length === 0) {
    throw new Error('[addBlindMirrors]: No mirrors provided')
  }

  await Promise.all(
    mirrors.map((mirror) => activeVaultInstance.addMirror(mirror))
  )

  await setMirrorMetadata(false)
}

/**
 * @returns {Promise<void>}
 */
export const removeBlindMirror = async (key) => {
  if (!isActiveVaultInitialized) {
    throw new Error('[removeBlindMirror]: Vault not initialised')
  }

  if (!key) {
    throw new Error('[removeBlindMirror]: mirror key not provided!')
  }

  await activeVaultInstance.removeMirror(key)
}

/**
 * @returns {Promise<void>}
 */
export const addDefaultBlindMirrors = async () => {
  if (!isActiveVaultInitialized) {
    throw new Error('[addDefaultBlindMirrors]: Vault not initialised')
  }

  await Promise.all(
    defaultMirrorKeys.map((key) => activeVaultInstance.addMirror(key))
  )

  await setMirrorMetadata(true)
}

/**
 * Remove all blind mirrors from the active vault
 * @returns {Promise<void>}
 */
export const removeAllBlindMirrors = async () => {
  if (!isActiveVaultInitialized) {
    throw new Error('[removeAllBlindMirrors]: Vault not initialised')
  }

  const currentMirrors = await activeVaultInstance.getMirror()
  const currentKeys = (Array.isArray(currentMirrors) ? currentMirrors : []).map(
    (m) => m?.key
  )

  await Promise.all(
    currentKeys.map((key) => activeVaultInstance.removeMirror(key))
  )

  await vaultRemove('mirror-metadata')
}

export const getHashedPassword = async () => {
  const masterEncryption = await vaultsGet('masterEncryption')
  return masterEncryption?.hashedPassword
}

/**
 * Job queue storage path management
 * @param {string} path
 * @returns {void}
 */
export const setJobStoragePath = (path) => {
  const sanitizedPath = validateAndSanitizePath(path)
  JOB_STORAGE_PATH = sanitizedPath
}

/**
 * @param {string} relativePath
 * @returns {string}
 */
export const buildJobPath = (relativePath) => {
  if (!JOB_STORAGE_PATH) {
    throw new Error('JOB_STORAGE_PATH not set')
  }

  const resolved = barePath.join(JOB_STORAGE_PATH, relativePath)

  const normalizedRoot = barePath.normalize(JOB_STORAGE_PATH)
  const normalizedResolved = barePath.normalize(resolved)

  if (
    normalizedResolved !== normalizedRoot &&
    !normalizedResolved.startsWith(normalizedRoot + barePath.sep)
  ) {
    throw new Error('Path traversal detected')
  }

  return normalizedResolved
}

/**
 * Reads and decrypts the job queue file.
 * @returns {Promise<Array>}
 */
export const readAndDecryptJobFile = async () => {
  const hashedPasswordHex = await getHashedPassword()
  if (!hashedPasswordHex) {
    return []
  }

  const filePath = buildJobPath(JOB_FILE_NAME)

  let fileData
  try {
    fileData = fs.readFileSync(filePath)
  } catch (err) {
    if (err.code === 'ENOENT') {
      return []
    }
    throw err
  }

  if (fileData.length < JOB_FILE_HEADER_SIZE + JOB_FILE_NONCE_SIZE) {
    throw new Error('Job file too small')
  }

  const magic = fileData.slice(0, 4).toString('utf-8')
  if (magic !== JOB_FILE_MAGIC) {
    throw new Error('Invalid job file magic bytes')
  }

  const version = fileData.readUInt16LE(4)
  if (version !== 1) {
    throw new Error(`Unsupported job file version: ${version}`)
  }

  const nonce = fileData.slice(
    JOB_FILE_HEADER_SIZE,
    JOB_FILE_HEADER_SIZE + JOB_FILE_NONCE_SIZE
  )
  const ciphertext = fileData.slice(JOB_FILE_HEADER_SIZE + JOB_FILE_NONCE_SIZE)

  if (ciphertext.length < sodium.crypto_secretbox_MACBYTES) {
    throw new Error('Job file ciphertext too small')
  }

  const key = sodium.sodium_malloc(sodium.crypto_secretbox_KEYBYTES)
  const plaintext = sodium.sodium_malloc(
    ciphertext.length - sodium.crypto_secretbox_MACBYTES
  )

  try {
    key.write(hashedPasswordHex, 'hex')

    const opened = sodium.crypto_secretbox_open_easy(
      plaintext,
      ciphertext,
      nonce,
      key
    )

    if (!opened) {
      throw new Error('Failed to decrypt job file: authentication failed')
    }

    const json = plaintext.toString('utf-8')
    const parsed = JSON.parse(json)
    return parsed
  } finally {
    sodium.sodium_memzero(key)
    sodium.sodium_memzero(plaintext)
    sodium.sodium_free(key)
    sodium.sodium_free(plaintext)
  }
}

/**
 * Encrypts and writes the job queue file atomically.
 * @param {Array} jobs
 * @returns {Promise<void>}
 */
export const writeAndEncryptJobFile = async (jobs) => {
  const hashedPasswordHex = await getHashedPassword()
  if (!hashedPasswordHex) {
    throw new Error('Not authenticated')
  }

  const filePath = buildJobPath(JOB_FILE_NAME)
  const tempPath = filePath + '.tmp'

  const dirPath = barePath.dirname(filePath)
  try {
    fs.mkdirSync(dirPath, { recursive: true })
  } catch (err) {
    if (err.code !== 'EEXIST') {
      throw err
    }
  }

  const jsonBuffer = Buffer.from(JSON.stringify(jobs), 'utf-8')

  const nonce = sodium.sodium_malloc(JOB_FILE_NONCE_SIZE)
  const key = sodium.sodium_malloc(sodium.crypto_secretbox_KEYBYTES)
  const ciphertext = sodium.sodium_malloc(
    jsonBuffer.length + sodium.crypto_secretbox_MACBYTES
  )

  try {
    sodium.randombytes_buf(nonce)
    key.write(hashedPasswordHex, 'hex')

    sodium.crypto_secretbox_easy(ciphertext, jsonBuffer, nonce, key)

    const header = Buffer.alloc(JOB_FILE_HEADER_SIZE)
    header.write(JOB_FILE_MAGIC, 0, 4, 'utf-8')
    header.writeUInt16LE(1, 4)
    header.writeUInt16LE(jobs.length, 6)

    const output = Buffer.concat([
      header,
      Buffer.from(nonce),
      Buffer.from(ciphertext)
    ])

    fs.writeFileSync(tempPath, output)
    fs.renameSync(tempPath, filePath)
  } finally {
    sodium.sodium_memzero(nonce)
    sodium.sodium_memzero(key)
    sodium.sodium_memzero(ciphertext)
    sodium.sodium_free(nonce)
    sodium.sodium_free(key)
    sodium.sodium_free(ciphertext)
  }
}

/**
 * Reads a raw record from the active vault by key without enrichment.
 * @param {string} key
 * @returns {Promise<object|null>}
 */
const activeVaultGetRaw = async (key) => {
  if (!isActiveVaultInitialized) {
    throw new Error('Vault not initialised')
  }

  const res = await epochStore.get(key)
  if (!res || !res.value) return null
  return JSON.parse(res.value)
}

/**
 * Enriches a record for client consumption.
 * If the record has an OTP config, strips the secret and attaches
 * `otpPublic`. Current codes are generated unless
 * `options.includeOtpCodes` is false (autofill list).
 * The original record in storage is never mutated.
 * @param {object} record
 * @param {{ includeOtpCodes?: boolean }} [options]
 * @returns {object}
 */
export const enrichRecordForClient = (record, options = {}) => {
  if (!record?.data?.otp) {
    return record
  }

  const includeOtpCodes = options.includeOtpCodes !== false
  const otp = record.data.otp
  const enriched = {
    ...record,
    data: { ...record.data }
  }

  try {
    const otpPublic = {
      type: otp.type,
      digits: otp.digits,
      issuer: otp.issuer,
      label: otp.label
    }

    if (otp.type === OTP_TYPE.TOTP) {
      otpPublic.period = otp.period
      if (includeOtpCodes) {
        const { code, timeRemaining } = generateTOTP(otp)
        otpPublic.currentCode = code
        otpPublic.timeRemaining = timeRemaining
      }
    } else if (otp.type === OTP_TYPE.HOTP && includeOtpCodes) {
      const { code } = generateHOTP(otp)
      otpPublic.currentCode = code
    }

    delete enriched.data.otp
    enriched.otpPublic = otpPublic
  } catch (error) {
    workletLogger.error('Failed to enrich record with OTP data:', error)
    delete enriched.data.otp
  }

  return enriched
}

/**
 * Generates OTP codes for a list of record IDs.
 * @param {string[]} recordIds
 * @returns {Promise<Array<{ recordId: string, code: string, timeRemaining?: number }>>}
 */
export const generateOtpCodesByIds = async (recordIds) => {
  if (!isActiveVaultInitialized) {
    throw new Error('Vault not initialised')
  }

  const results = []

  for (const recordId of recordIds) {
    try {
      const record = (await getReadableRecord(recordId))?.record
      if (!record?.data?.otp) continue

      const otp = record.data.otp
      if (otp.type === OTP_TYPE.TOTP) {
        const { code, timeRemaining } = generateTOTP(otp)
        results.push({ recordId, code, timeRemaining })
      } else if (otp.type === OTP_TYPE.HOTP) {
        const { code } = generateHOTP(otp)
        results.push({ recordId, code })
      }
    } catch (error) {
      workletLogger.error(
        `Failed to generate OTP code for record ${recordId}:`,
        error
      )
    }
  }

  return results
}

// Store errors reach the UI in writeErrorMessage's words, as in activeVaultAdd.
const writeOtpRecord = async (recordId, record) => {
  try {
    await writeRecordV2AndProjectV1(
      createActiveVaultAdapter(),
      recordId,
      record
    )
  } catch (error) {
    throw new Error(writeErrorMessage(error))
  }
}

/**
 * Generates the next HOTP code for a record and increments the counter.
 * @param {string} recordId
 * @returns {Promise<{ code: string, counter: number }>}
 */
export const generateHotpNext = async (recordId) => {
  if (!isActiveVaultInitialized) {
    throw new Error('Vault not initialised')
  }

  const record = (await getReadableRecord(recordId))?.record
  if (!record) {
    throw new Error('Record not found')
  }
  if (!record.data?.otp || record.data.otp.type !== OTP_TYPE.HOTP) {
    throw new Error('Record does not have HOTP configuration')
  }

  const otp = record.data.otp
  const newCounter = (otp.counter || 0) + 1

  const { code } = generateHOTP({ ...otp, counter: newCounter })

  record.data.otp = { ...otp, counter: newCounter }
  record.updatedAt = Date.now()
  await writeOtpRecord(recordId, record)

  return { code, counter: newCounter }
}

/**
 * Adds an OTP configuration to a record.
 * @param {string} recordId
 * @param {string} otpInput - otpauth:// URI or raw Base32 secret
 * @returns {Promise<void>}
 */
export const addOtpToRecord = async (recordId, otpInput) => {
  if (!isActiveVaultInitialized) {
    throw new Error('Vault not initialised')
  }

  const record = (await getReadableRecord(recordId))?.record
  if (!record?.data) {
    throw new Error('Record not found')
  }

  const otpConfig = parseOtpInput(otpInput)
  record.data.otp = otpConfig
  record.updatedAt = Date.now()
  await writeOtpRecord(recordId, record)
}

/**
 * Removes OTP configuration from a record.
 * @param {string} recordId
 * @returns {Promise<void>}
 */
export const removeOtpFromRecord = async (recordId) => {
  if (!isActiveVaultInitialized) {
    throw new Error('Vault not initialised')
  }

  const record = (await getReadableRecord(recordId))?.record
  if (!record?.data) {
    throw new Error('Record not found')
  }

  delete record.data.otp
  record.updatedAt = Date.now()
  await writeOtpRecord(recordId, record)
}

/**
 * Finds records whose stored OTP secret matches the given one.
 * @param {{ secret?: string, excludeRecordId?: string }} params
 * @returns {Promise<Array<{ id: string, title: string }>>}
 */
export const findOtpDuplicates = async ({ secret, excludeRecordId } = {}) => {
  if (!isActiveVaultInitialized) {
    throw new Error('Vault not initialised')
  }

  if (!secret) return []

  return filterDuplicateRecords(secret, await listMergedRecords(), {
    excludeRecordId
  })
}

/**
 * @returns {Promise<Array<{
 *   id: string,
 *   type: string,
 *   data: { title?: string, username?: string, otp: object }
 * }>>}
 */
export const exportOtpRecords = async () => {
  if (!isActiveVaultInitialized) {
    throw new Error('Vault not initialised')
  }

  return toExportableOtpRecords(await listMergedRecords())
}
