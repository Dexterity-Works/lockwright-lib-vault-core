/**
 * Dual-store Autopass namespaces: record/ (schema 1) + record-v2/ (schema 2).
 * Pure helpers + migrate/reconcile orchestration against a vault adapter.
 */

export const RECORD_V1_PREFIX = 'record/'
export const RECORD_V2_PREFIX = 'record-v2/'
export const VAULT_EXT_KEY = 'vault-ext'
export const SCHEMA_V2 = 2
export const DEFAULT_URI_MATCH = 'baseDomain'

const V1_RECORD_RE = /^record\/([^/]+)$/
const V2_RECORD_RE = /^record-v2\/([^/]+)$/
const V1_FILE_RE = /^record\/([^/]+)\/file\/([^/]+)$/
const V2_FILE_RE = /^record-v2\/([^/]+)\/file\/([^/]+)$/

/**
 * @param {string} id
 * @returns {string}
 */
export const recordKeyV1 = (id) => `${RECORD_V1_PREFIX}${id}`

/**
 * @param {string} id
 * @returns {string}
 */
export const recordKeyV2 = (id) => `${RECORD_V2_PREFIX}${id}`

/**
 * @param {string} recordId
 * @param {string} fileId
 * @returns {string}
 */
export const fileKeyV1 = (recordId, fileId) =>
  `${RECORD_V1_PREFIX}${recordId}/file/${fileId}`

/**
 * @param {string} recordId
 * @param {string} fileId
 * @returns {string}
 */
export const fileKeyV2 = (recordId, fileId) =>
  `${RECORD_V2_PREFIX}${recordId}/file/${fileId}`

/**
 * @param {string} key
 * @returns {boolean}
 */
export const isV1RecordKey = (key) =>
  typeof key === 'string' && V1_RECORD_RE.test(key)

/**
 * @param {string} key
 * @returns {boolean}
 */
export const isV2RecordKey = (key) =>
  typeof key === 'string' && V2_RECORD_RE.test(key)

/**
 * @param {string} key
 * @returns {boolean}
 */
export const isV1FileKey = (key) =>
  typeof key === 'string' && V1_FILE_RE.test(key)

/**
 * @param {string} key
 * @returns {boolean}
 */
export const isV2FileKey = (key) =>
  typeof key === 'string' && V2_FILE_RE.test(key)

/**
 * @param {string} key
 * @returns {string|null}
 */
export const parseRecordIdFromKey = (key) => {
  const v1 = typeof key === 'string' ? key.match(V1_RECORD_RE) : null
  if (v1) return v1[1]
  const v2 = typeof key === 'string' ? key.match(V2_RECORD_RE) : null
  if (v2) return v2[1]
  return null
}

/**
 * @param {string} key
 * @returns {{ recordId: string, fileId: string, schema: 1|2 }|null}
 */
export const parseFileKey = (key) => {
  if (typeof key !== 'string') return null
  const v1 = key.match(V1_FILE_RE)
  if (v1) return { recordId: v1[1], fileId: v1[2], schema: 1 }
  const v2 = key.match(V2_FILE_RE)
  if (v2) return { recordId: v2[1], fileId: v2[2], schema: 2 }
  return null
}

/**
 * @param {string} v1FileKey
 * @returns {string|null}
 */
export const v1FileKeyToV2 = (v1FileKey) => {
  const parsed = parseFileKey(v1FileKey)
  if (!parsed || parsed.schema !== 1) return null
  return fileKeyV2(parsed.recordId, parsed.fileId)
}

/**
 * Stable JSON compare for no-op detection.
 * @param {any} a
 * @param {any} b
 * @returns {boolean}
 */
export const deepEqualJson = (a, b) => {
  try {
    return JSON.stringify(a) === JSON.stringify(b)
  } catch {
    return false
  }
}

/**
 * @param {string[]|undefined} websites
 * @param {Array<{ uri?: string, match?: string }>|undefined} existingUris
 * @returns {Array<{ uri: string, match: string }>}
 */
export const deriveUrisFromWebsites = (websites, existingUris) => {
  const list = Array.isArray(websites) ? websites : []
  const byUri = new Map()
  if (Array.isArray(existingUris)) {
    for (const entry of existingUris) {
      if (entry && typeof entry.uri === 'string') {
        byUri.set(entry.uri, entry)
      }
    }
  }
  return list.map((uri) => {
    const prev = byUri.get(uri)
    if (prev && typeof prev === 'object') {
      return {
        uri,
        match:
          typeof prev.match === 'string' && prev.match.length > 0
            ? prev.match
            : DEFAULT_URI_MATCH
      }
    }
    return { uri, match: DEFAULT_URI_MATCH }
  })
}

/**
 * @param {Array<{ uri?: string }>|undefined} uris
 * @param {string[]|undefined} fallbackWebsites
 * @returns {string[]}
 */
export const deriveWebsitesFromUris = (uris, fallbackWebsites) => {
  if (Array.isArray(uris)) {
    return uris
      .map((entry) =>
        entry && typeof entry.uri === 'string' ? entry.uri : null
      )
      .filter((uri) => typeof uri === 'string')
  }
  return Array.isArray(fallbackWebsites) ? [...fallbackWebsites] : []
}

/**
 * Convert a raw v1 storage record into a v2 storage record (keeps OTP secrets).
 * @param {object} v1Record
 * @returns {object}
 */
export const convertV1RecordToV2 = (v1Record) => {
  if (!v1Record || typeof v1Record !== 'object') {
    throw new Error('convertV1RecordToV2: record required')
  }

  const data = { ...(v1Record.data || {}) }
  const websites = Array.isArray(data.websites) ? data.websites : []

  if (v1Record.type === 'login' || Array.isArray(data.websites) || data.uris) {
    if (!Array.isArray(data.uris) || data.uris.length === 0) {
      data.uris = deriveUrisFromWebsites(websites, data.uris)
    }
    data.websites = deriveWebsitesFromUris(data.uris, websites)
  }

  return {
    ...v1Record,
    schema: SCHEMA_V2,
    data
  }
}

/**
 * Project a v2 login (or any) record to v1 wire shape.
 * websites = uris.map(u => u.uri) or existing string websites; strip uris + schema.
 * @param {object} v2Record
 * @returns {object}
 */
export const projectV2ToV1 = (v2Record) => {
  if (!v2Record || typeof v2Record !== 'object') {
    throw new Error('projectV2ToV1: record required')
  }

  const rest = { ...v2Record }
  delete rest.schema
  const dataIn = rest.data && typeof rest.data === 'object' ? rest.data : {}
  const { uris, ...dataRest } = dataIn

  const websites = deriveWebsitesFromUris(
    uris,
    Array.isArray(dataRest.websites) ? dataRest.websites : undefined
  )

  const projected = {
    ...rest,
    data: {
      ...dataRest,
      websites
    }
  }

  // Keep version if present (v1 wire expects it); do not invent schema on v1.
  return projected
}

/**
 * Later-wins merge of projectable v1 fields into v2.
 * Returns null when no write is needed (v1 not later, or result unchanged).
 * Keeps v2-only fields (e.g. uri match) when URLs still exist.
 * @param {object|null|undefined} v1Record
 * @param {object|null|undefined} v2Record
 * @returns {object|null}
 */
export const mergeV1IntoV2 = (v1Record, v2Record) => {
  if (!v1Record || typeof v1Record !== 'object') {
    return null
  }

  if (!v2Record || typeof v2Record !== 'object') {
    return convertV1RecordToV2(v1Record)
  }

  const v1UpdatedAt = Number(v1Record.updatedAt) || 0
  const v2UpdatedAt = Number(v2Record.updatedAt) || 0
  if (v1UpdatedAt <= v2UpdatedAt) {
    return null
  }

  const v1Data =
    v1Record.data && typeof v1Record.data === 'object' ? v1Record.data : {}
  const v2Data =
    v2Record.data && typeof v2Record.data === 'object' ? v2Record.data : {}

  const mergedData = { ...v2Data }

  for (const key of Object.keys(v1Data)) {
    if (key === 'uris') continue
    if (key === 'websites') continue
    mergedData[key] = v1Data[key]
  }

  if (Array.isArray(v1Data.websites) || Array.isArray(v2Data.uris)) {
    const websites = Array.isArray(v1Data.websites)
      ? v1Data.websites
      : deriveWebsitesFromUris(v2Data.uris, v2Data.websites)
    mergedData.uris = deriveUrisFromWebsites(websites, v2Data.uris)
    mergedData.websites = websites
  }

  const merged = {
    ...v2Record,
    id: v1Record.id ?? v2Record.id,
    type: v1Record.type ?? v2Record.type,
    vaultId: v1Record.vaultId ?? v2Record.vaultId,
    folder: v1Record.folder !== undefined ? v1Record.folder : v2Record.folder,
    isFavorite:
      v1Record.isFavorite !== undefined
        ? v1Record.isFavorite
        : v2Record.isFavorite,
    createdAt: v1Record.createdAt ?? v2Record.createdAt,
    updatedAt: v1Record.updatedAt,
    version: v1Record.version ?? v2Record.version,
    schema: SCHEMA_V2,
    data: mergedData
  }

  if (deepEqualJson(merged, v2Record)) {
    return null
  }

  return merged
}

/**
 * Completeness: every v1 record id / file key has a v2 twin. V2-only extras OK.
 * @param {Iterable<string>} v1RecordIds
 * @param {Iterable<string>} v2RecordIds
 * @param {Iterable<string>} v1FileKeys
 * @param {Iterable<string>} v2FileKeys
 * @returns {{ complete: boolean, missingRecordIds: string[], missingFileKeys: string[] }}
 */
export const checkMigrationCompleteness = (
  v1RecordIds,
  v2RecordIds,
  v1FileKeys,
  v2FileKeys
) => {
  const v2Ids = new Set(v2RecordIds)
  const v2Files = new Set(v2FileKeys)

  const missingRecordIds = []
  for (const id of v1RecordIds) {
    if (!v2Ids.has(id)) missingRecordIds.push(id)
  }

  const missingFileKeys = []
  for (const v1Key of v1FileKeys) {
    const v2Key = v1FileKeyToV2(v1Key)
    if (!v2Key || !v2Files.has(v2Key)) {
      missingFileKeys.push(v1Key)
    }
  }

  return {
    complete: missingRecordIds.length === 0 && missingFileKeys.length === 0,
    missingRecordIds,
    missingFileKeys
  }
}

/**
 * Build id → updatedAt index from record entries.
 * @param {Array<{ id?: string, updatedAt?: number }>} records
 * @returns {Map<string, number>}
 */
export const buildRecordUpdatedAtIndex = (records) => {
  const index = new Map()
  for (const record of records) {
    if (record?.id) {
      index.set(record.id, Number(record.updatedAt) || 0)
    }
  }
  return index
}

/**
 * @typedef {{
 *   getJson: (key: string) => Promise<object|null>,
 *   getWithFile: (key: string) => Promise<{ value: object|null, file: Buffer|null }>,
 *   addJson: (key: string, data: object, file?: Buffer|null) => Promise<void>,
 *   remove: (key: string) => Promise<void>,
 *   listEntries: () => Promise<Array<{ key: string, value: object|null }>>,
 *   skipIds?: Set<string>
 * }} VaultAdapter
 *
 * `skipIds`, read once `listEntries` returned: record ids with a row the
 * listing left out because it could not be read. Their records and files
 * are neither converted, merged, copied, nor deleted.
 */

/**
 * Partition list entries into v1/v2 records and files.
 * @param {Array<{ key: string, value: object|null }>} entries
 */
export const partitionNamespaceEntries = (entries) => {
  /** @type {Map<string, object>} */
  const v1Records = new Map()
  /** @type {Map<string, object>} */
  const v2Records = new Map()
  /** @type {string[]} */
  const v1FileKeys = []
  /** @type {string[]} */
  const v2FileKeys = []

  for (const { key, value } of entries) {
    if (isV1RecordKey(key) && value) {
      const id = parseRecordIdFromKey(key)
      if (id) v1Records.set(id, value)
    } else if (isV2RecordKey(key) && value) {
      const id = parseRecordIdFromKey(key)
      if (id) v2Records.set(id, value)
    } else if (isV1FileKey(key)) {
      v1FileKeys.push(key)
    } else if (isV2FileKey(key)) {
      v2FileKeys.push(key)
    }
  }

  return { v1Records, v2Records, v1FileKeys, v2FileKeys }
}

/**
 * First-launch (or resume) migrate: convert missing v2 records, copy missing files.
 * Sets vault-ext.migratedToSchema = 2 only when complete.
 * Never intended to run file copies after watermark is set (caller must skip).
 *
 * @param {VaultAdapter} vault
 * @returns {Promise<{
 *   alreadyMigrated: boolean,
 *   complete: boolean,
 *   recordsWritten: number,
 *   filesCopied: number,
 *   missingRecordIds: string[],
 *   missingFileKeys: string[]
 * }>}
 */
export const migrateToSchema2 = async (vault, options = {}) => {
  const onProgress =
    typeof options.onProgress === 'function' ? options.onProgress : null

  const vaultExt = (await vault.getJson(VAULT_EXT_KEY)) || {}
  if (Number(vaultExt.migratedToSchema) >= SCHEMA_V2) {
    onProgress?.({ done: 0, total: 0 })
    return {
      alreadyMigrated: true,
      complete: true,
      recordsWritten: 0,
      filesCopied: 0,
      missingRecordIds: [],
      missingFileKeys: []
    }
  }

  const entries = await vault.listEntries()
  const skipIds = vault.skipIds ?? new Set()
  const { v1Records, v2Records, v1FileKeys, v2FileKeys } =
    partitionNamespaceEntries(entries)

  const v2FileSet = new Set(v2FileKeys)
  const filesToCopy = v1FileKeys.filter((v1Key) => {
    const v2Key = v1FileKeyToV2(v1Key)
    return (
      v2Key &&
      !v2FileSet.has(v2Key) &&
      !skipIds.has(parseFileKey(v1Key).recordId)
    )
  })
  const total = v1Records.size + filesToCopy.length
  let done = 0
  onProgress?.({ done, total })

  let recordsWritten = 0
  let filesCopied = 0

  for (const [id, v1Record] of v1Records) {
    const existingV2 = v2Records.get(id)
    if (skipIds.has(id)) {
      // Left incomplete. The app runs it again on the next latest epoch this
      // device can open, which may carry the row's key.
    } else if (!existingV2) {
      const v2 = convertV1RecordToV2(v1Record)
      await vault.addJson(recordKeyV2(id), v2)
      v2Records.set(id, v2)
      recordsWritten++
    } else {
      const merged = mergeV1IntoV2(v1Record, existingV2)
      if (merged) {
        await vault.addJson(recordKeyV2(id), merged)
        v2Records.set(id, merged)
        recordsWritten++
      }
    }
    done++
    onProgress?.({ done, total })
  }

  for (const v1Key of filesToCopy) {
    const v2Key = v1FileKeyToV2(v1Key)
    const { value, file } = await vault.getWithFile(v1Key)
    await vault.addJson(
      v2Key,
      value && typeof value === 'object' ? value : {},
      file
    )
    v2FileSet.add(v2Key)
    v2FileKeys.push(v2Key)
    filesCopied++
    done++
    onProgress?.({ done, total })
  }

  const completeness = checkMigrationCompleteness(
    v1Records.keys(),
    v2Records.keys(),
    v1FileKeys,
    v2FileKeys
  )

  if (completeness.complete) {
    await vault.addJson(VAULT_EXT_KEY, {
      ...vaultExt,
      migratedToSchema: SCHEMA_V2
    })
  }

  return {
    alreadyMigrated: false,
    complete: completeness.complete,
    recordsWritten,
    filesCopied,
    missingRecordIds: completeness.missingRecordIds,
    missingFileKeys: completeness.missingFileKeys
  }
}

/**
 * Incremental reconcile after Autopass `update`.
 * Copies a file only when the v2 key is missing. No-op writes when unchanged.
 *
 * @param {VaultAdapter} vault
 * @param {{
 *   previousV1Ids?: Set<string>|null,
 *   blockV1DeleteMirror?: boolean
 * }} [options]
 * @returns {Promise<{
 *   previousV1Ids: Set<string>,
 *   recordsWritten: number,
 *   recordsDeleted: number,
 *   filesCopied: number
 * }>}
 */
export const reconcileDualStore = async (vault, options = {}) => {
  const previousV1Ids = options.previousV1Ids || new Set()
  const blockV1DeleteMirror = options.blockV1DeleteMirror === true

  const entries = await vault.listEntries()
  const skipIds = vault.skipIds ?? new Set()
  const { v1Records, v2Records, v1FileKeys, v2FileKeys } =
    partitionNamespaceEntries(entries)

  let recordsWritten = 0
  let recordsDeleted = 0
  let filesCopied = 0

  for (const [id, v1Record] of v1Records) {
    if (skipIds.has(id)) continue
    const existingV2 = v2Records.get(id)
    if (!existingV2) {
      const v2 = convertV1RecordToV2(v1Record)
      await vault.addJson(recordKeyV2(id), v2)
      v2Records.set(id, v2)
      recordsWritten++
      continue
    }
    const merged = mergeV1IntoV2(v1Record, existingV2)
    if (merged) {
      await vault.addJson(recordKeyV2(id), merged)
      v2Records.set(id, merged)
      recordsWritten++
    }
  }

  if (!blockV1DeleteMirror) {
    for (const id of previousV1Ids) {
      if (v1Records.has(id) || skipIds.has(id)) continue
      if (!v2Records.has(id)) continue
      await vault.remove(recordKeyV2(id))
      // Remove v2 files for this record
      for (const v2Key of [...v2FileKeys]) {
        const parsed = parseFileKey(v2Key)
        if (parsed && parsed.schema === 2 && parsed.recordId === id) {
          await vault.remove(v2Key)
        }
      }
      v2Records.delete(id)
      recordsDeleted++
    }
  }

  const v2FileSet = new Set(v2FileKeys)
  for (const v1Key of v1FileKeys) {
    const v2Key = v1FileKeyToV2(v1Key)
    if (!v2Key || v2FileSet.has(v2Key)) continue
    if (skipIds.has(parseFileKey(v1Key).recordId)) continue
    const { value, file } = await vault.getWithFile(v1Key)
    await vault.addJson(
      v2Key,
      value && typeof value === 'object' ? value : {},
      file
    )
    v2FileSet.add(v2Key)
    filesCopied++
  }

  return {
    previousV1Ids: new Set(v1Records.keys()),
    recordsWritten,
    recordsDeleted,
    filesCopied
  }
}

/**
 * Prefer v2 raw record for an id; fall back to v1.
 * @param {VaultAdapter} vault
 * @param {string} recordId
 * @returns {Promise<{ record: object, key: string, schema: 1|2 }|null>}
 */
export const getRawRecordPreferV2 = async (vault, recordId) => {
  const v2Key = recordKeyV2(recordId)
  const v2 = await vault.getJson(v2Key)
  if (v2) return { record: v2, key: v2Key, schema: 2 }

  const v1Key = recordKeyV1(recordId)
  const v1 = await vault.getJson(v1Key)
  if (v1) return { record: v1, key: v1Key, schema: 1 }

  return null
}

/**
 * Write OTP (or other) update to v2 + projectable v1. No-op if unchanged.
 * @param {VaultAdapter} vault
 * @param {string} recordId
 * @param {object} updatedRecord - full storage record (with secrets)
 * @returns {Promise<void>}
 */
export const writeRecordV2AndProjectV1 = async (
  vault,
  recordId,
  updatedRecord
) => {
  const asV2 =
    updatedRecord?.schema === SCHEMA_V2
      ? updatedRecord
      : convertV1RecordToV2(updatedRecord)

  const existingV2 = await vault.getJson(recordKeyV2(recordId))
  if (!existingV2 || !deepEqualJson(existingV2, asV2)) {
    await vault.addJson(recordKeyV2(recordId), asV2)
  }

  const projected = projectV2ToV1(asV2)
  const existingV1 = await vault.getJson(recordKeyV1(recordId))
  if (!existingV1 || !deepEqualJson(existingV1, projected)) {
    await vault.addJson(recordKeyV1(recordId), projected)
  }
}
