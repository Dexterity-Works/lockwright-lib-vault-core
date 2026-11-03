import {
  RECORD_V1_PREFIX,
  RECORD_V2_PREFIX,
  VAULT_EXT_KEY,
  SCHEMA_V2,
  recordKeyV1,
  recordKeyV2,
  fileKeyV1,
  fileKeyV2,
  isV1RecordKey,
  isV2RecordKey,
  isV1FileKey,
  isV2FileKey,
  parseRecordIdFromKey,
  parseFileKey,
  v1FileKeyToV2,
  deriveUrisFromWebsites,
  deriveWebsitesFromUris,
  convertV1RecordToV2,
  projectV2ToV1,
  mergeV1IntoV2,
  checkMigrationCompleteness,
  migrateToSchema2,
  reconcileDualStore,
  writeRecordV2AndProjectV1,
  getRawRecordPreferV2,
  deepEqualJson,
  buildRecordUpdatedAtIndex
} from './recordNamespaces.js'

const makeLoginV1 = (overrides = {}) => {
  const baseData = {
    title: 'Example',
    username: 'user',
    password: 'secret-pass',
    websites: ['https://example.com'],
    otp: {
      secret: 'JBSWY3DPEHPK3PXP',
      type: 'TOTP',
      algorithm: 'SHA1',
      digits: 6,
      period: 30
    }
  }
  const { data: dataOverride, ...rest } = overrides
  return {
    id: 'rec1',
    version: 1,
    type: 'login',
    vaultId: 'vault1',
    folder: null,
    isFavorite: false,
    createdAt: 1000,
    updatedAt: 2000,
    ...rest,
    data: { ...baseData, ...(dataOverride || {}) }
  }
}

let fileCopyLog = []

const createMemoryVault = (initial = {}) => {
  const store = new Map()

  for (const [key, entry] of Object.entries(initial)) {
    if (entry && typeof entry === 'object' && 'value' in entry) {
      store.set(key, { value: entry.value, file: entry.file || null })
    } else {
      store.set(key, { value: entry, file: null })
    }
  }

  return {
    store,
    adapter: {
      getJson: async (key) => store.get(key)?.value ?? null,
      getWithFile: async (key) => {
        const entry = store.get(key)
        if (!entry) return { value: null, file: null }
        return { value: entry.value, file: entry.file }
      },
      addJson: async (key, data, file = null) => {
        const prev = store.get(key)
        store.set(key, {
          value: data,
          file:
            file !== null && file !== undefined ? file : (prev?.file ?? null)
        })
        if (key.includes('/file/') && file) {
          fileCopyLog.push(key)
        }
      },
      remove: async (key) => {
        store.delete(key)
      },
      listEntries: async () =>
        [...store.entries()].map(([key, entry]) => ({
          key,
          value: entry.value
        }))
    }
  }
}

describe('recordNamespaces key helpers', () => {
  test('prefixes and key builders', () => {
    expect(RECORD_V1_PREFIX).toBe('record/')
    expect(RECORD_V2_PREFIX).toBe('record-v2/')
    expect(recordKeyV1('a')).toBe('record/a')
    expect(recordKeyV2('a')).toBe('record-v2/a')
    expect(fileKeyV1('a', 'f')).toBe('record/a/file/f')
    expect(fileKeyV2('a', 'f')).toBe('record-v2/a/file/f')
  })

  test('key classifiers do not confuse record/ with record-v2/', () => {
    expect(isV1RecordKey('record/abc')).toBe(true)
    expect(isV1RecordKey('record-v2/abc')).toBe(false)
    expect(isV2RecordKey('record-v2/abc')).toBe(true)
    expect(isV1FileKey('record/abc/file/f1')).toBe(true)
    expect(isV1FileKey('record/abc')).toBe(false)
    expect(isV2FileKey('record-v2/abc/file/f1')).toBe(true)
    expect(parseRecordIdFromKey('record/abc')).toBe('abc')
    expect(parseFileKey('record/abc/file/f1')).toEqual({
      recordId: 'abc',
      fileId: 'f1',
      schema: 1
    })
    expect(v1FileKeyToV2('record/abc/file/f1')).toBe('record-v2/abc/file/f1')
  })

  test('rejects non-string and v2 keys when converting a v1 file key', () => {
    expect(parseRecordIdFromKey(null)).toBeNull()
    expect(parseFileKey(null)).toBeNull()
    expect(v1FileKeyToV2('record-v2/abc/file/f1')).toBeNull()
    expect(v1FileKeyToV2('record/abc')).toBeNull()
  })
})

describe('website and URI fallbacks', () => {
  test('uses defaults for missing websites and invalid prior URI entries', () => {
    expect(deriveUrisFromWebsites(undefined, undefined)).toEqual([])
    expect(
      deriveUrisFromWebsites(
        ['https://example.com', 'https://other.com'],
        [null, { uri: 3 }, { uri: 'https://example.com', match: '' }]
      )
    ).toEqual([
      { uri: 'https://example.com', match: 'baseDomain' },
      { uri: 'https://other.com', match: 'baseDomain' }
    ])
  })

  test('drops invalid URI entries and uses only array website fallbacks', () => {
    expect(deriveWebsitesFromUris([null, {}, { uri: 3 }], undefined)).toEqual(
      []
    )
    expect(deriveWebsitesFromUris(undefined, undefined)).toEqual([])
    expect(deriveWebsitesFromUris(undefined, ['https://example.com'])).toEqual([
      'https://example.com'
    ])
  })
})

test('buildRecordUpdatedAtIndex skips missing ids and defaults invalid times', () => {
  expect(
    buildRecordUpdatedAtIndex([
      null,
      {},
      { id: 'missing-time' },
      { id: 'invalid-time', updatedAt: 'not a time' }
    ])
  ).toEqual(
    new Map([
      ['missing-time', 0],
      ['invalid-time', 0]
    ])
  )
})

describe('convert / project / merge', () => {
  test('convertV1RecordToV2 keeps OTP secret and derives uris', () => {
    const v2 = convertV1RecordToV2(makeLoginV1())
    expect(v2.schema).toBe(SCHEMA_V2)
    expect(v2.data.otp.secret).toBe('JBSWY3DPEHPK3PXP')
    expect(v2.data.uris).toEqual([
      { uri: 'https://example.com', match: 'baseDomain' }
    ])
    expect(v2.data.websites).toEqual(['https://example.com'])
  })

  test('projectV2ToV1 strips uris/schema and derives websites', () => {
    const v2 = convertV1RecordToV2(makeLoginV1())
    v2.data.uris = [
      { uri: 'https://example.com', match: 'host' },
      { uri: 'https://other.com', match: 'baseDomain' }
    ]
    const v1 = projectV2ToV1(v2)
    expect(v1.schema).toBeUndefined()
    expect(v1.data.uris).toBeUndefined()
    expect(v1.data.websites).toEqual([
      'https://example.com',
      'https://other.com'
    ])
    expect(v1.version).toBe(1)
    expect(v1.data.otp.secret).toBe('JBSWY3DPEHPK3PXP')
  })

  test('mergeV1IntoV2 later-wins and keeps v2 uri match for surviving URLs', () => {
    const v1 = makeLoginV1({
      updatedAt: 5000,
      data: {
        password: 'new-pass',
        websites: ['https://example.com', 'https://new.com']
      }
    })
    const v2 = convertV1RecordToV2(
      makeLoginV1({
        updatedAt: 3000,
        data: { password: 'old-pass' }
      })
    )
    v2.data.uris = [{ uri: 'https://example.com', match: 'exact' }]

    const merged = mergeV1IntoV2(v1, v2)
    expect(merged).not.toBeNull()
    expect(merged.data.password).toBe('new-pass')
    expect(merged.updatedAt).toBe(5000)
    expect(merged.data.uris).toEqual([
      { uri: 'https://example.com', match: 'exact' },
      { uri: 'https://new.com', match: 'baseDomain' }
    ])
  })

  test('mergeV1IntoV2 no-ops when v1 is not later', () => {
    const v1 = makeLoginV1({ updatedAt: 2000, data: { password: 'x' } })
    const v2 = convertV1RecordToV2(
      makeLoginV1({ updatedAt: 4000, data: { password: 'y' } })
    )
    expect(mergeV1IntoV2(v1, v2)).toBeNull()
  })

  test('handles missing records and records without website fields', () => {
    expect(() => convertV1RecordToV2(null)).toThrow('record required')
    expect(convertV1RecordToV2({ id: 'note', type: 'note', data: {} })).toEqual(
      {
        id: 'note',
        type: 'note',
        schema: 2,
        data: {}
      }
    )
    expect(() => projectV2ToV1(null)).toThrow('record required')
    expect(projectV2ToV1({ id: 'empty', data: null })).toEqual({
      id: 'empty',
      data: { websites: [] }
    })
  })

  test('mergeV1IntoV2 converts without a v2 row and ignores missing v1', () => {
    const v1 = makeLoginV1()

    expect(mergeV1IntoV2(null, {})).toBeNull()
    expect(mergeV1IntoV2(v1, null)).toEqual(convertV1RecordToV2(v1))
  })

  test('checkMigrationCompleteness allows v2-only extras', () => {
    const result = checkMigrationCompleteness(
      ['a'],
      ['a', 'v2only'],
      ['record/a/file/f1'],
      ['record-v2/a/file/f1', 'record-v2/v2only/file/x']
    )
    expect(result.complete).toBe(true)
    expect(result.missingRecordIds).toEqual([])
    expect(result.missingFileKeys).toEqual([])
  })

  test('checkMigrationCompleteness names missing records and invalid file keys', () => {
    expect(
      checkMigrationCompleteness(['missing'], [], ['record/bad'], [])
    ).toEqual({
      complete: false,
      missingRecordIds: ['missing'],
      missingFileKeys: ['record/bad']
    })
  })

  test('deepEqualJson', () => {
    expect(deepEqualJson({ a: 1 }, { a: 1 })).toBe(true)
    expect(deepEqualJson({ a: 1 }, { a: 2 })).toBe(false)
  })
})

describe('migrateToSchema2', () => {
  beforeEach(() => {
    fileCopyLog = []
  })

  test('first-launch migrates records+files once and sets watermark; OTP secret on v2', async () => {
    const fileBuf = Buffer.from('attachment-bytes')
    const { store, adapter } = createMemoryVault({
      [recordKeyV1('rec1')]: makeLoginV1(),
      [fileKeyV1('rec1', 'f1')]: { value: {}, file: fileBuf }
    })

    const first = await migrateToSchema2(adapter)
    expect(first.alreadyMigrated).toBe(false)
    expect(first.complete).toBe(true)
    expect(first.recordsWritten).toBe(1)
    expect(first.filesCopied).toBe(1)
    expect(fileCopyLog).toEqual([fileKeyV2('rec1', 'f1')])

    const v2 = store.get(recordKeyV2('rec1'))?.value
    expect(v2.schema).toBe(2)
    expect(v2.data.otp.secret).toBe('JBSWY3DPEHPK3PXP')
    expect(store.get(fileKeyV2('rec1', 'f1'))?.file).toEqual(fileBuf)
    // v1 originals remain (copy, not move)
    expect(store.get(recordKeyV1('rec1'))?.value.data.otp.secret).toBe(
      'JBSWY3DPEHPK3PXP'
    )
    expect(store.get(fileKeyV1('rec1', 'f1'))?.file).toEqual(fileBuf)
    expect(store.get(VAULT_EXT_KEY)?.value.migratedToSchema).toBe(SCHEMA_V2)

    fileCopyLog = []
    const second = await migrateToSchema2(adapter)
    expect(second.alreadyMigrated).toBe(true)
    expect(second.filesCopied).toBe(0)
    expect(second.recordsWritten).toBe(0)
    expect(fileCopyLog).toEqual([])
  })

  test('second open with watermark does not recopy files', async () => {
    const fileBuf = Buffer.from('blob')
    const { adapter } = createMemoryVault({
      [VAULT_EXT_KEY]: { migratedToSchema: 2 },
      [recordKeyV1('rec1')]: makeLoginV1(),
      [recordKeyV2('rec1')]: convertV1RecordToV2(makeLoginV1()),
      [fileKeyV1('rec1', 'f1')]: { value: {}, file: fileBuf },
      [fileKeyV2('rec1', 'f1')]: { value: {}, file: fileBuf }
    })

    fileCopyLog = []
    const result = await migrateToSchema2(adapter)
    expect(result.alreadyMigrated).toBe(true)
    expect(result.filesCopied).toBe(0)
    expect(fileCopyLog).toEqual([])
  })

  test('reports n of max as each record and file is copied', async () => {
    const fileBuf = Buffer.from('attachment-bytes')
    const { adapter } = createMemoryVault({
      [recordKeyV1('rec1')]: makeLoginV1({ id: 'rec1' }),
      [recordKeyV1('rec2')]: makeLoginV1({ id: 'rec2' }),
      [fileKeyV1('rec1', 'f1')]: { value: {}, file: fileBuf }
    })

    const ticks = []
    await migrateToSchema2(adapter, {
      onProgress: (progress) => {
        ticks.push({ ...progress })
      }
    })

    expect(ticks[0]).toEqual({ done: 0, total: 3 })
    expect(ticks[ticks.length - 1]).toEqual({ done: 3, total: 3 })
    expect(ticks.map((t) => t.done)).toEqual([0, 1, 2, 3])
  })
})

describe('reconcileDualStore', () => {
  beforeEach(() => {
    fileCopyLog = []
  })

  test('later-wins merge on reconcile', async () => {
    const v2 = convertV1RecordToV2(
      makeLoginV1({ updatedAt: 1000, data: { password: 'old' } })
    )
    const v1Later = makeLoginV1({
      updatedAt: 9000,
      data: { password: 'from-v1' }
    })
    const { store, adapter } = createMemoryVault({
      [VAULT_EXT_KEY]: { migratedToSchema: 2 },
      [recordKeyV1('rec1')]: v1Later,
      [recordKeyV2('rec1')]: v2
    })

    const result = await reconcileDualStore(adapter, {
      previousV1Ids: new Set(['rec1']),
      blockV1DeleteMirror: false
    })
    expect(result.recordsWritten).toBe(1)
    expect(store.get(recordKeyV2('rec1'))?.value.data.password).toBe('from-v1')
  })

  test('delete mirror blocked when blockV1DeleteMirror is true', async () => {
    const v2 = convertV1RecordToV2(makeLoginV1())
    const { store, adapter } = createMemoryVault({
      [VAULT_EXT_KEY]: {
        migratedToSchema: 2,
        blockV1DeleteMirror: true
      },
      // v1 deleted — only v2 remains
      [recordKeyV2('rec1')]: v2,
      [fileKeyV2('rec1', 'f1')]: { value: {}, file: Buffer.from('x') }
    })

    const result = await reconcileDualStore(adapter, {
      previousV1Ids: new Set(['rec1']),
      blockV1DeleteMirror: true
    })
    expect(result.recordsDeleted).toBe(0)
    expect(store.has(recordKeyV2('rec1'))).toBe(true)
    expect(store.has(fileKeyV2('rec1', 'f1'))).toBe(true)
  })

  test('delete mirror removes v2 when flag unset and v1 id disappeared', async () => {
    const v2 = convertV1RecordToV2(makeLoginV1())
    const { store, adapter } = createMemoryVault({
      [VAULT_EXT_KEY]: { migratedToSchema: 2 },
      [recordKeyV2('rec1')]: v2,
      [fileKeyV2('rec1', 'f1')]: { value: {}, file: Buffer.from('x') }
    })

    const result = await reconcileDualStore(adapter, {
      previousV1Ids: new Set(['rec1']),
      blockV1DeleteMirror: false
    })
    expect(result.recordsDeleted).toBe(1)
    expect(store.has(recordKeyV2('rec1'))).toBe(false)
    expect(store.has(fileKeyV2('rec1', 'f1'))).toBe(false)
  })

  test('reconcile copies file only when v2 key missing', async () => {
    const fileBuf = Buffer.from('peer-file')
    const { store, adapter } = createMemoryVault({
      [VAULT_EXT_KEY]: { migratedToSchema: 2 },
      [recordKeyV1('rec1')]: makeLoginV1(),
      [recordKeyV2('rec1')]: convertV1RecordToV2(makeLoginV1()),
      [fileKeyV1('rec1', 'f2')]: { value: {}, file: fileBuf }
    })

    fileCopyLog = []
    const result = await reconcileDualStore(adapter, {
      previousV1Ids: new Set(['rec1'])
    })
    expect(result.filesCopied).toBe(1)
    expect(store.get(fileKeyV2('rec1', 'f2'))?.file).toEqual(fileBuf)

    fileCopyLog = []
    const again = await reconcileDualStore(adapter, {
      previousV1Ids: new Set(['rec1'])
    })
    expect(again.filesCopied).toBe(0)
    expect(fileCopyLog).toEqual([])
  })
})

describe('writeRecordV2AndProjectV1', () => {
  test('writes v2 with secret and projectable v1 without uris', async () => {
    const { store, adapter } = createMemoryVault({
      [recordKeyV1('rec1')]: makeLoginV1()
    })
    const updated = convertV1RecordToV2(
      makeLoginV1({
        updatedAt: 8000,
        data: {
          otp: {
            secret: 'NEWSECRETBASE32XX',
            type: 'HOTP',
            algorithm: 'SHA1',
            digits: 6,
            counter: 3
          }
        }
      })
    )
    await writeRecordV2AndProjectV1(adapter, 'rec1', updated)

    const v2 = store.get(recordKeyV2('rec1'))?.value
    const v1 = store.get(recordKeyV1('rec1'))?.value
    expect(v2.data.otp.secret).toBe('NEWSECRETBASE32XX')
    expect(v1.data.otp.secret).toBe('NEWSECRETBASE32XX')
    expect(v1.data.uris).toBeUndefined()
    expect(v1.schema).toBeUndefined()
  })

  test('does not rewrite an already projected v2 and v1 pair', async () => {
    const v2 = convertV1RecordToV2(makeLoginV1())
    const { adapter } = createMemoryVault({
      [recordKeyV1('rec1')]: projectV2ToV1(v2),
      [recordKeyV2('rec1')]: v2
    })
    const addJson = jest.spyOn(adapter, 'addJson')

    await writeRecordV2AndProjectV1(adapter, 'rec1', v2)

    expect(addJson).not.toHaveBeenCalled()
  })
})

describe('getRawRecordPreferV2', () => {
  test('returns the v2 row when both namespaces have a record', async () => {
    const v2 = convertV1RecordToV2(makeLoginV1())
    v2.data.uris = [{ uri: 'https://example.com', match: 'exact' }]
    const { adapter } = createMemoryVault({
      [recordKeyV1('rec1')]: makeLoginV1(),
      [recordKeyV2('rec1')]: v2
    })

    const found = await getRawRecordPreferV2(adapter, 'rec1')
    expect(found.schema).toBe(2)
    expect(found.record.data.uris).toEqual([
      { uri: 'https://example.com', match: 'exact' }
    ])
  })

  test('returns the v2 row when v1 has been deleted', async () => {
    const v2 = convertV1RecordToV2(makeLoginV1())
    const { adapter } = createMemoryVault({
      [recordKeyV2('rec1')]: v2
    })

    const found = await getRawRecordPreferV2(adapter, 'rec1')
    expect(found.schema).toBe(2)
    expect(found.record).toBe(v2)
  })

  test('falls back to v1 when v2 is missing', async () => {
    const v1 = makeLoginV1()
    const { adapter } = createMemoryVault({
      [recordKeyV1('rec1')]: v1
    })

    const found = await getRawRecordPreferV2(adapter, 'rec1')
    expect(found.schema).toBe(1)
    expect(found.record).toBe(v1)
  })

  test('returns null when neither namespace has a row', async () => {
    const { adapter } = createMemoryVault()
    expect(await getRawRecordPreferV2(adapter, 'missing')).toBeNull()
  })
})
