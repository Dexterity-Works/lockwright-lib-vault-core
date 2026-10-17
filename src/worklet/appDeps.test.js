// bare-fs uses `using` declarations Jest's parser can't handle; stub the
// methods appDeps.js actually calls (mkdir, sync helpers, promises.mkdir).
jest.mock('bare-fs', () => ({
  __esModule: true,
  default: {
    mkdirSync: jest.fn(),
    readFileSync: jest.fn(),
    writeFileSync: jest.fn(),
    renameSync: jest.fn(),
    promises: {
      mkdir: jest.fn().mockResolvedValue(undefined),
      rm: jest.fn().mockResolvedValue(undefined)
    }
  }
}))

jest.mock('bare-crypto', () => ({
  randomBytes: (n) => Buffer.alloc(n),
  createCipheriv: () => ({
    update: (data) => data,
    final: () => Buffer.alloc(0),
    getAuthTag: () => Buffer.alloc(16)
  }),
  createDecipheriv: () => ({
    update: (data) => data,
    final: () => Buffer.alloc(0),
    setAuthTag: jest.fn()
  })
}))

function mockMakeKeyPairFromSeed(seed) {
  const publicKey = Buffer.alloc(mockSodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = Buffer.alloc(mockSodium.crypto_sign_SECRETKEYBYTES)
  mockSodium.crypto_sign_seed_keypair(publicKey, secretKey, seed)
  return { publicKey, secretKey }
}

jest.mock('autopass', () => {
  const mockPair = {
    finished: jest.fn().mockResolvedValue({
      ready: jest.fn().mockResolvedValue(),
      close: jest.fn().mockResolvedValue(),
      add: jest.fn().mockResolvedValue(),
      remove: jest.fn().mockResolvedValue(),
      get: jest.fn().mockResolvedValue({
        value: JSON.stringify({ id: 'vault-id' }),
        file: Buffer.from('test file content')
      }),
      createInvite: jest.fn().mockResolvedValue('invite-code'),
      encryptionKey: {
        toString: jest.fn().mockReturnValue('encryption-key')
      },
      list: jest.fn().mockResolvedValue({
        on: (event, callback) => {
          if (event === 'data') {
            callback({ key: 'test1', value: 1 })
            callback({ key: 'filter_test', value: 2 })
            callback({ key: 'test2', value: 3 })
          }
          if (event === 'end') {
            callback()
          }
        }
      }),
      removeAllListeners: jest.fn(),
      on: jest.fn(),
      core: {
        ready: jest.fn().mockResolvedValue()
      }
    })
  }

  const mockAutopassUpdate = jest.fn().mockResolvedValue()
  globalThis.__mockAutopassUpdate = mockAutopassUpdate

  // A real EventEmitter, so 'update' reaches every listener the code adds.
  const { EventEmitter } = jest.requireActual('events')
  const mockAutopass = jest.fn().mockImplementation(() =>
    Object.assign(new EventEmitter(), {
      ready: jest.fn().mockResolvedValue(),
      close: jest.fn().mockResolvedValue(),
      suspend: jest.fn().mockResolvedValue(),
      resume: jest.fn().mockResolvedValue(),
      add: jest.fn().mockResolvedValue(),
      remove: jest.fn().mockResolvedValue(),
      removeWriter: jest.fn().mockResolvedValue(),
      get: jest.fn().mockResolvedValue({
        value: JSON.stringify({ id: 'vault-id' }),
        file: Buffer.from('test file content')
      }),
      createInvite: jest.fn().mockResolvedValue('invite-code'),
      deleteInvite: jest.fn().mockResolvedValue(),
      encryptionKey: {
        toString: jest.fn().mockReturnValue('encryption-key')
      },
      list: jest.fn().mockResolvedValue({
        on: (event, callback) => {
          if (event === 'data') {
            callback({ key: 'test1', value: 1 })
            callback({ key: 'filter_test', value: 2 })
            callback({ key: 'test2', value: 3 })
          }
          if (event === 'end') {
            callback()
          }
        }
      }),
      pairInstance: jest.fn().mockResolvedValue(),
      core: {
        ready: jest.fn().mockResolvedValue()
      },
      base: {
        update: (...args) => globalThis.__mockAutopassUpdate(...args),
        view: {
          flush: jest.fn().mockResolvedValue(),
          find: jest.fn().mockReturnValue({
            async *[Symbol.asyncIterator]() {}
          })
        },
        local: {
          keyPair: mockMakeKeyPairFromSeed(Buffer.alloc(32, 0x11)),
          userData: new Map(),
          async getUserData(key) {
            return this.userData.get(key) ?? null
          },
          async setUserData(key, value) {
            this.userData.set(key, value)
          }
        }
      },
      store: {
        createKeyPair: jest.fn(async (name) => {
          const seed = Buffer.alloc(32)
          Buffer.from(`mock-store:${name}`).copy(seed)
          return mockMakeKeyPairFromSeed(seed)
        })
      },
      writerKey: Buffer.from(
        'aabbccddeeff0011223344556677889900aabbccddeeff00112233445566778899',
        'hex'
      ),
      getMirror: jest.fn().mockResolvedValue([]),
      addMirror: jest.fn().mockResolvedValue(),
      removeMirror: jest.fn().mockResolvedValue()
    })
  )

  mockAutopass.pair = jest.fn().mockReturnValue(mockPair)

  return mockAutopass
})

jest.mock('corestore', () =>
  jest.fn().mockImplementation(() => ({
    ready: jest.fn().mockResolvedValue(),
    close: jest.fn().mockResolvedValue(),
    add: jest.fn().mockResolvedValue(),
    remove: jest.fn().mockResolvedValue(),
    get: jest.fn().mockResolvedValue({ id: 'vault-id' }),
    pairInstance: jest.fn().mockResolvedValue(),
    list: jest.fn().mockResolvedValue({
      on: (event, callback) => {
        if (event === 'data') {
          callback({ key: 'test1', value: 1 })
          callback({ key: 'other', value: 2 })
          callback({ key: 'test2', value: 3 })
        }
        if (event === 'end') {
          callback()
        }
      }
    })
  }))
)

jest.mock('bare-rpc', () =>
  jest.fn().mockImplementation(() => ({
    request: jest.fn().mockReturnValue({
      send: jest.fn().mockResolvedValue(),
      reply: jest.fn().mockResolvedValue('{}')
    })
  }))
)

jest.mock('bare-path', () => ({
  sep: '/', // Unix path separator for tests
  join: (...args) => args.join('/'),
  normalize: (path) => {
    // Simple normalization: remove trailing slashes and redundant slashes
    const result = path.replace(/\/+/g, '/').replace(/\/$/, '') || '/'
    // Handle .. for normalization
    const parts = result.split('/')
    const normalized = []
    for (const part of parts) {
      if (part === '..') {
        normalized.pop()
      } else if (part !== '.' && part !== '') {
        normalized.push(part)
      }
    }
    return '/' + normalized.join('/')
  },
  resolve: (...paths) => {
    // Simple resolve: join paths and make absolute, handle ..
    let joined = paths.join('/').replace(/\/+/g, '/')
    if (!joined.startsWith('/')) {
      joined = '/' + joined
    }
    // Handle .. for resolution
    const parts = joined.split('/')
    const resolved = []
    for (const part of parts) {
      if (part === '..') {
        resolved.pop()
      } else if (part !== '.' && part !== '') {
        resolved.push(part)
      }
    }
    return '/' + resolved.join('/')
  }
}))

jest.mock(
  '@tetherto/swarmconf',
  () =>
    jest.fn().mockImplementation(() => ({
      ready: jest.fn().mockResolvedValue(),
      current: {
        blindRelays: []
      }
    })),
  { virtual: true }
)

// blind-encryption-sodium pulls sodium-universal native bindings; stub it.
jest.mock('blind-encryption-sodium', () =>
  jest.fn().mockImplementation(() => ({}))
)

jest.mock('./utils/isPearWorker', () => ({
  isPearWorker: jest.fn().mockReturnValue(false)
}))

jest.mock('./validateAndSanitizePath', () => ({
  validateAndSanitizePath: jest.fn().mockImplementation((path) => path)
}))

jest.mock('./getForbiddenRoots', () => ({
  getForbiddenRoots: jest.fn().mockReturnValue(['/etc', '/bin', '/tmp', '/var'])
}))

jest.mock('./utils/workletLogger', () => ({
  workletLogger: {
    log: jest.fn(),
    debug: jest.fn(),
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    configure: jest.fn()
  },
  WorkletLogger: jest.fn()
}))

// Mock Bare global for platform detection
global.Bare = {
  platform: 'posix' // Unix-like for tests
}

import bareFs from 'bare-fs'

import * as appDeps from './appDeps'
import { buildEpochRecord, generateEpochId } from './epoch/epochRecord'
import { generateEpochKey, sealRing } from './epoch/keyring'

const mockSodium = require('sodium-native')

// In-memory records behind the mocked active vault: add/get/remove and a
// HyperDB-style range find, so the real epoch store runs over it.
const useMemoryVault = (instance) => {
  const rows = new Map()
  const inRange = (key, { gte, gt, lte, lt } = {}) =>
    (!gte || key >= gte.key) &&
    (!gt || key > gt.key) &&
    (!lte || key <= lte.key) &&
    (!lt || key < lt.key)
  instance.add = jest.fn(async (key, value, file) => {
    rows.set(key, { key, value, file: file ?? null })
  })
  instance.get = jest.fn(async (key) => {
    const row = rows.get(key)
    return row ? { value: row.value, file: row.file } : null
  })
  instance.remove = jest.fn(async (key) => {
    rows.delete(key)
  })
  instance.base.view.find = jest.fn((_, range) => ({
    async *[Symbol.asyncIterator]() {
      for (const key of [...rows.keys()].sort()) {
        if (inRange(key, range)) yield rows.get(key)
      }
    }
  }))
  instance.base.writable = true
  const put = (key, value) => rows.set(key, { key, value, file: null })
  return { rows, put }
}

const makeSignKeyPair = () => {
  const publicKey = Buffer.alloc(mockSodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = Buffer.alloc(mockSodium.crypto_sign_SECRETKEYBYTES)
  mockSodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

const deviceRow = (id, keyPair) =>
  JSON.stringify({ id, masterTopic: keyPair.publicKey.toString('hex') })

const waitFor = async (check) => {
  for (let i = 0; i < 200 && !check(); i++) {
    await new Promise((resolve) => setTimeout(resolve, 10))
  }
  expect(check()).toBe(true)
}

describe('appDeps module functions (excluding encryption)', () => {
  beforeEach(async () => {
    jest.resetModules()
  })

  describe('setStoragePath and buildPath', () => {
    test('buildPath should throw if STORAGE_PATH is not set', async () => {
      expect(() => appDeps.buildPath('vault/test')).toThrow(
        'Storage path not set'
      )
    })

    test('buildPath returns expected path after setStoragePath', async () => {
      await appDeps.setStoragePath('/home/user/data')
      const result = appDeps.buildPath('vault/test')
      expect(result).toBe('/home/user/data/vault/test')
    })

    test('setStoragePath should reject paths to restricted system directories', async () => {
      await expect(appDeps.setStoragePath('/etc')).rejects.toThrow(
        'Storage path points to a restricted system directory'
      )
      await expect(appDeps.setStoragePath('/etc/config')).rejects.toThrow(
        'Storage path points to a restricted system directory'
      )
      await expect(appDeps.setStoragePath('/bin/sh')).rejects.toThrow(
        'Storage path points to a restricted system directory'
      )
      // /tmp is inappropriate for permanent vault storage (files deleted on reboot)
      await expect(appDeps.setStoragePath('/tmp')).rejects.toThrow(
        'Storage path points to a restricted system directory'
      )
      await expect(appDeps.setStoragePath('/tmp/vaults')).rejects.toThrow(
        'Storage path points to a restricted system directory'
      )
      // /var is a system directory with critical subdirectories
      await expect(appDeps.setStoragePath('/var')).rejects.toThrow(
        'Storage path points to a restricted system directory'
      )
      await expect(appDeps.setStoragePath('/var/data')).rejects.toThrow(
        'Storage path points to a restricted system directory'
      )
    })

    test('buildPath should prevent path traversal outside storage root', async () => {
      await appDeps.setStoragePath('/home/user/data')
      // This should throw because the resolved path would escape the storage root
      expect(() => appDeps.buildPath('../../../etc/passwd')).toThrow(
        'Resolved path escapes storage root'
      )
    })

    test('buildPath should allow normal subdirectories', async () => {
      await appDeps.setStoragePath('/home/user/data')
      const result = appDeps.buildPath('vault/subfolder/file')
      expect(result).toBe('/home/user/data/vault/subfolder/file')
    })
  })

  describe('State getters', () => {
    test('initially vaults, encryption, and active vault are not initialized', () => {
      expect(appDeps.getIsVaultsInitialized()).toBe(false)
      expect(appDeps.getIsEncryptionInitialized()).toBe(false)
      expect(appDeps.getIsActiveVaultInitialized()).toBe(false)
    })
  })

  describe('Vaults initialization and closing', () => {
    afterEach(async () => {
      await appDeps.closeAllInstances()
    })

    test('masterVaultInit sets vaultsInitialized to true', async () => {
      await appDeps.setStoragePath('/home/testuser/vaultdata')
      await appDeps.masterVaultInit({
        encryptionKey: 'key',
        hashedPassword: 'pw'
      })
      expect(appDeps.getIsVaultsInitialized()).toBe(true)
    })

    test('closeVaultsInstance resets vaultsInitialized to false', async () => {
      await appDeps.setStoragePath('/home/testuser/vaultdata')
      await appDeps.masterVaultInit({
        encryptionKey: 'key',
        hashedPassword: 'pw'
      })
      expect(appDeps.getIsVaultsInitialized()).toBe(true)
      await appDeps.closeVaultsInstance()
      expect(appDeps.getIsVaultsInitialized()).toBe(false)
    })
  })

  describe('Active vault functions', () => {
    beforeEach(async () => {
      globalThis.__mockAutopassUpdate.mockReset()
      globalThis.__mockAutopassUpdate.mockResolvedValue()
      // initActiveVaultInstance calls getHashedPassword → vaultsGet,
      // so vaults must be initialized first.
      await appDeps.setStoragePath('/home/testuser/vaultdata')
      await appDeps.masterVaultInit({
        encryptionKey: 'key',
        hashedPassword: 'pw'
      })
    })

    afterEach(async () => {
      await appDeps.closeAllInstances()
    })

    test('initActiveVaultInstance sets active vault as initialized', async () => {
      await appDeps.initActiveVaultInstance({
        id: 'vault1',
        encryptionKey: 'key'
      })
      expect(appDeps.getIsActiveVaultInitialized()).toBe(true)
    })

    test('initActiveVaultInstance returns while Autobase update is still pending', async () => {
      expect(appDeps.getIsActiveVaultInitialized()).toBe(false)
      globalThis.__mockAutopassUpdate.mockReturnValue(new Promise(() => {}))

      const opened = appDeps.initActiveVaultInstance({
        id: 'vault1',
        encryptionKey: 'key'
      })
      const blocked = new Promise((_, reject) => {
        setTimeout(() => reject(new Error('blocked on Autobase update')), 200)
      })
      await Promise.race([opened, blocked])
      expect(appDeps.getIsActiveVaultInitialized()).toBe(true)
    })

    test('closeActiveVaultInstance resets active vault initialization', async () => {
      await appDeps.initActiveVaultInstance({
        id: 'vault1',
        encryptionKey: 'key'
      })
      expect(appDeps.getIsActiveVaultInitialized()).toBe(true)
      await appDeps.closeActiveVaultInstance()
      expect(appDeps.getIsActiveVaultInitialized()).toBe(false)
    })

    test('activeVaultAdd calls add on activeVaultInstance', async () => {
      await appDeps.initActiveVaultInstance({
        id: 'vault1',
        encryptionKey: 'key'
      })

      const mockInstance = appDeps.getActiveVaultInstance()
      mockInstance.add = jest.fn().mockResolvedValue()

      await appDeps.activeVaultAdd('key1', { data: 'test' })
      expect(mockInstance.add).toHaveBeenCalledWith(
        'key1',
        JSON.stringify({ data: 'test' }),
        undefined
      )
    })

    test('vaultsGet calls get on vaultsInstance and returns result', async () => {
      const result = await appDeps.vaultsGet('key4')
      expect(result.id).toEqual('vault-id')
      expect(result.file).toEqual(Buffer.from('test file content'))
    })

    test('vaultsAdd calls add on vaultsInstance', async () => {
      const mockInstance = appDeps.getVaultsInstance()
      mockInstance.add = jest.fn().mockResolvedValue()

      await appDeps.vaultsAdd('key2', { data: 'test' })
      expect(mockInstance.add).toHaveBeenCalledWith(
        'key2',
        JSON.stringify({ data: 'test' })
      )
    })

    test('removeVault throws when vaultId is missing', async () => {
      await expect(appDeps.removeVault()).rejects.toThrow('vaultId is required')
    })

    test('removeVault drops the master entry and wipes disk for an inactive vault', async () => {
      bareFs.promises.rm.mockClear()

      const mockInstance = appDeps.getVaultsInstance()
      mockInstance.remove = jest.fn().mockResolvedValue()

      await appDeps.removeVault('vault-x')

      expect(mockInstance.remove).toHaveBeenCalledWith('vault/vault-x')
      expect(bareFs.promises.rm).toHaveBeenCalledWith(
        expect.stringContaining('vault/vault-x'),
        { recursive: true, force: true }
      )
    })

    test('removeVault closes the active instance first when it owns the vault', async () => {
      bareFs.promises.rm.mockClear()

      await appDeps.initActiveVaultInstance({
        id: 'vault1',
        encryptionKey: 'key'
      })
      expect(appDeps.getIsActiveVaultInitialized()).toBe(true)

      const vaultsInstance = appDeps.getVaultsInstance()
      vaultsInstance.remove = jest.fn().mockResolvedValue()

      await appDeps.removeVault('vault1')

      expect(appDeps.getIsActiveVaultInitialized()).toBe(false)
      expect(vaultsInstance.remove).toHaveBeenCalledWith('vault/vault1')
      expect(bareFs.promises.rm).toHaveBeenCalledWith(
        expect.stringContaining('vault/vault1'),
        { recursive: true, force: true }
      )
    })

    test('vaultRemove calls remove on activeVaultInstance', async () => {
      await appDeps.initActiveVaultInstance({
        id: 'vault1',
        encryptionKey: 'key'
      })

      const mockInstance = appDeps.getActiveVaultInstance()
      mockInstance.remove = jest.fn().mockResolvedValue()

      await appDeps.vaultRemove('key3')
      expect(mockInstance.remove).toHaveBeenCalledWith('key3')
    })

    test('vaultRemoveWriter calls removeWriter with the hex key decoded to bytes', async () => {
      await appDeps.initActiveVaultInstance({
        id: 'vault1',
        encryptionKey: 'key'
      })

      const mockInstance = appDeps.getActiveVaultInstance()
      mockInstance.removeWriter = jest.fn().mockResolvedValue()

      await appDeps.vaultRemoveWriter('abc123')

      const calledWith = mockInstance.removeWriter.mock.calls[0][0]
      expect(Buffer.isBuffer(calledWith)).toBe(true)
      expect(Buffer.compare(calledWith, Buffer.from('abc123', 'hex'))).toBe(0)
    })

    test('vaultRemoveWriter throws when writerKey is missing', async () => {
      await appDeps.initActiveVaultInstance({
        id: 'vault1',
        encryptionKey: 'key'
      })

      await expect(appDeps.vaultRemoveWriter()).rejects.toThrow(
        'writerKey is required'
      )
    })

    test('signMessage uses the personal-identity keypair, not the autobase writer keypair', async () => {
      // Regression guard: if this flips, signMessage is back to being a
      // hypercore block-signature oracle.
      const sodium = require('sodium-native')

      const message = Buffer.from('arbitrary attacker-supplied bytes', 'utf-8')
      const messageHex = message.toString('hex')

      const signatureHex = await appDeps.signMessage(messageHex)
      const signature = Buffer.from(signatureHex, 'hex')

      const { publicKey: personalPub } = await appDeps.getPersonalKeyPair()
      const writerPub = appDeps.getVaultsInstance().base.local.keyPair.publicKey

      expect(Buffer.compare(personalPub, writerPub)).not.toBe(0)
      expect(
        sodium.crypto_sign_verify_detached(signature, message, personalPub)
      ).toBe(true)
      expect(
        sodium.crypto_sign_verify_detached(signature, message, writerPub)
      ).toBe(false)
    })

    test('activeVaultGet calls get on activeVaultInstance and returns result', async () => {
      await appDeps.initActiveVaultInstance({
        id: 'vault1',
        encryptionKey: 'key'
      })
      const result = await appDeps.activeVaultGet('key4')
      expect(result.id).toEqual('vault-id')
      expect(result.file).toEqual(Buffer.from('test file content'))
    })

    test('createInvite returns correct invite string', async () => {
      await appDeps.initActiveVaultInstance({
        id: 'vault1',
        encryptionKey: 'key'
      })
      const result = await appDeps.createInvite()
      expect(result).toBe('vault-id/invite-code')
    })
  })

  describe('List functions (vaultsList and activeVaultList)', () => {
    beforeEach(async () => {
      await appDeps.setStoragePath('/home/testuser/vaultdata')
      await appDeps.masterVaultInit({
        encryptionKey: 'key',
        hashedPassword: 'pw'
      })
    })

    afterEach(async () => {
      await appDeps.closeAllInstances()
    })

    // The autopass mock's list emits keys ['test1', 'filter_test', 'test2']
    // with values [1, 2, 3]. Filtering by 'test' matches the keys that
    // start with 'test' → values 1 and 3.
    test('vaultsList returns filtered values based on filterKey', async () => {
      const result = await appDeps.vaultsList('test')
      expect(result).toEqual([1, 3])
    })

    test('activeVaultList returns filtered values based on filterKey', async () => {
      await appDeps.initActiveVaultInstance({
        id: 'vault1',
        encryptionKey: 'key'
      })
      const { put } = useMemoryVault(appDeps.getActiveVaultInstance())
      put('test1', '1')
      put('filter_test', '2')
      put('test2', '3')
      const result = await appDeps.activeVaultList('test')
      expect(result).toEqual([1, 3])
    })
  })

  describe('exportOtpRecords', () => {
    afterEach(async () => {
      await appDeps.closeAllInstances()
    })

    test('throws if vault not initialised', async () => {
      await expect(appDeps.exportOtpRecords()).rejects.toThrow(
        'Vault not initialised'
      )
    })
  })

  describe('activeVaultGetWriterKey', () => {
    afterEach(async () => {
      await appDeps.closeAllInstances()
    })

    test('throws if vault not initialised', () => {
      expect(() => appDeps.activeVaultGetWriterKey()).toThrow(
        'Vault not initialised'
      )
    })

    test('returns the writer key as a hex string', async () => {
      await appDeps.setStoragePath('/home/testuser/vaultdata')
      await appDeps.masterVaultInit({
        encryptionKey: 'key',
        hashedPassword: 'pw'
      })
      await appDeps.initActiveVaultInstance({
        id: 'vault1',
        encryptionKey: 'key'
      })

      const result = appDeps.activeVaultGetWriterKey()

      expect(typeof result).toBe('string')
      expect(result).toMatch(/^[0-9a-f]+$/)
    })
  })

  describe('activeVaultFind', () => {
    const initVault = async () => {
      await appDeps.setStoragePath('/home/testuser/vaultdata')
      await appDeps.masterVaultInit({
        encryptionKey: 'key',
        hashedPassword: 'pw'
      })
      await appDeps.initActiveVaultInstance({
        id: 'vault1',
        encryptionKey: 'key'
      })
    }

    afterEach(async () => {
      await appDeps.closeAllInstances()
    })

    test('throws if vault not initialised', async () => {
      await expect(
        appDeps.activeVaultFind({ gte: { key: 'a' }, lt: { key: 'b' } })
      ).rejects.toThrow('Vault not initialised')
    })

    test('forwards range bounds to view.find and returns parsed { key, value } pairs', async () => {
      await initVault()
      const instance = appDeps.getActiveVaultInstance()

      instance.base.view.find.mockReturnValue({
        async *[Symbol.asyncIterator]() {
          yield {
            key: 'actions/queue/AAA/1',
            value: JSON.stringify({ type: 'x' })
          }
          yield {
            key: 'actions/queue/AAA/2',
            value: JSON.stringify({ type: 'y' })
          }
        }
      })

      const result = await appDeps.activeVaultFind({
        gte: { key: 'actions/queue/AAA/' },
        lt: { key: 'actions/queue/AAA0' },
        limit: 50,
        reverse: false
      })

      expect(instance.base.view.find).toHaveBeenCalledWith(
        '@autopass/records',
        {
          gte: { key: 'actions/queue/AAA/' },
          lte: undefined,
          gt: undefined,
          lt: { key: 'actions/queue/AAA0' },
          // The epoch store applies the limit to readable rows itself.
          reverse: false
        }
      )
      expect(result).toEqual([
        { key: 'actions/queue/AAA/1', value: { type: 'x' } },
        { key: 'actions/queue/AAA/2', value: { type: 'y' } }
      ])
    })

    test('skips entries with empty value', async () => {
      await initVault()
      const instance = appDeps.getActiveVaultInstance()

      instance.base.view.find.mockReturnValue({
        async *[Symbol.asyncIterator]() {
          yield { key: 'a', value: JSON.stringify({ ok: true }) }
          yield { key: 'b', value: null }
          yield { key: 'c', value: undefined }
        }
      })

      const result = await appDeps.activeVaultFind({
        gte: { key: 'a' },
        lt: { key: 'z' }
      })

      expect(result).toEqual([{ key: 'a', value: { ok: true } }])
    })

    test('returns empty array when no records match', async () => {
      await initVault()
      const result = await appDeps.activeVaultFind({
        gte: { key: 'nope/' },
        lt: { key: 'nope0' }
      })
      expect(result).toEqual([])
    })
  })

  describe('Pairing functions', () => {
    afterEach(async () => {
      await appDeps.closeAllInstances()
    })

    test('pair calls pair with invite code and returns vault id', async () => {
      await appDeps.setStoragePath('/home/testuser/vaultdata')
      await appDeps.masterVaultInit({
        encryptionKey: 'key',
        hashedPassword: 'pw'
      })
      // PearPassPairer.pairInstance reads hashedPassword via vaultsGet.
      const vaultsInst = appDeps.getVaultsInstance()
      vaultsInst.get = jest.fn().mockResolvedValue({
        value: JSON.stringify({ hashedPassword: 'hashed-pw' })
      })

      const { vaultId, encryptionKey } = await appDeps.pairActiveVault(
        'vault-id/invite-code'
      )
      expect(vaultId).toBe('vault-id')
      expect(encryptionKey).toBe('encryption-key')
    })
  })

  describe('Blind mirrors management', () => {
    beforeEach(async () => {
      await appDeps.setStoragePath('/home/testuser/vaultdata')
      await appDeps.masterVaultInit({
        encryptionKey: 'key',
        hashedPassword: 'pw'
      })
      await appDeps.initActiveVaultInstance({
        id: 'vault1',
        encryptionKey: 'key'
      })

      const inst = appDeps.getActiveVaultInstance()
      inst.getMirror = jest.fn().mockResolvedValue([{ key: 'a' }, { key: 'b' }])
      inst.addMirror = jest.fn().mockResolvedValue()
      inst.removeMirror = jest.fn().mockResolvedValue()
    })

    afterEach(async () => {
      await appDeps.closeAllInstances()
    })

    test('getBlindMirrors returns mirrors from instance', async () => {
      const res = await appDeps.getBlindMirrors()
      expect(res).toEqual([
        { key: 'a', isDefault: false },
        { key: 'b', isDefault: false }
      ])
    })

    test('addBlindMirrors adds provided keys', async () => {
      const inst = appDeps.getActiveVaultInstance()
      await appDeps.addBlindMirrors(['k1', 'k2'])
      expect(inst.addMirror).toHaveBeenCalledWith('k1')
      expect(inst.addMirror).toHaveBeenCalledWith('k2')
    })

    test('removeBlindMirror removes key', async () => {
      const inst = appDeps.getActiveVaultInstance()
      await appDeps.removeBlindMirror('k1')
      expect(inst.removeMirror).toHaveBeenCalledWith('k1')
    })

    test('addDefaultBlindMirrors adds defaults', async () => {
      const inst = appDeps.getActiveVaultInstance()
      await appDeps.addDefaultBlindMirrors()
      expect(inst.addMirror).toHaveBeenCalled()
    })

    test('removeAllBlindMirrors removes all current mirrors', async () => {
      const inst = appDeps.getActiveVaultInstance()
      inst.getMirror = jest
        .fn()
        .mockResolvedValue([{ key: 'a' }, { key: 'b' }, { key: 'c' }])

      await appDeps.removeAllBlindMirrors()
      expect(inst.removeMirror).toHaveBeenCalledWith('a')
      expect(inst.removeMirror).toHaveBeenCalledWith('b')
      expect(inst.removeMirror).toHaveBeenCalledWith('c')
    })
  })

  describe('restartActiveVault', () => {
    afterEach(async () => {
      await appDeps.closeAllInstances()
    })

    test('restarts instance when same vault is active', async () => {
      await appDeps.setStoragePath('/home/testuser/vaultdata')
      await appDeps.masterVaultInit({
        encryptionKey: 'key',
        hashedPassword: 'pw'
      })
      await appDeps.initActiveVaultInstance({
        id: 'vaultX',
        encryptionKey: 'encKey'
      })

      const onUpdate = jest.fn()
      await appDeps.initListener({ vaultId: 'vaultX', onUpdate })

      await appDeps.restartActiveVault()
      expect(appDeps.getIsActiveVaultInitialized()).toBe(true)
    })

    test('throws if no previous vault to restart', async () => {
      await appDeps.setStoragePath('/home/testuser/vaultdata')
      await appDeps.closeAllInstances()
      await expect(appDeps.restartActiveVault()).rejects.toThrow(
        '[restartActiveVault]: No previous active vault to restart'
      )
    })
  })
  describe('initListener', () => {
    afterEach(async () => {
      await appDeps.closeAllInstances()
    })

    test('initListener should not reinitialize if vaultId matches previous value', async () => {
      await appDeps.setStoragePath('/home/testuser/vaultdata')
      await appDeps.masterVaultInit({
        encryptionKey: 'key',
        hashedPassword: 'pw'
      })
      await appDeps.initActiveVaultInstance({
        id: 'vault1',
        encryptionKey: 'key'
      })

      const active = appDeps.getActiveVaultInstance()
      const removeAllListenersSpy = jest.spyOn(active, 'removeAllListeners')

      const onUpdate = jest.fn()
      await appDeps.initListener({ vaultId: 'vault1', onUpdate })

      removeAllListenersSpy.mockClear()

      await appDeps.initListener({ vaultId: 'vault1', onUpdate })
      expect(removeAllListenersSpy).not.toHaveBeenCalled()
    })
  })

  describe('closeAllInstances', () => {
    test('closeAllInstances closes all initialized instances and clears restart cache', async () => {
      await appDeps.setStoragePath('/home/testuser/vaultdata')
      await appDeps.masterVaultInit({
        encryptionKey: 'key',
        hashedPassword: 'pw'
      })
      await appDeps.initActiveVaultInstance({
        id: 'vault1',
        encryptionKey: 'key'
      })
      await appDeps.encryptionInit()

      const activeVault = appDeps.getActiveVaultInstance()
      const vaults = appDeps.getVaultsInstance()
      const encryption = appDeps.getEncryptionInstance()

      const closeSpy1 = jest.spyOn(activeVault, 'close')
      const closeSpy2 = jest.spyOn(vaults, 'close')
      const closeSpy3 = jest.spyOn(encryption, 'close')

      await appDeps.closeAllInstances()

      expect(closeSpy1).toHaveBeenCalled()
      expect(closeSpy2).toHaveBeenCalled()
      expect(closeSpy3).toHaveBeenCalled()

      expect(appDeps.getIsActiveVaultInitialized()).toBe(false)
      expect(appDeps.getIsVaultsInitialized()).toBe(false)
      expect(appDeps.getIsEncryptionInitialized()).toBe(false)

      await expect(appDeps.restartActiveVault()).rejects.toThrow(
        '[restartActiveVault]: No previous active vault to restart'
      )
    })
  })

  describe('suspendAllInstances/resumeAllInstances', () => {
    afterEach(async () => {
      await appDeps.closeAllInstances()
    })

    test('suspendAllInstances calls suspend on all instances', async () => {
      await appDeps.setStoragePath('/home/testuser/vaultdata')
      await appDeps.masterVaultInit({
        encryptionKey: 'key',
        hashedPassword: 'pw'
      })
      await appDeps.initActiveVaultInstance({
        id: 'vault1',
        encryptionKey: 'key'
      })
      await appDeps.encryptionInit()

      const activeVault = appDeps.getActiveVaultInstance()
      const vaults = appDeps.getVaultsInstance()
      const encryption = appDeps.getEncryptionInstance()

      await appDeps.suspendAllInstances()

      expect(activeVault.suspend).toHaveBeenCalled()
      expect(vaults.suspend).toHaveBeenCalled()
      expect(encryption.suspend).toHaveBeenCalled()
    })

    test('resumeAllInstances calls resume on all instances', async () => {
      await appDeps.setStoragePath('/home/testuser/vaultdata')
      await appDeps.masterVaultInit({
        encryptionKey: 'key',
        hashedPassword: 'pw'
      })
      await appDeps.initActiveVaultInstance({
        id: 'vault1',
        encryptionKey: 'key'
      })
      await appDeps.encryptionInit()

      const activeVault = appDeps.getActiveVaultInstance()
      const vaults = appDeps.getVaultsInstance()
      const encryption = appDeps.getEncryptionInstance()

      await appDeps.resumeAllInstances()

      expect(activeVault.resume).toHaveBeenCalled()
      expect(vaults.resume).toHaveBeenCalled()
      expect(encryption.resume).toHaveBeenCalled()
    })
  })

  describe('enrichRecordForClient', () => {
    const totpLogin = () => ({
      id: 'rec-1',
      type: 'login',
      data: {
        title: 'GitHub',
        otp: {
          type: 'TOTP',
          secret: 'JBSWY3DPEHPK3PXP',
          digits: 6,
          period: 30,
          issuer: 'GitHub',
          label: 'user'
        }
      }
    })

    test('default list still attaches a current TOTP code', () => {
      const enriched = appDeps.enrichRecordForClient(totpLogin())
      expect(enriched.data.otp).toBeUndefined()
      expect(enriched.otpPublic.type).toBe('TOTP')
      expect(enriched.otpPublic.currentCode).toMatch(/^\d{6}$/)
    })

    test('includeOtpCodes false strips the secret and skips code generation', () => {
      const enriched = appDeps.enrichRecordForClient(totpLogin(), {
        includeOtpCodes: false
      })
      expect(enriched.data.otp).toBeUndefined()
      expect(enriched.otpPublic.type).toBe('TOTP')
      expect(enriched.otpPublic).not.toHaveProperty('currentCode')
      expect(enriched.otpPublic).not.toHaveProperty('timeRemaining')
    })
  })
  describe('Active vault epoch store', () => {
    let me
    let vault

    beforeEach(async () => {
      await appDeps.setStoragePath('/home/testuser/vaultdata')
      await appDeps.masterVaultInit({
        encryptionKey: 'key',
        hashedPassword: 'pw'
      })
      await appDeps.initActiveVaultInstance({
        id: 'vault1',
        encryptionKey: 'key'
      })
      me = await appDeps.getPersonalKeyPair()
      vault = useMemoryVault(appDeps.getActiveVaultInstance())
      vault.put('device/me', deviceRow('me', me))
    })

    afterEach(async () => {
      appDeps.setEpochStatusListener(null)
      await appDeps.closeAllInstances()
    })

    // Attach the app's update listener; the returned function emits one
    // update and waits until its reconcile and epoch sync ran.
    const listen = async () => {
      const instance = appDeps.getActiveVaultInstance()
      const onUpdate = jest.fn()
      await appDeps.initListener({ vaultId: 'vault1', onUpdate })
      return async () => {
        const before = onUpdate.mock.calls.length
        instance.emit('update')
        await waitFor(() => onUpdate.mock.calls.length > before)
        await new Promise((resolve) => setTimeout(resolve, 50))
      }
    }

    // A rostered device `other` writes epoch `seq` sealed to itself only.
    const putForeignEpoch = (seq = 1) => {
      const other = makeSignKeyPair()
      const topic = other.publicKey.toString('hex')
      vault.put('device/other', deviceRow('other', other))
      const id = generateEpochId()
      const box = sealRing({ [id]: generateEpochKey() }, [
        { id: 'other', masterTopic: topic }
      ]).other
      const record = buildEpochRecord({
        id,
        seq,
        prev: null,
        members: { other: { topic, box } },
        personalKeyPair: other
      })
      vault.put(`epoch/${id}`, JSON.stringify(record))
      return id
    }

    test('activeVaultAdd writes plaintext before an epoch and an envelope after', async () => {
      await appDeps.activeVaultAdd('note/1', { title: 'before' })
      expect(JSON.parse(vault.rows.get('note/1').value)).toEqual({
        title: 'before'
      })

      const result = await appDeps.activeVaultEnsureEpoch({ start: true })
      expect(result).toMatchObject({ rotated: true, members: ['me'] })

      await appDeps.activeVaultAdd('note/2', { title: 'after' })
      const stored = vault.rows.get('note/2').value
      expect(JSON.parse(stored)).toMatchObject({ $enc: 1, e: result.id })
      expect(stored).not.toContain('after')
    })

    test('get, getFile, list and find decrypt and omit unreadable records', async () => {
      await appDeps.activeVaultAdd('note/1', { title: 'legacy' })
      await appDeps.activeVaultEnsureEpoch({ start: true })
      await appDeps.activeVaultAdd('note/2', { title: 'sealed' })
      await appDeps.activeVaultAdd('file/1', {}, Buffer.from('attachment'))
      vault.put(
        'note/3',
        JSON.stringify({ $enc: 1, e: 'ff'.repeat(16), n: 'AA==', c: 'AA==' })
      )

      expect(vault.rows.get('file/1').file.toString()).not.toBe('attachment')
      expect(await appDeps.activeVaultGetFile('file/1')).toEqual(
        Buffer.from('attachment')
      )
      expect(await appDeps.activeVaultGet('note/2')).toEqual({
        title: 'sealed'
      })
      expect(await appDeps.activeVaultGet('note/3')).toBeNull()
      expect(await appDeps.activeVaultList('note/')).toEqual([
        { title: 'legacy' },
        { title: 'sealed' }
      ])
      expect(
        await appDeps.activeVaultFind({
          gte: { key: 'note/' },
          lt: { key: 'note0' }
        })
      ).toEqual([
        { key: 'note/1', value: { title: 'legacy' } },
        { key: 'note/2', value: { title: 'sealed' } }
      ])
    })

    test('activeVaultAdd reports a missing epoch key in words the UI can show', async () => {
      const id = putForeignEpoch()

      await expect(
        appDeps.activeVaultAdd('note/1', { title: 'x' })
      ).rejects.toThrow('Vault key not available yet')
      expect(vault.rows.has('note/1')).toBe(false)
      expect(await appDeps.activeVaultGetEpochStatus()).toMatchObject({
        epoch: id,
        canRead: false,
        revoked: false
      })
    })

    test('activeVaultAdd refuses to write under an epoch that still lists a removed device', async () => {
      vault.put('device/other', deviceRow('other', makeSignKeyPair()))
      await appDeps.activeVaultEnsureEpoch({ start: true })
      vault.rows.delete('device/other')
      appDeps.getActiveVaultInstance().base.writable = false

      await expect(
        appDeps.activeVaultAdd('note/1', { title: 'x' })
      ).rejects.toThrow('Vault key must rotate first')
      expect(vault.rows.has('note/1')).toBe(false)
    })

    test('the update listener rotates when needed and pushes status only on change', async () => {
      const pushes = []
      appDeps.setEpochStatusListener((status) => pushes.push(status))
      const fireUpdate = await listen()

      await appDeps.activeVaultEnsureEpoch({ start: true })
      await fireUpdate()
      expect(pushes).toHaveLength(1)
      expect(pushes[0]).toMatchObject({
        vaultId: 'vault1',
        legacy: false,
        members: ['me']
      })

      await fireUpdate()
      expect(pushes).toHaveLength(1)

      vault.put('device/other', deviceRow('other', makeSignKeyPair()))
      await fireUpdate()
      expect(pushes).toHaveLength(2)
      expect(pushes[1]).toMatchObject({ seq: 2, members: ['me', 'other'] })
    })

    describe('incremental reconcile', () => {
      const v1 = { id: 'r1', type: 'note', data: { title: 'kept' } }
      const unreadable = JSON.stringify({
        $enc: 1,
        e: 'ff'.repeat(16),
        n: 'AA==',
        c: 'AA=='
      })

      // A v1 record the reconcile has already seen, with its v2 twin.
      const seenRecord = async () => {
        const fireUpdate = await listen()
        await appDeps.activeVaultEnsureEpoch({ start: true })
        vault.put('record/r1', JSON.stringify(v1))
        await fireUpdate()
        expect(vault.rows.has('record-v2/r1')).toBe(true)
        return fireUpdate
      }

      test('mirrors a v1 delete to v2 when every record is readable', async () => {
        const fireUpdate = await seenRecord()
        vault.rows.delete('record/r1')
        await fireUpdate()

        expect(vault.rows.has('record-v2/r1')).toBe(false)
      })

      test('keeps the v2 twin of a v1 record it cannot read', async () => {
        const fireUpdate = await seenRecord()
        vault.put('record/r1', unreadable)
        await fireUpdate()

        expect(vault.rows.has('record-v2/r1')).toBe(true)
        expect(await appDeps.activeVaultGet('record-v2/r1')).toMatchObject({
          data: { title: 'kept' }
        })
      })

      test('deletes nothing while the latest epoch is unreadable here', async () => {
        const fireUpdate = await seenRecord()
        putForeignEpoch(2)
        vault.rows.delete('record/r1')
        await fireUpdate()

        expect((await appDeps.activeVaultGetEpochStatus()).canRead).toBe(false)
        expect(vault.rows.has('record-v2/r1')).toBe(true)
      })
    })
  })

  describe('epoch API without an active vault', () => {
    test('activeVaultEnsureEpoch and activeVaultGetEpochStatus throw', async () => {
      await expect(
        appDeps.activeVaultEnsureEpoch({ start: true })
      ).rejects.toThrow('Vault not initialised')
      await expect(appDeps.activeVaultGetEpochStatus()).rejects.toThrow(
        'Vault not initialised'
      )
    })
  })
})
