import crypto from 'crypto'
import fs from 'fs'

// One Lockwright device, driven through the real worklet module (appDeps)
// the way lib-vault drives it over RPC. `modules` is a private copy of the
// module graph (jest.isolateModules, or a process of its own), because
// appDeps keeps one device's state in module singletons.
export class Peer {
  /**
   * @param {{
   *   id: string,
   *   modules: { appDeps: object, network: object, personalSwarm?: object, dht?: object, logger?: object },
   *   bootstrap: Array<{ host: string, port: number }>,
   *   relayThrough?: Array<Buffer> | Function | null,
   *   dir: string,
   *   onCreate?: (label: string, instance: object, peer: Peer) => void,
   *   onUpdate?: (peer: Peer) => void
   * }} options
   */
  constructor({
    id,
    modules,
    bootstrap,
    relayThrough = [],
    dir,
    onCreate,
    onUpdate
  }) {
    this.id = id
    this.modules = modules
    this.appDeps = modules.appDeps
    this.network = modules.network
    this.bootstrap = bootstrap
    this.relayThrough = relayThrough
    this.dir = dir
    this.onCreate = onCreate
    this.onUpdate = onUpdate
    this.deviceId = `device-${id}`
    // The master vault's blind-encryption secret; production derives it
    // from the master password. Random per device here.
    this.hashedPassword = crypto.randomBytes(32).toString('hex')
    this.masterKey = crypto.randomBytes(32).toString('base64')
    this.masterTopic = null
    this.vaultId = null
    this.encryptionKey = null
    this.updates = 0
    this.errors = []
  }

  async start() {
    fs.mkdirSync(this.dir, { recursive: true })
    await this.appDeps.setStoragePath(this.dir)
    this.network.setNetworkOverrides({
      bootstrap: this.bootstrap,
      relayThrough: this.relayThrough,
      onCreate: (label, instance) => this.onCreate?.(label, instance, this)
    })
    await this.appDeps.masterVaultInit({
      encryptionKey: this.masterKey,
      hashedPassword: this.hashedPassword
    })
    // getHashedPassword() reads this row; production stores the master key
    // ciphertext and nonce beside it, which nothing here reads.
    await this.appDeps.vaultsAdd('masterEncryption', {
      hashedPassword: this.hashedPassword
    })
    const keyPair = await this.appDeps.getPersonalKeyPair()
    this.masterTopic = Buffer.from(keyPair.publicKey).toString('hex')
    return this
  }

  /** The device row lib-vault's addDevice writes after create or pair. */
  async addDeviceRow() {
    const row = {
      id: this.deviceId,
      name: this.deviceId,
      vaultId: this.vaultId,
      writerKey: this.appDeps.activeVaultGetWriterKey(),
      masterTopic: this.masterTopic,
      createdAt: Date.now()
    }
    await this.appDeps.activeVaultAdd(`device/${row.id}`, row)
    return row
  }

  async listen() {
    await this.appDeps.initListener({
      vaultId: this.vaultId,
      onUpdate: () => {
        this.updates++
        this.onUpdate?.(this)
      }
    })
  }

  /** createUnprotectedVault, as lib-vault does it. */
  async createVault({ id = `vault-${this.id}`, name = id } = {}) {
    this.vaultId = id
    this.encryptionKey = crypto.randomBytes(32).toString('base64')
    await this.appDeps.initActiveVaultInstance({
      id,
      encryptionKey: this.encryptionKey
    })
    await this.appDeps.vaultsAdd(`vault/${id}`, { id, name })
    await this.appDeps.activeVaultAdd('vault', { id, name })
    await this.listen()
    await this.addDeviceRow()
    return id
  }

  /** `<vaultId>/<z32 invite>` */
  invite() {
    return this.appDeps.createInvite()
  }

  /** pairActiveVault, as lib-vault does it: pair, open, catalog, device row. */
  async pair(code) {
    const { vaultId, encryptionKey } = await this.appDeps.pairActiveVault(code)
    this.vaultId = vaultId
    this.encryptionKey = encryptionKey
    await this.appDeps.initActiveVaultInstance({ id: vaultId, encryptionKey })
    const vault = (await this.appDeps.activeVaultGet('vault')) ?? {
      id: vaultId
    }
    await this.appDeps.vaultsAdd(`vault/${vaultId}`, vault)
    await this.listen()
    await this.addDeviceRow()
    return vaultId
  }

  add(key, data, file, fileName) {
    return this.appDeps.activeVaultAdd(key, data, file, fileName)
  }

  get(key) {
    return this.appDeps.activeVaultGet(key)
  }

  getFile(key) {
    return this.appDeps.activeVaultGetFile(key)
  }

  remove(key) {
    return this.appDeps.vaultRemove(key)
  }

  list(prefix) {
    return this.appDeps.activeVaultList(prefix)
  }

  devices() {
    return this.appDeps.activeVaultList('device/')
  }

  /**
   * kickDevice, as lib-vault does it minus the personal-swarm envelope:
   * revoke every swept writer, drop the rows (primary last), rotate.
   */
  async kick(deviceId) {
    const devices = (await this.devices()) ?? []
    const target = devices.find((d) => d?.id === deviceId)
    if (!target) throw new Error(`kick: no device row ${deviceId}`)
    const myWriterKey = this.appDeps.activeVaultGetWriterKey()
    const matches = (d) =>
      (!!target.writerKey && d.writerKey === target.writerKey) ||
      (!!target.masterTopic && d.masterTopic === target.masterTopic)
    const duplicates = devices.filter(
      (d) =>
        d?.id && d.id !== deviceId && d.writerKey !== myWriterKey && matches(d)
    )
    const writerKeys = new Set(
      [...duplicates, target]
        .map((d) => d.writerKey)
        .filter((k) => k && k !== myWriterKey)
    )
    for (const writerKey of writerKeys) {
      await this.appDeps.vaultRemoveWriter(writerKey)
    }
    for (const id of new Set(duplicates.map((d) => d.id))) {
      await this.appDeps.vaultRemove(`device/${id}`)
    }
    await this.appDeps.vaultRemove(`device/${deviceId}`)
    return this.appDeps.activeVaultEnsureEpoch({ start: true })
  }

  ensureEpoch({ start = false } = {}) {
    return this.appDeps.activeVaultEnsureEpoch({ start })
  }

  epochStatus() {
    return this.appDeps.activeVaultGetEpochStatus()
  }

  /** The active vault's Autopass. */
  get instance() {
    return this.appDeps.getActiveVaultInstance()
  }

  get writerKey() {
    return this.appDeps.activeVaultGetWriterKey()
  }

  /** Cut the active vault off the network; writes keep landing locally. */
  async goOffline() {
    await this.instance.swarm.suspend()
  }

  async goOnline() {
    await this.instance.swarm.resume()
  }

  /** Close the active vault and open it again from disk, with a new swarm. */
  restartVault() {
    return this.appDeps.restartActiveVault()
  }

  closeVault() {
    return this.appDeps.closeActiveVaultInstance()
  }

  async openVault() {
    await this.appDeps.initActiveVaultInstance({
      id: this.vaultId,
      encryptionKey: this.encryptionKey
    })
    await this.listen()
  }

  async stop({ keep = false } = {}) {
    const steps = [
      () => this.appDeps.closeAllInstances(),
      () => this.modules.personalSwarm?.personalSwarmClose(),
      () => this.modules.dht?.destroySharedDHT()
    ]
    for (const step of steps) {
      try {
        await step()
      } catch (error) {
        this.errors.push(error)
      }
    }
    this.network.setNetworkOverrides(null)
    if (!keep) fs.rmSync(this.dir, { recursive: true, force: true })
  }
}
