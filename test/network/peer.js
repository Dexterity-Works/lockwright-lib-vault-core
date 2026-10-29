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
   *   tracer?: import('./tracer.js').Tracer | null,
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
    tracer = null,
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
    this.tracer = tracer
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
    this.started = false
    /** Every instance the seam handed out, so a failed init still closes. */
    this.created = []
    this.destroying = []
  }

  async start() {
    fs.mkdirSync(this.dir, { recursive: true })
    await this.appDeps.setStoragePath(this.dir)
    this.network.setNetworkOverrides({
      bootstrap: this.bootstrap,
      relayThrough: this.relayThrough,
      onCreate: (label, instance) => {
        this.created.push({ label, instance })
        // personalSend destroys its swarm without awaiting it; stop() waits
        // for that destroy, or its socket outlives the test.
        if (label === 'personalSend') {
          const destroy = instance.destroy.bind(instance)
          instance.destroy = (...args) => {
            const done = destroy(...args)
            this.destroying.push(done)
            return done
          }
        }
        // appDeps builds the master vault and the active vault alike; the
        // master vault is the only one built while start() runs.
        const traced =
          label === 'autopass' ? (this.started ? 'vault' : 'master') : label
        this.tracer?.attach(traced, instance)
        this.onCreate?.(label, instance, this)
      }
    })
    this.appDeps.setEpochStatusListener((status) =>
      this.tracer?.epochStatus(status)
    )
    this.trace('peer.start', { dir: this.dir })
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
    this.started = true
    return this
  }

  trace(event, fields) {
    return this.tracer?.record(event, fields) ?? null
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
        this.trace('vault.update', { n: this.updates })
        this.onUpdate?.(this)
      }
    })
  }

  /** createUnprotectedVault, as lib-vault does it. */
  async createVault({ id = `vault-${this.id}`, name = id } = {}) {
    this.vaultId = id
    this.encryptionKey = crypto.randomBytes(32).toString('base64')
    this.trace('peer.createVault', { vaultId: id })
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
  async invite() {
    const code = await this.appDeps.createInvite()
    this.trace('peer.invite', { vaultId: this.vaultId })
    return code
  }

  /** pairActiveVault, as lib-vault does it: pair, open, catalog, device row. */
  async pair(code) {
    this.trace('peer.pair', { vaultId: code.split('/')[0] })
    let paired
    try {
      paired = await this.appDeps.pairActiveVault(code)
    } catch (error) {
      this.tracer?.error('peer.pair', error)
      throw error
    }
    const { vaultId, encryptionKey } = paired
    this.trace('peer.paired', { vaultId })
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

  /** The stored row as Autopass holds it: `{ value, file }` or null. */
  raw(key) {
    return this.instance.get(key)
  }

  getFile(key) {
    return this.appDeps.activeVaultGetFile(key)
  }

  remove(key) {
    return this.appDeps.vaultRemove(key)
  }

  /** Traced only when the count under `prefix` changes: waits poll it. */
  async list(prefix) {
    const rows = await this.appDeps.activeVaultList(prefix)
    this.listed ??= new Map()
    if (this.listed.get(prefix) !== rows.length) {
      this.listed.set(prefix, rows.length)
      this.trace('peer.list', { prefix, n: rows.length })
    }
    return rows
  }

  devices() {
    return this.appDeps.activeVaultList('device/')
  }

  /**
   * kickDevice, as lib-vault does it minus the personal-swarm envelope:
   * revoke every swept writer, drop the rows (primary last), rotate.
   */
  async kick(deviceId) {
    this.trace('peer.kick', { deviceId })
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

  /** Start this device's personal swarm (its master topic) and collect envelopes. */
  async personalInit() {
    const ps = this.modules.personalSwarm
    this.envelopes ??= []
    if (!this.unsubscribeEnvelope) {
      this.unsubscribeEnvelope = ps.personalSwarmOnEnvelope((hex) => {
        this.envelopes.push(hex)
        this.trace('personal.envelope', { bytes: hex.length / 2 })
      })
    }
    const { topic } = await ps.personalSwarmInit()
    this.trace('personal.init', { topic: topic.slice(0, 8) })
    return topic
  }

  async personalClose() {
    this.trace('personal.close')
    await this.modules.personalSwarm.personalSwarmClose()
  }

  /** personalSwarmSend: one framed envelope to a device's master topic. */
  async personalSend(topicHex, envelopeHex) {
    const result = await this.modules.personalSwarm.personalSwarmSend(
      topicHex,
      envelopeHex
    )
    this.trace('personal.send', {
      topic: String(topicHex).slice(0, 8),
      ok: result.ok,
      reason: result.reason ?? null
    })
    return result
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
    this.trace('peer.offline')
    await this.instance.swarm.suspend()
  }

  async goOnline() {
    this.trace('peer.online')
    await this.instance.swarm.resume()
  }

  /** Close the active vault and open it again from disk, with a new swarm. */
  restartVault() {
    this.trace('peer.restartVault')
    return this.appDeps.restartActiveVault()
  }

  closeVault() {
    this.trace('peer.closeVault')
    return this.appDeps.closeActiveVaultInstance()
  }

  async openVault() {
    this.trace('peer.openVault')
    await this.appDeps.initActiveVaultInstance({
      id: this.vaultId,
      encryptionKey: this.encryptionKey
    })
    await this.listen()
  }

  /**
   * Make another vault this device owns the active one, as lib-vault does
   * on a vault switch: appDeps closes the previous instance itself.
   */
  switchVault({ id, encryptionKey }) {
    this.trace('peer.switchVault', { from: this.vaultId, vaultId: id })
    this.vaultId = id
    this.encryptionKey = encryptionKey
    return this.openVault()
  }

  /**
   * lockAppSession, as the desktop app does it: close every instance, the
   * active vault first. Returns how long the close took, in ms.
   */
  async lock() {
    this.trace('peer.lock')
    const t0 = Date.now()
    await this.appDeps.closeAllInstances()
    const ms = Date.now() - t0
    this.trace('peer.locked', { ms })
    return ms
  }

  /**
   * API.CLOSE_ALL_INSTANCES as appCore.js handles it: the personal swarm,
   * then every instance, then the shared DHT, in that order.
   */
  async closeAll() {
    this.trace('peer.closeAll')
    await this.modules.personalSwarm.personalSwarmClose()
    await this.appDeps.closeAllInstances()
    await this.modules.dht.destroySharedDHT()
  }

  /** Forget closed instances, so a long run does not measure its own list. */
  pruneClosed() {
    this.created = this.created.filter(
      ({ instance }) => !instance.closed && !instance.destroyed
    )
  }

  /** Unlock: the master vault with the same keys, then the active vault. */
  async unlock() {
    this.trace('peer.unlock')
    // The master vault's Autopass is built again: label it as such.
    this.started = false
    try {
      await this.appDeps.masterVaultInit({
        encryptionKey: this.masterKey,
        hashedPassword: this.hashedPassword
      })
    } finally {
      this.started = true
    }
    if (this.vaultId) await this.openVault()
  }

  async stop({ keep = false } = {}) {
    this.trace('peer.stop')
    const steps = [
      () => this.appDeps.closeAllInstances(),
      () => this.modules.personalSwarm?.personalSwarmClose(),
      () => this.modules.dht?.destroySharedDHT()
    ]
    for (const step of steps) {
      try {
        await step()
      } catch (error) {
        this.tracer?.error('peer.stop', error)
        this.errors.push(error)
      }
    }
    // An init that threw after building its Autopass leaves it outside
    // appDeps' bookkeeping; close whatever is still open.
    for (const { instance } of this.created.reverse()) {
      try {
        if (typeof instance.close === 'function' && !instance.closed) {
          await instance.close()
        } else if (
          typeof instance.destroy === 'function' &&
          !instance.destroyed
        ) {
          await instance.destroy()
        }
      } catch (error) {
        this.errors.push(error)
      }
    }
    this.created = []
    await Promise.allSettled(this.destroying)
    this.destroying = []
    this.unsubscribeEnvelope?.()
    this.unsubscribeEnvelope = null
    this.appDeps.setEpochStatusListener(null)
    this.network.setNetworkOverrides(null)
    this.tracer?.close()
    if (!keep) fs.rmSync(this.dir, { recursive: true, force: true })
  }
}
