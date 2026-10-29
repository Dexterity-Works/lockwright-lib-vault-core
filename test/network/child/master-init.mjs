/* eslint-disable no-console -- stdout is how the parent test reads progress */
// A device creating (or reopening) its master vault in its own process, so
// a test can SIGKILL it mid-way: node --import ./register.mjs master-init.mjs
// <storage dir> <encryptionKey> <hashedPassword>
// Prints "opening" right before masterVaultInit, "inited" after it, then
// "opened" once vaultsAdd is done, or
// "error <message>". No network: the swarm gets an isolated DHT
// (bootstrap []), and the guard is loaded.
const [dir, encryptionKey, hashedPassword] = process.argv.slice(2)

const main = async () => {
  const appDeps = await import('../../../src/worklet/appDeps.js')
  const network = await import('../../../src/worklet/utils/swarm.js')
  network.setNetworkOverrides({ bootstrap: [], relayThrough: [] })
  await appDeps.setStoragePath(dir)
  console.log('opening')
  try {
    await appDeps.masterVaultInit({ encryptionKey, hashedPassword })
    console.log('inited')
    await appDeps.vaultsAdd('masterEncryption', { hashedPassword })
    console.log('opened')
    await appDeps.closeAllInstances()
    process.exit(0)
  } catch (error) {
    console.log(`error ${error.message}`)
    process.exit(1)
  }
}

main()
