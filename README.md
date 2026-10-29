<p align="center">
  <img src="docs/logo.svg" alt="Lockwright" width="128"/>
</p>

# lockwright-lib-vault-core

Bare-runtime vault core for Lockwright. Create, encrypt, and manage password vaults.

Site: [lockwright.dexterity.works](https://lockwright.dexterity.works)

Community fork of PearPass (Apache 2.0). Not affiliated with or endorsed by Tether Data or the Pears project.

## Table of Contents

- [Features](#features)
- [Install](#install)
- [Usage Examples](#usage-examples)
- [Revoking a device](#revoking-a-device)
- [Dependencies](#dependencies)
- [Related Projects](#related-projects)
- [License](#license)

## Features

- Encrypted vault create and manage
- Local encrypt and decrypt
- Event-based updates
- Vault sharing via invite codes
- Debug mode

## Install

```bash
pnpm add git+https://github.com/Dexterity-Works/lockwright-lib-vault-core.git
```

The package name is `lockwright-lib-vault-core`.

## Usage Examples

### Initialize a vault client
```javascript
import { createPearpassVaultClient } from 'lockwright-lib-vault-core';

// Create a new client with a storage path
const client = createPearpassVaultClient('/path/to/storage', {
    debugMode: false // Set to true for verbose logging
});
```

### Encryption for vault key
```javascript
const password = 'my-secure-password';

// hashing the password 
const { hashedPassword, salt } = await client.hashPassword(password);

// Generate a random encryption key
const { ciphertext, nonce } = await client.encryptVaultKeyWithHashedPassword(hashedPassword);

// Encrypt existing vault key 
const { ciphertext, nonce } = await client.encryptVaultWithKey(hashedPassword, key);
```

### Decryption for vault key
```javascript
// Get hashed password from user input
const hashedPassword = await client.getDecryptionKey({salt, password});

// Decrypt the vault key
const key = await client.decryptVaultKey({ciphertext, nonce, hashedPassword});
```

### Working with vaults
```javascript
// Initialize encryption
await client.encryptionInit();

// Initialize vaults storage
await client.vaultsInit();


// Store vault info
await client.vaultsAdd('vault/my-vault', {
    id: 'my-vault',
    name: 'My Password Vault',
    hashedPassword,
    ciphertext,
    nonce,
    salt,
});

// Initialize active vault
await client.activeVaultInit({
    id: vaultId,
    encryptionKey: key
});

// Add an entry to the vault
await client.activeVaultAdd(`record/${vaultId}`, {
    name: 'GitHub',
    username: 'user@example.com',
    password: 'secure-password'
});

// Retrieve passwords
const github = await client.activeVaultGet(`vault/${vaultId}`);
console.log(githubPassword);

// Close connections when done
await client.closeAllInstances();
```

## Revoking a device

A vault's records are sealed under per-epoch keys (ADR 0014 in the Lockwright superproject), so a device removed from the roster cannot read what members write after the key rotates.

- Each epoch has a random 32-byte key. Once a vault has an epoch, every value and attached file is sealed with `secretbox` under the latest epoch's key, except `vault`, `vault-ext`, `device/*` and `epoch/*`, which stay plaintext.
- The key reaches each roster device in a signed `epoch/<id>` record, boxed to the Curve25519 form of the device's `masterTopic`. A roster row counts only when its writer signed it for this vault and is still a writer.
- A vault with no epoch record stays plaintext until its first roster shrink.

```javascript
// lib-vault's kickDevice does all of this. In a vault with no epoch yet,
// start one while the device is still a member, so that any member can
// rotate past the removal if this device stops before the rotation:
const status = await client.activeVaultGetEpochStatus()
if (status.legacy) await client.activeVaultEnsureEpoch({ start: true })
// ...remove the device's writer (activeVaultRemoveWriter) and its rows...
const result = await client.activeVaultEnsureEpoch({ start: true })
// { rotated: true, id, seq, members, uncovered }
// or { rotated: false, reason, uncovered }, reason one of
// 'current', 'pending', 'legacy', 'not-writable', 'self-not-in-roster'

// status: { vaultId, epoch, seq, legacy, canRead, revoked, members, uncovered }

client.on('epoch-status', (status) => {
  // pushed when the active vault's status changes
})
```

What revoking does not do: the removed device keeps everything it synced before the rotation. It still replicates the vault and sees the roster, record keys, timestamps and ciphertext sizes. It can read a record written by a member whose copy of the roster had not yet shown the removal. Before its removal lands it can add another writer, which stays a member until it is removed too. Devices on builds without epoch keys write plaintext until they update.

## Dependencies

- [Autopass](https://github.com/holepunchto/autopass)
- [Corestore](https://github.com/holepunchto/corestore)
- [Bare Crypto](https://github.com/holepunchto/bare-crypto)
- [Bare FS](https://github.com/holepunchto/bare-fs)
- [Bare Path](https://github.com/holepunchto/bare-path)
- [Bare RPC](https://github.com/holepunchto/bare-rpc)
- [Sodium Native](https://github.com/sodium-friends/sodium-native)
- [UDX Native](https://github.com/holepunchto/udx-native)
- Node.js Events

## Related Projects

- [lockwright-app-mobile](https://github.com/Dexterity-Works/lockwright-app-mobile)
- [lockwright-app-desktop](https://github.com/Dexterity-Works/lockwright-app-desktop)
- [lockwright-app-browser-extension](https://github.com/Dexterity-Works/lockwright-app-browser-extension)
- [lockwright-lib-vault](https://github.com/Dexterity-Works/lockwright-lib-vault)
- [lockwright-lib-constants](https://github.com/Dexterity-Works/lockwright-lib-constants)

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](./CONTRIBUTING.md).

## License

Apache License 2.0. See `LICENSE.md` and `NOTICE.md`.
