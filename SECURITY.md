# Report a security issue

Email [security-lockwright@dexterity.works](mailto:security-lockwright@dexterity.works).

Do not file a public issue for an unfixed vulnerability.

## What revoking a device protects

Revoking a device rotates the vault's epoch key. Records written after the rotation are sealed under a key the removed device does not get. It keeps every record it synced before the rotation, and it can still see the vault's metadata: the roster, record keys, timestamps and ciphertext sizes. See [Revoking a device](./README.md#revoking-a-device) for the other limits. Reports that a removed device can read a record written after the rotation, by a member that had seen the removal, are in scope.
