# Mixed-version findings: release 031d532 beside the epoch re-key build

Each scenario runs real code on the harness's private testnet: the released vault-core at 031d532, which the shipped apps run, and the epoch re-key build. Each side uses its own dependencies (DEPS.md, "Mixed-version peers"). The test names below are in `mixedversion.test.js`, under `mixed versions: release-031d532 beside the epoch re-key build`. "R" is a device on the released build.

What the re-key build does to an existing vault, from the code and confirmed by the tests:
- It re-encrypts nothing. A vault stays plaintext ("legacy") until a device starts an epoch; lib-vault starts one on a kick.
- From then on, new writes are sealed and old rows stay plaintext.
- Its schema-2 migration is the one 031d532 already ran, so on an upgraded vault it does nothing.
- The one write it makes on open: it re-signs the device's own `device/` row, which 031d532 wrote unsigned.

## 1. Upgrade

- Nothing is lost.
  - Every item, both file copies and the record list read back identical.
  - The migration reports `ready`, `alreadyMigrated: true`, no error.
  - Once the re-signed row lands, an epoch starts with the device as its only member. Old rows stay plaintext and readable, and new writes are sealed.
  - Test: `upgrade: a vault the released build filled opens intact on the re-key build`.
- Two devices on 031d532, one upgrades:
  - Both keep every item, and writes cross both ways in plaintext.
  - R's reconcile writes nothing when the upgraded device re-signs its row.
  - Test: `mixed: one of two released devices upgrades; both keep every item and writes cross both ways`.
- Defect: an epoch start right after the upgraded vault opens is refused.
  - While the re-sign is still in flight, the start returns `self-not-in-roster` and records the start as owed.
  - A write in that window is refused with "Vault key must rotate first: wait for a device that can rotate it".
  - It heals on its own: the re-signed row's update runs the owed start, and writes work again.
  - Cause: `resignMyRows` marks the row as re-signed before the write lands, so the start's own pass skips it.
  - Production impact: lib-vault's kickDevice starts an epoch first in a legacy vault, so a kick just after an upgraded device opens hits this.
  - Test: `upgrade: an epoch start while the open-time re-sign is in flight is refused, then heals`.

## 2. Mixed versions

Test: `mixed: an epoch started on the re-key build leaves the released device out until it upgrades`.

- Before any epoch, both builds read each other's writes. The re-key devices list R as `uncovered`, because 031d532 never signs its row.
- When B starts an epoch, it is sealed to B and C only. R never gets a key while it runs 031d532.
- Old items: R still reads every item nobody edited since the epoch. Once a re-key device edits an old item, R can no longer read it.
- New items from re-key devices: R cannot read them, but gets no error either.
  - `activeVaultGet` returns the envelope `{ $enc, e, n, c }` as if it were the record.
  - `activeVaultList('record/')` returns one entry with no id per sealed record.
  - `activeVaultGetFile` returns ciphertext.
  - The app on R would show broken entries. The app UI was not tested.
- No crash, no logged error on R, no stall. B and C keep syncing and read every sealed item and file in full.
- R's writes (a new note, an edit of an old login) reach B and C and read there, in plaintext.
- When R upgrades, its row gets signed. B and C both rotated at once (two seq-2 epochs) and then settled on one that includes R. R then reads everything.

Corruption: the dual-store twins race between the builds.

Both builds save a record as two rows in two appends: a v1 row (`record/<id>`) and a v2 twin (`record-v2/<id>`). Each build's reconcile writes a missing twin itself.

Test: `mixed: when one twin of a record lands late, the other build writes it`. This race first appeared without any forcing, in 1 of 5 runs of an earlier version of the epoch test.

- A re-key device saves a new record through its v1 key, and its v2 twin is slow.
  - R writes a plaintext twin: the v1 envelope plus `schema: 2, data: {}`. It holds only ciphertext, so nothing leaks.
  - If the re-key twin lands after R's copy, it wins and nothing is lost.
  - If R's copy lands last, the re-key build reads that record without `schema` or `uris`, so any URI match setting is lost. Neither reconcile repairs it, because both rows carry the same `updatedAt`. The next save of the record on a re-key build repairs it.
- R edits an old record through its v1 key, and its v2 twin is slow.
  - B's reconcile writes the merged twin, sealed.
  - If B's twin lands last, R can no longer read the record it just edited. B reads it in full.
- No write from R: records saved through the v2 key, files saved through the v2 file key, and a re-key device's v1-key edit of an old record.

Not tested:
- R editing or deleting an item it sees as an envelope. The store side of a merge over an envelope is covered in `epochStore.integration.test.js`.
- R upgrading while no re-key member is online.
- More than one released device in a vault that has an epoch.

## 3. Rollback

Test: `rollback: the released build reopens a vault the re-key build sealed`.

- 031d532 opens the vault with no error. Its migration reads the plaintext `vault-ext` and reports `alreadyMigrated`, and its reconcile writes nothing.
- Readable: everything written before the epoch, files included.
- Not readable: everything sealed after it. Sealed records come back as envelopes and as entries with no id; the sealed file comes back as ciphertext.
- Writes on the rolled-back build land in plaintext.
- Rolling forward again loses nothing. The epoch is the same, sealed items and the file read in full, and the rollback's writes read too.
- Only a single device was rolled back.

## 4. Revoke

- Kicking R while A and B run the re-key build.
  - The epoch already leaves R out, so the kick returns `rotated: false, reason: 'current'`.
  - R's `base.writable` turns false and its writes are refused with "Not writable".
  - R still reads items from before the epoch and sees later ones as envelopes.
  - Test: `revoke: kicking a device on the released build needs no rotation and leaves it read-only`.
- Kicking re-key device C while R stays.
  - The rotation seals to A only, and C reports `revoked`.
  - Neither C nor R reads A's writes after the kick.
  - R's writes stay plaintext, so A reads them, and so does the kicked C.
  - Test: `revoke: a device on the released build stays while a re-key device is kicked`.
- Not tested: lib-vault's kickDevice and its kick notice, and a kick issued from 031d532 (it has no epoch API).
