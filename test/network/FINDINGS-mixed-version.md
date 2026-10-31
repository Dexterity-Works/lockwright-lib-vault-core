# Mixed-version findings: release 031d532 beside the epoch re-key build

The tests run real code on the harness's private testnet: the released vault-core at 031d532 (what the shipped apps run) and this branch's epoch re-key build, each with its own dependencies (DEPS.md, "Mixed-version peers"). Test names are in `mixedversion.test.js`, under `mixed versions: release-031d532 beside the epoch re-key build`. "R" is a device on the released build. Peers are driven through each build's `appDeps` the way lib-vault drives it. lib-vault itself does not run in the harness.

## What the re-key build does, and when an epoch starts

- It re-encrypts nothing. A vault stays plaintext ("legacy") until a device starts an epoch. After that, new writes are sealed and old rows stay plaintext. Its schema-2 migration is the one 031d532 already ran, so on an upgraded vault it does nothing.
- On open it writes one row: it re-signs the device's own `device/` row, which 031d532 wrote unsigned. R's row is never signed, so R is never a member of any epoch.
- In a legacy vault, updates call only `ensureEpoch({ start: false })` (appDeps.js:632). That starts nothing unless a start is owed.
- What starts an epoch (read from code):
  - kickDevice, through startLegacyEpoch (lib-vault `src/api/kickDevice.js:62`, `src/utils/startLegacyEpoch.js:17-36`).
  - The leave-vault inbox handler (`src/actions/handlers/leaveVault.js:34`, `:48`), including a leave processed late after a `vault-not-active` deferral (`:19-21`).
  - "Rotate now": desktop `PairedDevicesModalContent/index.tsx:103`, mobile `PairedDevicesScreen/index.jsx:158`, extension `PairedDevicesModalContent/index.tsx:131`.
  - Both revoke modals: desktop `RevokeAccessModalContentV2.tsx:225`, extension `RevokeAccessModalContent/index.tsx:208`.
- A leave is broadcast whenever any device deletes the vault locally, the released build included (`src/api/deleteVaultLocal.js:47-52`, same at 24a94fc). Every upgraded device that processes it starts an epoch.

Upgrading one device at a time is safe only if, until the last device is upgraded:
- nobody kicks a device,
- nobody presses "rotate now",
- no device deletes or leaves the vault, and no leave is already queued in an inbox.

Any of these starts an epoch that leaves out every device still on 031d532.

## 1. Upgrade (031d532 vault reopened by the re-key build on the same storage)

- Two vaults, each read back after the upgrade, are identical. The fixture: a v1 login in a folder, marked favourite, with two files under both file keys; a v2 note in another folder; an HOTP login; a deleted record (still absent); a note; a second vault holding a login and a note.
  - Every raw view row is unchanged except the device row, which gains only `sig` and `writerPublicKey`.
  - Both vaults' entries in the master vault are unchanged.
  - The migration reports `ready`, `alreadyMigrated: true`, no error.
  - An epoch then starts with the device as its only member. Old rows stay plaintext and readable; new writes are sealed.
  - Test: `upgrade: two vaults the released build filled open intact on the re-key build`.
  - Not covered: TOTP items, items in a shared vault other than these, larger vaults.
- Two devices on 031d532, one upgraded: both keep every item, writes cross both ways in plaintext, and R's reconcile writes nothing when the upgraded device re-signs its row. Test: `mixed: one of two released devices upgrades; both keep every item and writes cross both ways`.
- Defect: a kick right after the upgrade is refused, and an epoch starts anyway.
  - While the open-time re-sign is in flight, startLegacyEpoch throws "kickDevice: cannot start the vault key: self-not-in-roster". Nothing is removed. A write in that window is refused with "Vault key must rotate first".
  - The start stays owed. The re-signed row's update runs it a moment later: an epoch with the upgraded device alone, which leaves out R. R then reads the next write as an envelope.
  - A leave in the same window stays in the inbox for a retry (read from leaveVault.js:33-34), and the owed start runs the same way.
  - Cause: `resignMyRows` adds the row to `resigned` (epochStore.js:704) before its add lands (:706), so the start's own pass skips it and reads the old roster.
  - Suggested src fix, for the record only: keep the in-flight re-sign promise and have doEnsureEpoch await it.
  - Test: `upgrade: a kick right after the upgrade is refused, then the owed start leaves the released device out`.
- A leave from a released device. L (031d532) closes the vault; the upgraded A runs the leave handler's steps (startLegacyEpoch, the sweep, `ensureEpoch({ start: true })`; the harness cannot run lib-vault, so this is simulated). A starts an epoch with members `[device-A]`, uncovered `[device-R]`. R, also on 031d532, stayed and cannot read A's later writes. Before the leave, an update from R started nothing. Test: `upgrade: a leave from a released device makes an upgraded device start an epoch without the other released devices`.

## 2. Mixed versions (R beside re-key devices in one vault)

The apps' save order: lib-vault saves `record-v2/<id>` first, then the v1 projection `record/<id>` (`src/compat/writeRecordDualStore.js:13-19`, same at 24a94fc). The core's `activeVaultAdd` for a v2 key appends the v1 projection itself.

### Edit of an old record, saved the apps' way, with the v1 append late

Test: `mixed: a re-key device edits an old record the way the apps save it, v2 then v1`. B (re-key) edits notes that R created before the epoch.

- If both appends reach R before its reconcile runs, R writes nothing and reads the record as its envelope.
- If the v1 projection reaches R more than one debounce (100 ms) after v2:
  - R's reconcile sees its plaintext v1 (updatedAt 1) against the sealed v2, which the released mergeV1IntoV2 counts as updatedAt 0 (release recordNamespaces.js:245-248). v1 wins.
  - R writes a mixed row: B's new ciphertext, with R's old plaintext fields beside it. This row becomes the v2 row on both devices.
  - R then reads the old record, and B reads its own edit.
  - It never repairs. A reconcile on each side afterwards writes nothing.
- R then edits the stale record, starting from the old content.
  - Saved as rebuilt fields (no envelope fields), it replaces B's edit on both devices. B's edit is lost.
  - Saved as the listed record spread with new fields, it keeps B's envelope. B keeps reading its own edit and never sees R's; R reads its own.
  - Which of the two the apps do was not checked.

### Epoch started on the re-key build

Test: `mixed: an epoch started on the re-key build leaves the released device out until it upgrades` (R, B, C).

- Before any epoch, both builds read each other's writes. The re-key devices list R as `uncovered`.
- B's epoch is sealed to B and C only: `members: [device-B, device-C], uncovered: [device-R]`.
- R still reads every item from before the epoch that nobody edited.
- New items, saved v2 first: R cannot read them, and its reconcile writes nothing.
  - 031d532 returns the envelope `{ $enc, e, n, c }` as the record, a list entry with no id, and ciphertext for the file.
- No crash, no logged error on R, no stall. B and C keep syncing and read every sealed item and file in full.
- R's writes reach B and C and read there, in plaintext: a note, and an edit of an old login saved v2 first.
- After R upgrades, its row is signed, a re-key device rotates to an epoch that includes R, and R reads everything.

What the app on R shows (read from code, not run):
- Shipped lib-vault listRecords maps each record through toAppRecord, so an envelope becomes `{ $enc, e, n, c, schema: 2, data: {} }`, with no id, type or title.
- Shipped desktop renders list rows with `key={record.id}` (RecordListView.tsx:192), so expect blank, untitled rows.
- Records hit by the late-v1 case above show stale content instead.

### Clients that write record/ first

No current app saves this way; these orders need a client that writes `record/` directly. Test: `mixed: a client that saves record/ first races the other build for the v2 twin`.

- A new record saved through its v1 key, with its v2 twin slow. R writes a plaintext twin: the v1 envelope plus `schema: 2, data: {}`.
  - If the re-key twin lands after it, nothing is lost.
  - If R's copy lands last, the re-key build reads the record without `schema` and `uris`, and neither reconcile repairs it. The next save on a re-key build repairs it.
- R edits an old record through its v1 key, with its v2 twin slow, and B's reconcile writes a sealed merged twin that lands last.
  - R reads its own edit as an envelope only until its next reconcile.
  - That reconcile writes a mixed row (B's ciphertext plus R's edit), after which both sides read R's edit.

Not tested: R editing or deleting an item it sees only as an envelope; R upgrading while no re-key member is online; more than one released device in an epoch vault.

## 3. Rollback (vault sealed by the re-key build, reopened by 031d532 on the same storage)

Test: `rollback: the released build reopens a vault the re-key build sealed`.

- 031d532 opens the vault with no error, its migration reports `alreadyMigrated`, and its reconcile writes nothing.
- Readable: everything from before the epoch, files included.
- Not readable: everything sealed after it, which comes back as envelopes, entries with no id, and ciphertext.
- Writes made on 031d532 are plaintext.
- Rolling forward again loses nothing: same epoch, sealed items and the file read in full, and the rollback-era writes read too.
- Only a single device was rolled back.

## 4. Revoke with a released device in the vault

- Kicking R while A and B run the re-key build.
  - The epoch already leaves R out, so the kick returns `rotated: false, reason: 'current'`.
  - R's `base.writable` turns false and its writes are refused with "Not writable".
  - R still reads items from before the epoch, and sees later ones as envelopes.
  - Test: `revoke: kicking a device on the released build needs no rotation and leaves it read-only`.
- Kicking re-key device C while R stays.
  - The rotation seals to A only, and C reports `revoked`.
  - C holds A's later rows, sealed, and reads none of them; R cannot read them either.
  - R's writes stay plaintext, so A reads them, and so does the kicked C.
  - Test: `revoke: a device on the released build stays while a re-key device is kicked`.

Not tested: lib-vault's kickDevice and its kick notice; a kick issued from 031d532 (it has no epoch API).
