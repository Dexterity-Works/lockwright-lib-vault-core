# Mixed-version findings: release 031d532 beside the epoch re-key build

Real code on the harness's private testnet: the released vault-core at 031d532 and this branch's epoch re-key build, each with its own dependencies (DEPS.md, "Mixed-version peers"). Test names are in `mixedversion.test.js`, under `mixed versions: release-031d532 beside the epoch re-key build`. "R" is a device on 031d532. Peers are driven through each build's `appDeps`. lib-vault does not run in the harness, so anything lib-vault does is either simulated in a test, which says so, or read from code.

Citations outside this repo:
- "lib-vault 24a94fc" is the lib-vault the shipped apps pin.
- "lib-vault 88c12b1" is current lib-vault on feat/vault-epoch-rekey.
- Desktop 9427ac8, mobile 160d99b and extension 806bc88 are the current app trees, not the shipped ones.

## What the re-key build does, and what starts an epoch

- It re-encrypts nothing. A vault stays plaintext ("legacy") until a device starts an epoch. After that, new writes are sealed and old rows stay plaintext.
- Its schema-2 migration is the one 031d532 already ran, so it does nothing on an upgraded vault.
- On open it writes one row per vault it opens: it re-signs the device's own `device/` row, which 031d532 wrote unsigned. R's row is never signed, so R is never a member of an epoch.
- In a legacy vault, updates call only `ensureEpoch({ start: false })` (appDeps.js:632). That starts nothing unless a start is owed.
- What starts an epoch (read from code):
  - kickDevice, through startLegacyEpoch (lib-vault 88c12b1 `src/api/kickDevice.js:62`, `src/utils/startLegacyEpoch.js:17-36`).
  - The leave-vault inbox handler (88c12b1 `src/actions/handlers/leaveVault.js:34`, `:48`). It starts one even when the leaver's row is already gone (`:32-34`); 24a94fc returned early at `:23`.
  - "Rotate now": desktop 9427ac8 `PairedDevicesModalContent/index.tsx:103`, mobile 160d99b `PairedDevicesScreen/index.jsx:158`, extension 806bc88 `PairedDevicesModalContent/index.tsx:131`.
  - The revoke modals: desktop 9427ac8 `RevokeAccessModalContentV2.tsx:225`, extension 806bc88 `RevokeAccessModalContent/index.tsx:208`.
- How a leave reaches an upgraded device (read from code):
  - Any device that deletes a vault locally broadcasts a leave, a 031d532 device included (lib-vault 24a94fc and 88c12b1 `src/api/deleteVaultLocal.js:47-52`).
  - On 24a94fc the leave waits in the sender's outbox until the receiver is online (`src/api/broadcastAction.js:63`).
  - On the receiver, a leave for a vault that is not active is deferred (24a94fc `leaveVault.js:16-19`). Deferred entries are skipped without counting an attempt, so they stay in the inbox (24a94fc `src/api/inbox.js:125-127`).
  - Once that device upgrades and opens the vault, the leave starts an epoch.

### Upgrade rule

Upgrading one device at a time is safe only if, until the last device is upgraded:
- nobody kicks a device,
- nobody presses "rotate now",
- no device deletes or leaves a shared vault,
- and no leave is waiting in any outbox or inbox.

Any of these starts an epoch that leaves out every device still on 031d532.

The step that clears queued leaves: before upgrading anything, on every device, open each shared vault while online and let it sync, so the 031d532 handler handles any queued leave first. Any device that deleted a vault must have come online since it did.

## 1. Upgrade (031d532 vault reopened by the re-key build on the same storage)

- Two vaults, each read back identical after the upgrade. Test: `upgrade: two vaults the released build filled open intact on the re-key build`.
  - The fixture: a v1 login in a folder, marked favourite, with two files under both file keys; a v2 note in another folder; an HOTP login; a deleted record (still absent afterwards); a note; and a second vault with a login and a note.
  - Every raw view row of both vaults is unchanged except the device row, which gains only `sig` and `writerPublicKey`.
  - The master vault's raw rows are unchanged.
  - The migration reports `ready`, `alreadyMigrated: true`, no error.
  - An epoch then starts with the device as its only member. Old rows stay plaintext and readable; new writes are sealed.
  - Not covered: TOTP items, larger vaults.
- Two devices on 031d532, one upgraded: both keep every item, writes cross both ways in plaintext, and R's reconcile writes nothing when the upgraded device re-signs its row. Test: `mixed: one of two released devices upgrades; both keep every item and writes cross both ways`.
- Defect: a kick right after the upgrade is refused, and an epoch starts anyway. Test: `upgrade: a kick right after the upgrade is refused, then the owed start leaves the released device out`.
  - While the open-time re-sign is in flight, startLegacyEpoch throws "kickDevice: cannot start the vault key: self-not-in-roster" before anything is removed. A write in that window is refused with "Vault key must rotate first".
  - The start stays owed. The re-signed row's update runs it a moment later: an epoch with the upgraded device alone, which leaves out R.
  - A leave in that window stays in the inbox for a retry, and the owed start runs the same way (read from code, 88c12b1 `leaveVault.js:33-34`).
  - Cause: `resignMyRows` adds the row to `resigned` (epochStore.js:704) before its add lands (:706).
  - Suggested src fix, for the record only: keep the in-flight re-sign promise and have doEnsureEpoch await it.
- A leave from a 031d532 device, processed at once. Test: `upgrade: a leave from a released device makes an upgraded device start an epoch without the other released devices`.
  - Simulated: the upgraded device runs the handler's steps (startLegacyEpoch, the sweep, `ensureEpoch({ start: true })`).
  - Before the leave, an update from R started nothing.
  - After it: members `[device-A]`, uncovered `[device-R]`. The handler's own `ensureEpoch` returns `rotated: false, reason: 'current'`, which it accepts, so the leave finishes instead of retrying.
  - R stayed and cannot read A's later writes.
- A leave deferred on 031d532. Test: `upgrade: a leave deferred on the released build fires once the upgraded device opens that vault`.
  - L deletes the shared vault while A works in another vault. The test writes the leave into A's inbox itself; the 031d532 deferral is read from code, not run.
  - After the upgrade the entry is still in A's master vault.
  - When A opens the shared vault, the handler's steps (simulated) start an epoch that leaves out R.
- Defect found while writing that test: on the upgraded device, opening one vault and switching to another right away throws an uncaught `TypeError: Cannot read properties of null (reading 'flushing')` from hypercore.
  - It happened in 4 of 4 runs.
  - It did not happen in 3 of 3 runs once the test waited for the first vault's re-signed device row before switching.
  - Cause not confirmed. No test asserts it; the test waits.

## 2. Mixed versions (R beside re-key devices in one vault)

The apps' save order: lib-vault saves `record-v2/<id>` first, then the v1 projection `record/<id>` (24a94fc and 88c12b1 `src/compat/writeRecordDualStore.js:13-19`). The core's `activeVaultAdd` for a v2 key appends the v1 projection itself.

### Edit of an old record, saved the apps' way, with the v1 append late

Test: `mixed: a re-key device edits an old record the way the apps save it, v2 then v1`. B (re-key) edits notes that R created before the epoch.

- If both appends reach R before its reconcile runs, R writes nothing and reads the record as its envelope.
- If the v1 append reaches R more than one debounce (100 ms) after v2:
  - The test forces this by holding B's v1 append. How often it happens on real devices was not measured. Possible triggers: the app suspended or killed between the two appends, or the two blocks reaching R in separate replication rounds.
  - R's reconcile sees its plaintext v1 (updatedAt 1) against the sealed v2, which the released mergeV1IntoV2 counts as updatedAt 0 (031d532 `recordNamespaces.js:245-248`). v1 wins.
  - R writes a mixed row: B's new ciphertext with R's old plaintext beside it. It becomes the v2 row on both devices.
  - R reads the old record and B reads its edit.
  - While R stays on 031d532, neither build's reconcile repairs it.
- R saves that stale record.
  - The shipped app rebuilds every saved record from id, type, vaultId, data, folder, isFavorite and createdAt, with a new updatedAt (lib-vault 24a94fc `src/utils/updateRecordsFactory.js:19-30`). Favourites and folder moves go through the same save (24a94fc `src/actions/updateRecords.js:83-113`).
  - An edit, favourite or folder move of that record on R replaces B's edit on both devices. B's edit is lost on every device.
  - A save that spreads the listed record would keep B's envelope instead. That path is not reachable from the shipped app.
- After R upgrades and joins the epoch, it decrypts the mixed row of a record it never saved and reads B's edit. Records R saved while on 031d532 read as R saved them.

### Epoch started on the re-key build

Test: `mixed: an epoch started on the re-key build leaves the released device out until it upgrades` (R, B, C).

- Before any epoch, both builds read each other's writes. The re-key devices list R as `uncovered`.
- B's epoch is sealed to B and C only: `members: [device-B, device-C], uncovered: [device-R]`.
- R still reads every item from before the epoch that nobody edited.
- New items, saved v2 first: R cannot read them, and its reconcile writes nothing.
  - 031d532 returns the envelope `{ $enc, e, n, c }` as the record, a list entry with no id, and ciphertext for the file.
- No crash, no logged error on R, no stall. B and C keep syncing and read every sealed item and file in full.
- R's writes reach B and C and read there, in plaintext: a note, and an edit of an old login saved v2 first.
- After R upgrades, a re-key device rotates to an epoch that includes R, and R reads everything.

What the app on R shows (read from code, not run):
- Lib-vault 24a94fc listRecords maps each record through toAppRecord, so an envelope becomes `{ $enc, e, n, c, schema: 2, data: {} }`, with no id, type or title.
- The desktop list renders rows with `key={record.id}` (desktop 9427ac8 `RecordListView.tsx:192`; the shipped desktop tree was not checked), so expect blank, untitled rows.
- Records hit by the late-v1 case show stale content instead.

### Clients that write record/ first

No current app saves this way; these orders need a client that writes `record/` directly. Test: `mixed: a client that saves record/ first races the other build for the v2 twin`. The gaps are forced by holding appends.

- A new record saved through its v1 key, with its v2 twin slow. R writes a plaintext twin: the v1 envelope plus `schema: 2, data: {}`.
  - If the re-key twin lands after it, nothing is lost.
  - If R's copy lands last, the re-key build reads the record without `schema` and `uris`. Neither reconcile repairs it, which the test checks after a reconcile on each side. The next save on a re-key build repairs it.
- R edits an old record through its v1 key, with its v2 twin slow, and B's reconcile writes a sealed merged twin that lands last.
  - R reads its own edit as an envelope only until its next reconcile.
  - That reconcile writes a mixed row (B's ciphertext plus R's edit), after which both sides read R's edit.

Not tested: R deleting a record it sees as an envelope; R upgrading while no re-key member is online; more than one 031d532 device in a vault that has an epoch.

## 3. Rollback (vault sealed by the re-key build, reopened by 031d532 on the same storage)

Test: `rollback: the released build reopens a vault the re-key build sealed`.

- 031d532 opens the vault with no error, its migration reports `alreadyMigrated`, and its reconcile writes nothing.
- Readable: everything from before the epoch, files included.
- Not readable: everything sealed after it, which comes back as envelopes, entries with no id, and ciphertext.
- Writes made on 031d532 are plaintext.
- Rolling forward again, every row reads as it did before the rollback, except what the rollback wrote (a note, and both rows of one edited login), which read as written. The epoch is the same.
- Only a single device was rolled back.

## 4. Revoke with a 031d532 device in the vault

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
