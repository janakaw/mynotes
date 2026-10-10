# SecretShare — Internal API (Step 2)

Status: implemented in `SecretShareCore` · 2026-10-05

## Layering

```
SwiftUI views ──► AppModel (@MainActor) ──► VaultService (actor)
                                               ├── CryptoEngine   (SodiumCryptoEngine)
                                               ├── VaultStore     (InMemory / File / CloudKit next)
                                               ├── VersionLedger  (InMemory / UserDefaults)
                                               └── Unlocker       (PasskeyPRF / DevLocal / Static)
```
Views never touch keys or ciphertext. Only `VaultService` holds the master key, in memory,
and wipes it on `lock()`.

## VaultService (actor)

| Call | Notes |
|---|---|
| `status() -> VaultStatus` | `.noVault` / `.locked` / `.unlocked` |
| `enrolledKinds() -> Set<UnlockerKind>` | readable while locked (public header data) |
| `setup(with: Unlocker) -> String` | creates MK, identity keys, primary + recovery entries; returns recovery code |
| `unlock(with: Unlocker)` | unlocker secret → HKDF → unwrap MK → open session |
| `unlock(recoveryCode:)` | same via recovery code |
| `lock()` | wipes keys and decrypted index |
| `list() -> [ItemSummary]` | from in-memory index |
| `failedItemIDs() -> [UUID]` | items that failed integrity/rollback on last load |
| `reloadIndex()` | re-fetch + verify all records |
| `item(id:) -> VaultItem` | decrypt + verify one |
| `create(title:secret:)` / `update(id:title:secret:)` / `delete(id:)` | |
| `unlockers()` / `addUnlocker(_:)` / `removeUnlocker(id:)` | manage wrapped MK copies |
| `regenerateRecoveryCode() -> String` | old code stops working |
| `identityFingerprint() -> String` | for key verification in sharing |
| `destroyVault()` | deletes header + items |

Errors: `VaultError` (user-facing `errorDescription`), e.g. `.wrongCredential`,
`.integrityFailure(id)`, `.rollbackDetected(id)`, `.secretTooLong`, `.cancelled`.

## Unlocker (protocol)

```swift
protocol Unlocker {
    var kind: UnlockerKind { get }                    // .passkeyPRF | .recoveryCode | .devLocal
    func enroll() async throws -> UnlockerEnrollment  // secret + credentialID + prfSalt
    func secret(for candidates: [UnlockerEntry]) async throws -> (secret: [UInt8], credentialID: Data?)
}
```
- `PasskeyPRFUnlocker` (App): registration with `.checkForSupport`, then assertion with
  per-credential PRF salts; returns `prf.first` bytes and the credential used.
- `DevLocalUnlocker` (App): random key in Keychain, `ThisDeviceOnly`. Simulator/testing only.
- `StaticUnlocker` (Core): fixed secret for unit tests.

## VaultStore (protocol)

```swift
loadHeader() / saveHeader(_:) / allItems() / item(id:) / save(_:) / delete(id:) / deleteAll()
```
Receives only `VaultHeader` and `ItemRecord` (ciphertext). `CloudKitVaultStore` will
implement the same protocol: VaultHeader → one record, ItemRecord → one record each.

## CryptoEngine (protocol)

`randomBytes`, `seal`/`open` (XChaCha20-Poly1305, nonce prepended), `pad`/`unpad`
(`sodium_pad`, 8 KiB block), `hkdfSHA256` (CryptoKit), `sha256`, `boxKeyPair` (X25519),
`signKeyPair` (Ed25519), `wipe`.

## Associated data (binds ciphertext to context)

| Ciphertext | Key | AD |
|---|---|---|
| wrapped MK | HKDF(secret, salt, "secretshare/unlock/v1/<kind>") | `ss/mk/v1/<entryID>` |
| wrapped identity | MK | `ss/identity/v1` |
| wrapped item key | MK | `ss/ik/v1/<itemID>` |
| item payload | item key | `ss/item/v1/<itemID>/<version>` |

## Integrity checks on every read
1. AEAD tag on item key and payload (tamper → `.integrityFailure`)
2. AD binds record ID + version (swap / version edit → `.integrityFailure`)
3. decrypted `version` must equal record `version`
4. `VersionLedger`: version lower than previously seen → `.rollbackDetected`;
   deleted items are tombstoned, so a resurrected record is rejected too.

## Changes vs. design review
- MVP storage is `FileVaultStore` (local, encrypted JSON) so the app runs end-to-end
  before CloudKit; CloudKit is a drop-in `VaultStore`.
- `DevLocalUnlocker` added so the Simulator works without a passkey domain.
- Padding block is 8 KiB (fits 1024 multi-byte characters plus JSON escaping).
- Removing an unlocker removes its wrapped MK copy; full revocation needs MK rotation (post-MVP).
