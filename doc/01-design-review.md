# SecretShare — MVP Design Review (Step 1)

Status: draft v2 (passkey + PRF unlock) · 2026-10-05

## 0. Scope

MVP = a private, end-to-end encrypted vault of short secrets on iOS.

- Each item: **title** (≤ 100 chars) + **secret** (≤ 1024 chars).
- Unlock: **passkey with the WebAuthn PRF extension** (iOS 26+), Face ID / device
  passcode via the system passkey sheet. **No master password, no Argon2id.**
- Backup unlock: **recovery code** shown once at setup.
- Storage: **CloudKit private database** (mocked first).
- Crypto: **libsodium** via `swift-sodium` (SPM) + CryptoKit `HKDF` for key derivation.
- Supabase public-key directory and sharing: **step 4**, not MVP.

Hard rule: **nothing leaves the Core unencrypted.** CloudKit, Supabase and
Apple only ever see ciphertext, salts, credential IDs and public keys.

## 1. Layer diagram

```
┌──────────────────────────────────────────────────────────────┐
│ UI (SwiftUI)                                                 │
│  Setup (create passkey, show recovery code) · Unlock ·       │
│  Item list · Item editor                                     │
└──────────────────────────────┬───────────────────────────────┘
                               │ calls only VaultService
┌──────────────────────────────▼───────────────────────────────┐
│ CORE                                                         │
│  VaultService  – setup / unlock / lock / list / get /        │
│                  create / update / delete / addPasskey       │
│  Session       – unlocked keys, in memory only; wiped on lock│
│  LocalIndex    – decrypted titles + version high-water marks │
│                                                              │
│  ┌─────────────────┐ ┌──────────────────┐ ┌───────────────┐  │
│  │ CryptoEngine    │ │ Unlockers        │ │ Protocols     │  │
│  │ (libsodium +    │ │ → 32-byte secret │ │  VaultStore   │  │
│  │  CryptoKit HKDF)│ │  PasskeyPRF      │ │  KeyDirectory │  │
│  │ aead, box, sign,│ │  RecoveryCode    │ │   (step 4)    │  │
│  │ pad             │ │  Mock (tests)    │ │               │  │
│  └─────────────────┘ └────────┬─────────┘ └───────┬───────┘  │
└───────────────────────────────┼───────────────────┼──────────┘
                                │                   │ ciphertext only
               AuthenticationServices      ┌────────┴──────────────┐
               (passkey + PRF, iOS 18)     ▼                       ▼
               synced by iCloud Keychain   MockVaultStore   CloudKitVaultStore
                                           (MVP testing)    (private DB, zone "Vault")
                                                            SupabaseDirectory (step 4)
```

## 2. Key hierarchy

Same tree as discussed earlier — only the top layer (what unlocks MK) is
pluggable via `Unlocker`.

```
Passkey (iCloud Keychain, synced)        Recovery code (paper, shown once)
  │ PRF(prfSalt) → 32 B, computed          │ 256-bit random, base32 for display
  │ inside the authenticator, never sent    │
  ▼ HKDF-SHA256(info "ss/wrap/v1")         ▼ HKDF-SHA256(info "ss/recovery/v1")
Wrap Key WK_passkey                      Wrap Key WK_recovery
  └──────────────┬───────────────────────────┘
                 │ each wraps the same MK (XChaCha20-Poly1305)
                 ▼
Master Key (MK, 32 B random) – created once at setup
  ├─ wraps Identity keys: X25519 (encrypt) + Ed25519 (sign)   ← for sharing in step 4
  └─ wraps Item Key (IK, 32 B random, one per item)
        └─ encrypts item payload (XChaCha20-Poly1305)
```

Why this replaces Argon2id:
- Argon2id exists to slow down guessing of a **low-entropy human password**.
- PRF output and the recovery code are **full-strength random 256-bit secrets**;
  there's nothing to guess, so a fast KDF (HKDF) is correct.
- Consequence: the offline-guessing risk from the password design is gone.

Why MK stays random (indirection kept):
- Multiple unlockers (passkey, recovery code, later a hardware security key or
  a second passkey) each wrap the **same** MK.
- Adding/removing an unlocker = add/remove one wrapped copy of MK. No item
  re-encryption.

## 3. CloudKit records (private DB, custom zone "Vault")

```
VaultHeader   (exactly one, recordName = "vault-header")
  formatVersion   Int        1
  unlockers       [Unlocker entry]   (encoded list, see below)
  wrappedIdentity Bytes      X25519 + Ed25519 secret keys sealed with MK
  publicKeys      Bytes      X25519 pub + Ed25519 pub (not secret)

Unlocker entry
  kind            "passkeyPRF" | "recoveryCode"
  credentialID    Bytes?     passkey credential ID (passkeyPRF only)
  prfSalt         Bytes(32)? PRF input (passkeyPRF only)
  hkdfSalt        Bytes(32)
  wrappedMK       Bytes      MK sealed with this unlocker's WK
  created         Date

Item          (one per secret, recordName = item UUID)
  wrappedKey      Bytes      IK sealed with MK          (AD = itemID)
  payload         Bytes      sealed padded JSON         (AD = itemID ‖ version)
  version         Int        increases on each update
```

Payload plaintext (JSON, then `sodium_pad` to a fixed 6 KiB block):
`{ "title", "secret", "created", "modified", "version" }`

- Fixed padding → every item the same size; Apple can't infer secret length.
- AEAD associated data binds ciphertext to record ID and version (no swapping
  payloads between records, no silent replacement).
- `encryptedValues` used as defense in depth — not relied on.

## 4. Core flows

| Flow | Steps |
|---|---|
| **Setup** | check iCloud account → create passkey with PRF enabled (`ASAuthorizationPlatformPublicKeyCredentialProvider`, PRF input = random prfSalt) → if PRF unsupported, stop with a clear message → random MK + identity keys → derive WK_passkey, WK_recovery → wrap MK twice → save VaultHeader → show recovery code once, require user to confirm it |
| **Unlock** | fetch VaultHeader → passkey assertion with PRF(prfSalt) via allowCredentials = credentialID → HKDF → unwrap MK (fail = wrong/foreign passkey) → unwrap identity keys → load items → decrypt titles into LocalIndex |
| **New Apple device** | same passkey arrives via iCloud Keychain → same PRF output → normal Unlock. Nothing to re-enrol. |
| **Create** | new IK → encrypt padded payload (v1) → wrap IK with MK → save Item |
| **Update** | version+1 → re-encrypt with same IK → save (CloudKit change tag guards conflicts) |
| **Read** | fetch → unwrap IK → decrypt → reject if version < local high-water mark |
| **Delete** | delete Item record → remove from LocalIndex |
| **Recover** | enter recovery code → unwrap MK → create a new passkey → add unlocker entry, remove the lost one |
| **Lock** | wipe MK, identity keys, LocalIndex (`sodium_memzero`); on background + idle timeout |

Passkey without a login server: in this MVP the passkey is used only for
its PRF output, not to sign in to a backend. The WebAuthn challenge is
generated locally and the assertion signature is not verified anywhere.
Authentication to CloudKit is the user's Apple Account.

## 5. Review findings

**Good**
- UI depends only on `VaultService`; storage and unlock methods sit behind
  protocols, so the app runs end-to-end on mocks (`MockUnlocker` returns a
  fixed 32 bytes) before passkeys, CloudKit or Supabase are wired in.
- Server-blind: no plaintext or usable key leaves the device.
- No password to phish, forget, or brute-force offline.

**Risks / decisions**
1. **Associated Domains requirement.** Passkeys need a relying-party domain
   you control hosting `/.well-known/apple-app-site-association` with a
   `webcredentials` entry, plus the Associated Domains capability in Xcode.
   A static host is enough (no WebAuthn server for MVP).
2. **Verify PRF stability early.** Do a spike before building on it: create
   the passkey on iPhone A, run PRF with the same salt on iPhone/iPad B signed
   into the same Apple Account, confirm identical output. Must be on **real
   devices**; don't rely on the Simulator for PRF.
3. **iCloud Keychain off** → passkey is device-bound; a second device can't
   unlock without the recovery code. Detect and warn at setup.
4. **User deletes the passkey** in the Passwords app → only the recovery code
   can get back in. Lost passkey + lost recovery code = data gone, by design.
   Onboarding must say so plainly.
5. **Minimum iOS 26** (Liquid Glass UI; PRF API needs 18+). Requires Xcode 26.
6. **Deletion is "deleted for the user", not cryptographic shredding.** Old
   copies may linger in Apple's storage, readable only with MK. Epoch-key
   rotation (old keys kept outside CloudKit) deferred post-MVP.
7. **Concurrent edits.** CloudKit change-tag conflict → keep higher version,
   show a "changed elsewhere" notice.
8. **Memory hygiene.** Keep secrets as `Bytes` in Core; only build a `String`
   in the editor view.

**Simplified from earlier discussion**
- Per-item Ed25519 signatures dropped for MVP (AEAD + associated data already
  gives integrity when all keys are the user's own). Return with sharing.
- Identity keypairs still generated at setup so sharing needs no migration.

**Deferred (post-MVP)**
Sharing via `CKShare` · Supabase key directory · key pinning / safety numbers
· hardware security key as extra unlocker · epoch rotation · attachments.

## 6. Tech choices

| Concern | Choice |
|---|---|
| Language / UI | Swift 6, SwiftUI, **iOS 26+** |
| Unlock | AuthenticationServices passkey + PRF extension |
| Key derivation | CryptoKit `HKDF<SHA256>` (no Argon2id needed) |
| Crypto | `swift-sodium` (jedisct1) via SPM |
| Symmetric | `crypto_aead_xchacha20poly1305_ietf` (24-byte random nonce stored with ciphertext) |
| Asymmetric (step 4) | `crypto_box_seal` (X25519), `crypto_sign` (Ed25519) |
| Storage | CloudKit private DB, custom zone; `CKSyncEngine` later if needed |
| Testing | XCTest against `MockVaultStore` + `MockUnlocker`; PRF spike on 2 real devices |

## Next: Step 2 — internal API
Define `VaultService`, `Unlocker`, `CryptoEngine`, `VaultStore`, `KeyDirectory`
Swift protocols, error types, and the item model.
