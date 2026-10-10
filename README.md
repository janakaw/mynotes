# SecretShare (MVP)

Private, end-to-end encrypted vault of short secrets (title + up to 1024 chars) on iOS.
Design: `doc/01-design-review.md` · Internal API: `doc/02-internal-api.md`

```
SecretShareCore/   Swift package: crypto (libsodium), key hierarchy, VaultService, stores, tests
App/               SwiftUI iOS app: views, AppModel, unlockers (passkey PRF, dev device key)
project.yml        XcodeGen spec that generates SecretShare.xcodeproj
```

## Quick start

Requires macOS Tahoe 26.2+ (or Sequoia 15.6+ with Xcode 26.3), Xcode 26, and XcodeGen.

```sh
# one-time
brew install xcodegen

# generate the Xcode project and open it
cd ~/Code/secretshare
xcodegen
open SecretShare.xcodeproj
```

Then in Xcode: pick an iOS 26 simulator (or your iPhone) and press **⌘R**.

Re-run `xcodegen` whenever files are added/renamed or `project.yml` changes.
`SecretShare.xcodeproj` is generated, so it isn't in git.

Run the core tests: `cd SecretShareCore && swift test`

## 1. Run the core tests (no device needed)

```sh
cd SecretShareCore
swift test
```
Covers: setup/unlock, wrong credential, recovery code, unlocker add/remove, update/delete,
validation limits, uniform payload size, no plaintext in storage, tamper / swap / version
tamper / rollback / resurrected-delete detection, file-store persistence.

## 2. Run the app in the Simulator

```sh
brew install xcodegen          # once
# edit project.yml: DEVELOPMENT_TEAM, bundle IDs
xcodegen
open SecretShare.xcodeproj
```
Pick an iPhone simulator (iOS 26+) and Run. With `AppConfig.relyingPartyID = nil`
the app uses the **dev device key** (random key in the Simulator's Keychain) so you can
test everything except passkeys: create vault → note recovery code → add/edit/delete
secrets → lock (button or background the app) → unlock → recovery-code unlock →
add/remove unlock methods → delete vault.

Data is stored as encrypted JSON files under the app's Application Support/Vault folder.
To see exactly what a server would see, find it with
`xcrun simctl get_app_container booted com.yourname.secretshare data`.

### Without XcodeGen
New Xcode project → iOS App (SwiftUI) named SecretShare → delete its generated
`ContentView.swift` and app file → drag in the `App/` folder → File ▸ Add Package
Dependencies ▸ Add Local… ▸ `SecretShareCore` → Build Settings: iOS Deployment Target 18.0,
Swift Language Version 5, **Default Actor Isolation = nonisolated** (Xcode 26 templates
default to MainActor) → add the Associated Domains capability.

## 3. Turn on passkeys (real iPhone)

1. A domain you control, served over HTTPS, with this file at
   `https://<domain>/.well-known/apple-app-site-association` (JSON, no redirects):
   ```json
   { "webcredentials": { "apps": [ "<TEAMID>.com.yourname.secretshare" ] } }
   ```
2. `project.yml` entitlement → `webcredentials:<domain>` (re-run `xcodegen`).
   While developing you can use `webcredentials:<domain>?mode=developer` and enable
   Settings ▸ Developer ▸ Associated Domains Development on the iPhone to skip Apple's CDN cache.
3. `App/AppConfig.swift` → `relyingPartyID = "<domain>"`.
4. Run on an iPhone with iOS 26+, signed into iCloud with iCloud Keychain on.

### PRF stability spike (do this before relying on passkeys)
Settings ▸ Diagnostics ▸ PRF stability test:
1. iPhone A: "Create test passkey", then "Evaluate PRF" → note fingerprint.
2. iPad/iPhone B, same Apple Account: "Evaluate PRF", pick the same passkey.
3. Fingerprints must match. If they do, the passkey can unlock the vault on every device.

## 4. Turn on sharing (Supabase)

1. Create a free project at supabase.com.
2. Authentication ▸ Sign In / Providers ▸ enable **Allow anonymous sign-ins**.
3. SQL Editor ▸ paste `supabase/schema.sql` ▸ Run. (Optional: enable pg_cron and run the
   commented purge job at the bottom.)
4. Project Settings ▸ API ▸ copy the Project URL and anon/publishable key into
   `App/AppConfig.swift` (`supabaseURL`, `supabaseAnonKey`).
5. `xcodegen` again (adds the supabase-swift package), build.

Test with two users: run the app on two different simulators (e.g. iPhone 16 and
iPhone 16 Pro). Each creates a vault and picks a username in the Received tab.
On one, open a secret ▸ Share ▸ enter the other's username ▸ pick expiry / view once ▸ Send.
The other sees it under Received with a countdown.

How sharing works: `doc/03-sharing.md`.

## Status
- [x] Step 1 design review
- [x] Step 2 internal API (Core package + tests)
- [x] Step 3 MVP UI (local file store, dev unlocker, passkey PRF unlocker)
- [ ] CloudKitVaultStore
- [x] Step 4 Supabase key directory + sharing with expiry / view once
- [ ] Sign in with Apple (replace anonymous accounts)
