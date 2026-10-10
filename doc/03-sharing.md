# SecretShare — Sharing with expiry (Step 4)

Status: implemented · 2026-10-05

## Flow

```
Alice's app                         Supabase                          Bob's app
───────────                         ────────                          ─────────
register "alice" ──publish X25519+Ed25519 public keys──► profiles
                                                         profiles ◄── register "bob"
find "bob" ◄──────────── bob's public keys ────────────── profiles
  pin fingerprint (TOFU)
seal(item) to bob's X25519 key
sign(id, alice, bob, expiry, viewOnce, H(envelope))
send_share() ─────────────────────────────────────────► shares + share_envelopes
                                                         (RLS: only bob/alice see row,
                                                          hidden after expires_at)
                                       inbox (metadata) ──────────────► list w/ countdown
                                                                          check alice's key pin
                                       open_share() ◄─────────────────── open
                                       (view-once → deleted in same txn)
                                       envelope + signature ───────────► verify signature (Ed25519)
                                                                          check expiry (signed)
                                                                          open sealed box
                                                                          show with live countdown
                                                                          (never saved to Bob's vault)
```

## What each party can see

| | Alice | Supabase / Apple | Bob | Eve (other user) |
|---|---|---|---|---|
| Secret text & title | ✔ | ✘ ciphertext only | ✔ until expiry | ✘ |
| Who shared with whom, when, expiry | ✔ | ✔ (metadata) | ✔ | ✘ (RLS) |
| Can extend expiry undetected | – | ✘ (signed) | – | – |
| Can swap Bob's key | – | could try → Alice sees "key changed" | – | – |

## Expiry: what is and isn't guaranteed
- **Guaranteed:** after expiry the server hides the row (RLS) and refuses `open_share`;
  the optional pg_cron job deletes it. Bob's app also refuses, using the signed expiry,
  even if the server misbehaves. View-once envelopes are deleted in the same database
  transaction that returns them.
- **Not possible to guarantee:** anything Bob already saw, copied or screenshotted.
  The app never stores received secrets, and the clipboard copy expires at
  min(60 s, time left), but no system can recall knowledge.

## Code map
- Core `Sharing.swift`: models, `ShareTransport` protocol, signing format, key pins
- Core `SharingService.swift`: register / find+pin / share / inbox / sent / open / revoke
- Core `VaultService` extension: `sealShare` / `openShare` (private keys stay inside the vault actor)
- Core `InMemoryShareTransport.swift`: test server with the same rules as Supabase
- Core tests `SharingTests.swift`: round trip, view-once, expiry (client + server clock),
  server can't extend expiry, tampered envelope, wrong recipient, key change, revoke,
  handle rules
- App `Sharing/SupabaseShareTransport.swift`: supabase-swift client (anonymous auth, RPCs)
- App `Views/SharingViews.swift`: tabs, register, inbox, sent, received-secret view, composer
- `supabase/schema.sql`: tables, RLS, `register_profile`, `send_share`, `open_share`

## Known limits / next
- Anonymous Supabase accounts: reinstalling the app creates a new account (username can be
  re-registered only if the old account is deleted). Next: Sign in with Apple.
- Metadata (who shares with whom, timing) is visible to the server.
- Recipient-side key changes surface as warnings; fingerprint comparison is manual.
