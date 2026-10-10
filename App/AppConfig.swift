import Foundation

enum AppConfig {
    /// Your passkey relying-party domain. Leave nil until you have a domain hosting
    /// /.well-known/apple-app-site-association with a "webcredentials" entry for this app,
    /// and the same domain in SecretShare.entitlements (webcredentials:<domain>).
    /// While nil, passkey options are hidden and the dev device-key unlocker is used.
    static let relyingPartyID: String? = nil // e.g. "secretshare.example.com"

    /// Supabase project (Dashboard ▸ Project Settings ▸ API). The anon/publishable key is
    /// safe to ship in the app; Row Level Security in supabase/schema.sql protects the data.
    /// While nil, sharing tabs show a "not configured" message.
    static let supabaseURL: String? = nil      // e.g. "https://abcdefgh.supabase.co"
    static let supabaseAnonKey: String? = nil  // e.g. "eyJhbGciOi..." or "sb_publishable_..."

    /// Seconds the copied secret stays on the clipboard.
    static let clipboardExpiry: TimeInterval = 60
}
