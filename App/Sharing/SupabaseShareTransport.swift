import Foundation
import Supabase
import SecretShareCore

/// ShareTransport backed by Supabase (Postgres + RLS + RPC functions in supabase/schema.sql).
/// Signs in anonymously on first use; the session persists in the Keychain.
final class SupabaseShareTransport: ShareTransport, @unchecked Sendable {
    private let client: SupabaseClient

    init(url: URL, anonKey: String) {
        client = SupabaseClient(supabaseURL: url, supabaseKey: anonKey)
    }

    // MARK: Rows

    private struct ProfileRow: Decodable {
        let userID: UUID
        let handle: String
        let boxPublicKey: String
        let signPublicKey: String

        enum CodingKeys: String, CodingKey {
            case userID = "user_id"
            case handle
            case boxPublicKey = "box_public_key"
            case signPublicKey = "sign_public_key"
        }

        var profile: DirectoryProfile? {
            guard let box = Data(base64Encoded: boxPublicKey),
                  let sign = Data(base64Encoded: signPublicKey) else { return nil }
            return DirectoryProfile(userID: userID, handle: handle, boxPublicKey: box, signPublicKey: sign)
        }
    }

    private struct ShareRow: Decodable {
        let id: UUID
        let senderID: UUID
        let recipientID: UUID
        let expiresAt: Int64
        let viewOnce: Bool
        let createdAt: Int64

        enum CodingKeys: String, CodingKey {
            case id
            case senderID = "sender_id"
            case recipientID = "recipient_id"
            case expiresAt = "expires_at"
            case viewOnce = "view_once"
            case createdAt = "created_at"
        }

        var summary: ShareSummary {
            ShareSummary(id: id, senderID: senderID, recipientID: recipientID,
                         expiresAtUnix: expiresAt, viewOnce: viewOnce, createdAtUnix: createdAt)
        }
    }

    private struct OpenRow: Decodable {
        let shareID: UUID
        let senderID: UUID
        let recipientID: UUID
        let expiresAt: Int64
        let viewOnce: Bool
        let createdAt: Int64
        let envelope: String
        let signature: String

        enum CodingKeys: String, CodingKey {
            case shareID = "share_id"
            case senderID = "sender_id"
            case recipientID = "recipient_id"
            case expiresAt = "expires_at"
            case viewOnce = "view_once"
            case createdAt = "created_at"
            case envelope
            case signature
        }
    }

    private static let profileColumns = "user_id,handle,box_public_key,sign_public_key"
    private static let shareColumns = "id,sender_id,recipient_id,expires_at,view_once,created_at"

    // MARK: ShareTransport

    func currentUserID() async throws -> UUID {
        if let session = try? await client.auth.session {
            return session.user.id
        }
        do {
            return try await client.auth.signInAnonymously().user.id
        } catch {
            throw VaultError.unlockerFailed(
                "Couldn't sign in to the sharing server. Check your connection and that anonymous sign-ins are enabled in Supabase. (\(error.localizedDescription))")
        }
    }

    func publishProfile(handle: String, boxPublicKey: Data, signPublicKey: Data) async throws {
        struct Params: Encodable {
            let p_handle: String
            let p_box_public_key: String
            let p_sign_public_key: String
        }
        _ = try await currentUserID()
        try await call {
            try await client.rpc("register_profile", params: Params(
                p_handle: handle,
                p_box_public_key: boxPublicKey.base64EncodedString(),
                p_sign_public_key: signPublicKey.base64EncodedString())).execute()
        }
    }

    func profile(userID: UUID) async throws -> DirectoryProfile? {
        let rows: [ProfileRow] = try await call {
            try await client.from("profiles").select(Self.profileColumns)
                .eq("user_id", value: userID).execute().value
        }
        return rows.first?.profile
    }

    func profile(handle: String) async throws -> DirectoryProfile? {
        let rows: [ProfileRow] = try await call {
            try await client.from("profiles").select(Self.profileColumns)
                .eq("handle", value: handle).execute().value
        }
        return rows.first?.profile
    }

    func send(_ share: OutgoingShare) async throws {
        struct Params: Encodable {
            let p_id: UUID
            let p_recipient_id: UUID
            let p_expires_at: Int64
            let p_view_once: Bool
            let p_envelope: String
            let p_signature: String
        }
        try await call {
            try await client.rpc("send_share", params: Params(
                p_id: share.id,
                p_recipient_id: share.recipientID,
                p_expires_at: share.expiresAtUnix,
                p_view_once: share.viewOnce,
                p_envelope: share.envelope.base64EncodedString(),
                p_signature: share.signature.base64EncodedString())).execute()
        }
    }

    func inbox() async throws -> [ShareSummary] {
        let me = try await currentUserID()
        let rows: [ShareRow] = try await call {
            try await client.from("shares").select(Self.shareColumns)
                .eq("recipient_id", value: me).execute().value
        }
        return rows.map(\.summary)
    }

    func sent() async throws -> [ShareSummary] {
        let me = try await currentUserID()
        let rows: [ShareRow] = try await call {
            try await client.from("shares").select(Self.shareColumns)
                .eq("sender_id", value: me).execute().value
        }
        return rows.map(\.summary)
    }

    func open(shareID: UUID) async throws -> SealedShare {
        struct Params: Encodable { let p_share_id: UUID }
        let rows: [OpenRow] = try await call {
            try await client.rpc("open_share", params: Params(p_share_id: shareID)).execute().value
        }
        guard let row = rows.first,
              let envelope = Data(base64Encoded: row.envelope),
              let signature = Data(base64Encoded: row.signature) else {
            throw VaultError.shareNotFound
        }
        let summary = ShareSummary(id: row.shareID, senderID: row.senderID, recipientID: row.recipientID,
                                   expiresAtUnix: row.expiresAt, viewOnce: row.viewOnce,
                                   createdAtUnix: row.createdAt)
        return SealedShare(summary: summary, envelope: envelope, signature: signature)
    }

    func revoke(shareID: UUID) async throws {
        try await call {
            try await client.from("shares").delete().eq("id", value: shareID).execute()
        }
    }

    // MARK: Errors

    @discardableResult
    private func call<T>(_ operation: () async throws -> T) async throws -> T {
        do {
            return try await operation()
        } catch let error as PostgrestError {
            switch error.code ?? "" {
            case "23505": throw VaultError.handleTaken
            case "P0002": throw VaultError.shareNotFound
            case "23503": throw VaultError.recipientNotFound
            case "23514": throw VaultError.invalidDuration
            default: throw VaultError.unlockerFailed("Server error: \(error.message)")
            }
        }
    }
}
