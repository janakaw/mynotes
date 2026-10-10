import Foundation
import CryptoKit

// MARK: - Directory

/// A user's public identity as published in the key directory.
public struct DirectoryProfile: Codable, Sendable, Hashable, Identifiable {
    public let userID: UUID
    public let handle: String
    public let boxPublicKey: Data
    public let signPublicKey: Data

    public var id: UUID { userID }

    public init(userID: UUID, handle: String, boxPublicKey: Data, signPublicKey: Data) {
        self.userID = userID
        self.handle = handle
        self.boxPublicKey = boxPublicKey
        self.signPublicKey = signPublicKey
    }

    /// Human-comparable fingerprint of both public keys, e.g. "3F2A 9C01 …" (10 bytes).
    public var fingerprint: String {
        let digest = SHA256.hash(data: boxPublicKey + signPublicKey)
        let hex = digest.prefix(10).map { String(format: "%02X", $0) }
        return stride(from: 0, to: hex.count, by: 2).map { hex[$0] + hex[$0 + 1] }.joined(separator: " ")
    }

    public static func isValidHandle(_ handle: String) -> Bool {
        handle.range(of: "^[a-z0-9_]{3,20}$", options: .regularExpression) != nil
    }
}

// MARK: - Shares

public enum ShareDuration: String, CaseIterable, Identifiable, Sendable {
    case fiveMinutes, oneHour, oneDay, sevenDays

    public var id: String { rawValue }

    public var seconds: TimeInterval {
        switch self {
        case .fiveMinutes: return 5 * 60
        case .oneHour: return 3600
        case .oneDay: return 86_400
        case .sevenDays: return 7 * 86_400
        }
    }

    public var label: String {
        switch self {
        case .fiveMinutes: return "5 minutes"
        case .oneHour: return "1 hour"
        case .oneDay: return "24 hours"
        case .sevenDays: return "7 days"
        }
    }
}

/// Share metadata visible to sender, recipient and the server. Contains no secret data.
public struct ShareSummary: Sendable, Hashable, Identifiable {
    public let id: UUID
    public let senderID: UUID
    public let recipientID: UUID
    /// Unix seconds. Covered by the sender's signature.
    public let expiresAtUnix: Int64
    public let viewOnce: Bool
    public let createdAtUnix: Int64

    public var expiresAt: Date { Date(timeIntervalSince1970: TimeInterval(expiresAtUnix)) }
    public var createdAt: Date { Date(timeIntervalSince1970: TimeInterval(createdAtUnix)) }

    public init(id: UUID, senderID: UUID, recipientID: UUID, expiresAtUnix: Int64,
                viewOnce: Bool, createdAtUnix: Int64) {
        self.id = id
        self.senderID = senderID
        self.recipientID = recipientID
        self.expiresAtUnix = expiresAtUnix
        self.viewOnce = viewOnce
        self.createdAtUnix = createdAtUnix
    }
}

/// What the sender uploads.
public struct OutgoingShare: Sendable, Equatable {
    public let id: UUID
    public let recipientID: UUID
    public let expiresAtUnix: Int64
    public let viewOnce: Bool
    /// Sealed box to the recipient's X25519 key.
    public let envelope: Data
    /// Sender's Ed25519 signature over `ShareSigning.message`.
    public let signature: Data
}

/// What the recipient downloads when opening.
public struct SealedShare: Sendable, Equatable {
    public let summary: ShareSummary
    public let envelope: Data
    public let signature: Data

    public init(summary: ShareSummary, envelope: Data, signature: Data) {
        self.summary = summary
        self.envelope = envelope
        self.signature = signature
    }
}

/// A decrypted share. Held in memory only; never written to the recipient's vault.
public struct ReceivedSecret: Sendable, Equatable, Identifiable {
    public let shareID: UUID
    public let title: String
    public let secret: String
    public let sender: DirectoryProfile
    public let sharedAt: Date
    public let expiresAt: Date
    public let viewOnce: Bool

    public var id: UUID { shareID }
}

/// List row: a share plus the other party's profile (sender for inbox, recipient for sent).
public struct ShareListEntry: Sendable, Hashable, Identifiable {
    public let summary: ShareSummary
    public let counterparty: DirectoryProfile?
    public var id: UUID { summary.id }
}

/// Plaintext inside the sealed envelope.
struct SharePlaintext: Codable {
    var title: String
    var secret: String
    var sharedAt: Date
}

/// Canonical bytes the sender signs. Binds the envelope to share ID, both parties,
/// the expiry and the view-once flag, so the server can't redirect, extend or replay it.
enum ShareSigning {
    static func message(shareID: UUID, senderID: UUID, recipientID: UUID,
                        expiresAtUnix: Int64, viewOnce: Bool, envelopeHash: [UInt8]) -> [UInt8] {
        let header = [
            "ss/share/v1",
            shareID.uuidString,
            senderID.uuidString,
            recipientID.uuidString,
            String(expiresAtUnix),
            viewOnce ? "1" : "0",
        ].joined(separator: "\n") + "\n"
        return Array(header.utf8) + envelopeHash
    }
}

// MARK: - Transport

/// Moves public keys and sealed shares between users. Never sees plaintext or private keys.
/// Implementations: InMemoryShareTransport (tests), SupabaseShareTransport (app).
public protocol ShareTransport: Sendable {
    func currentUserID() async throws -> UUID
    func publishProfile(handle: String, boxPublicKey: Data, signPublicKey: Data) async throws
    func profile(userID: UUID) async throws -> DirectoryProfile?
    func profile(handle: String) async throws -> DirectoryProfile?
    func send(_ share: OutgoingShare) async throws
    func inbox() async throws -> [ShareSummary]
    func sent() async throws -> [ShareSummary]
    /// Returns the sealed share. For view-once shares the server deletes it in the same step.
    func open(shareID: UUID) async throws -> SealedShare
    func revoke(shareID: UUID) async throws
}

// MARK: - Key pinning (trust on first use)

public protocol KeyPinStore: AnyObject {
    func pinnedFingerprint(for userID: UUID) -> String?
    func pin(_ fingerprint: String, for userID: UUID)
    func removeAll()
}

public final class InMemoryKeyPinStore: KeyPinStore {
    private var pins: [UUID: String] = [:]
    public init() {}
    public func pinnedFingerprint(for userID: UUID) -> String? { pins[userID] }
    public func pin(_ fingerprint: String, for userID: UUID) { pins[userID] = fingerprint }
    public func removeAll() { pins.removeAll() }
}

public final class UserDefaultsKeyPinStore: KeyPinStore {
    private let defaults: UserDefaults
    private let key: String

    public init(defaults: UserDefaults = .standard, key: String = "secretshare.keyPins") {
        self.defaults = defaults
        self.key = key
    }

    private var map: [String: String] {
        get { defaults.dictionary(forKey: key) as? [String: String] ?? [:] }
        set { defaults.set(newValue, forKey: key) }
    }

    public func pinnedFingerprint(for userID: UUID) -> String? { map[userID.uuidString] }

    public func pin(_ fingerprint: String, for userID: UUID) {
        var m = map
        m[userID.uuidString] = fingerprint
        map = m
    }

    public func removeAll() { defaults.removeObject(forKey: key) }
}

public enum PinStatus: Sendable, Equatable {
    /// First contact: key was just pinned.
    case new
    /// Matches the previously pinned key.
    case verified
    /// Differs from the pinned key. Not trusted until the user confirms.
    case changed
}
