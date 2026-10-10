import Foundation

/// How a copy of the master key is unlocked.
public enum UnlockerKind: String, Codable, Sendable, CaseIterable {
    /// Passkey + WebAuthn PRF extension (production).
    case passkeyPRF
    /// Random recovery code the user writes down.
    case recoveryCode
    /// Random key in this device's Keychain. Development/Simulator only.
    case devLocal
}

/// One wrapped copy of the master key, stored in the vault header.
public struct UnlockerEntry: Codable, Identifiable, Sendable, Equatable {
    public let id: UUID
    public let kind: UnlockerKind
    public let label: String
    /// Passkey credential ID, or the Keychain account for devLocal.
    public let credentialID: Data?
    /// PRF input salt (passkeyPRF only).
    public let prfSalt: Data?
    public let hkdfSalt: Data
    /// Master key sealed with HKDF(unlocker secret).
    public let wrappedMK: Data
    public let created: Date
}

/// Single per-vault record. Contains no plaintext and no usable key.
public struct VaultHeader: Codable, Sendable, Equatable {
    public static let currentFormat = 1
    public var formatVersion: Int
    public var unlockers: [UnlockerEntry]
    /// X25519 secret key ‖ Ed25519 secret key, sealed with the master key.
    public var wrappedIdentity: Data
    public var boxPublicKey: Data
    public var signPublicKey: Data
}

/// What the storage backend sees for one item: ciphertext only.
public struct ItemRecord: Codable, Sendable, Equatable {
    public let id: UUID
    public let wrappedKey: Data
    public let payload: Data
    public let version: Int

    public init(id: UUID, wrappedKey: Data, payload: Data, version: Int) {
        self.id = id
        self.wrappedKey = wrappedKey
        self.payload = payload
        self.version = version
    }
}

/// A decrypted item, handed to the UI.
public struct VaultItem: Identifiable, Sendable, Equatable {
    public let id: UUID
    public let title: String
    public let secret: String
    public let created: Date
    public let modified: Date
    public let version: Int
}

/// Decrypted list-row data, kept in memory only while unlocked.
public struct ItemSummary: Identifiable, Sendable, Equatable, Hashable {
    public let id: UUID
    public let title: String
    public let modified: Date
    public let version: Int
}

public enum VaultStatus: Sendable, Equatable {
    case noVault
    case locked
    case unlocked
}

public enum Limits {
    public static let maxTitleLength = 100
    public static let maxSecretLength = 1024
    /// Every payload is padded to exactly this size before encryption.
    public static let paddedPayloadSize = 8192
}

/// Plaintext inside the encrypted payload.
struct ItemPlaintext: Codable, Equatable {
    var title: String
    var secret: String
    var created: Date
    var modified: Date
    var version: Int
}
