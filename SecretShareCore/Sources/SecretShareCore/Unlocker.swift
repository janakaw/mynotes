import Foundation

/// Result of creating a new unlock credential.
public struct UnlockerEnrollment: Sendable {
    /// High-entropy secret (≥ 16 bytes). HKDF turns it into the key that wraps the master key.
    public var secret: [UInt8]
    public var credentialID: Data?
    public var prfSalt: Data?
    public var label: String

    public init(secret: [UInt8], credentialID: Data?, prfSalt: Data?, label: String) {
        self.secret = secret
        self.credentialID = credentialID
        self.prfSalt = prfSalt
        self.label = label
    }
}

/// Something that can produce a high-entropy secret to unwrap the master key:
/// a passkey (PRF), a device-only Keychain key, a test stub...
public protocol Unlocker {
    var kind: UnlockerKind { get }

    /// Create a new credential and return its secret plus the public parameters to store.
    func enroll() async throws -> UnlockerEnrollment

    /// Produce the secret for one of the given header entries.
    /// Return the credential ID used, if known, so the vault can pick the matching entry.
    func secret(for candidates: [UnlockerEntry]) async throws -> (secret: [UInt8], credentialID: Data?)
}

/// Fixed-secret unlocker for tests and previews. Never use in production.
public final class StaticUnlocker: Unlocker {
    public let kind: UnlockerKind
    private let fixedSecret: [UInt8]

    public init(kind: UnlockerKind = .devLocal, secret: [UInt8]) {
        self.kind = kind
        self.fixedSecret = secret
    }

    public func enroll() async throws -> UnlockerEnrollment {
        UnlockerEnrollment(secret: fixedSecret, credentialID: nil, prfSalt: nil, label: "Static (test)")
    }

    public func secret(for candidates: [UnlockerEntry]) async throws -> (secret: [UInt8], credentialID: Data?) {
        (fixedSecret, nil)
    }
}
