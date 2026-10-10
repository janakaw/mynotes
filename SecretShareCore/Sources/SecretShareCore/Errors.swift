import Foundation

public enum VaultError: Error, Equatable, LocalizedError {
    case vaultAlreadyExists
    case noVault
    case locked
    case noMatchingUnlocker
    case wrongCredential
    case invalidRecoveryCode
    case titleEmpty
    case titleTooLong
    case secretEmpty
    case secretTooLong
    case payloadTooLarge
    case itemNotFound
    case integrityFailure(UUID)
    case rollbackDetected(UUID)
    case corruptHeader
    case cannotRemoveLastUnlocker
    case cannotRemoveRecoveryCode
    case prfUnsupported
    case cancelled
    case unlockerFailed(String)
    case cryptoFailure(String)
    // Sharing
    case sharingNotConfigured
    case notRegistered
    case invalidHandle
    case handleTaken
    case recipientNotFound
    case recipientKeyChanged(String)
    case senderKeyChanged(String)
    case unknownSender
    case shareNotFound
    case shareExpired
    case shareSignatureInvalid
    case invalidDuration

    public var errorDescription: String? {
        switch self {
        case .vaultAlreadyExists: return "A vault already exists."
        case .noVault: return "No vault has been created yet."
        case .locked: return "The vault is locked."
        case .noMatchingUnlocker: return "This vault has no unlock method of that type."
        case .wrongCredential: return "That credential doesn't unlock this vault."
        case .invalidRecoveryCode: return "That isn't a valid recovery code. It should be 32 letters and digits."
        case .titleEmpty: return "Please enter a title."
        case .titleTooLong: return "Title must be \(Limits.maxTitleLength) characters or fewer."
        case .secretEmpty: return "Please enter a secret."
        case .secretTooLong: return "Secret must be \(Limits.maxSecretLength) characters or fewer."
        case .payloadTooLarge: return "This item is too large to store."
        case .itemNotFound: return "Item not found."
        case .integrityFailure: return "This item failed its integrity check. It may have been tampered with or corrupted."
        case .rollbackDetected: return "An older version of this item was served. It may have been rolled back or replayed."
        case .corruptHeader: return "The vault header is damaged or from an unsupported version."
        case .cannotRemoveLastUnlocker: return "You can't remove your only unlock method."
        case .cannotRemoveRecoveryCode: return "The recovery code can't be removed, only regenerated."
        case .prfUnsupported: return "This passkey doesn't support the PRF extension (iOS 18+ and iCloud Keychain required)."
        case .cancelled: return "Cancelled."
        case .unlockerFailed(let message): return message
        case .cryptoFailure(let message): return "Cryptography error: \(message)"
        case .sharingNotConfigured: return "Sharing isn't configured. Set the Supabase URL and key in AppConfig."
        case .notRegistered: return "Choose a username before sharing."
        case .invalidHandle: return "Usernames are 3–20 characters: a–z, 0–9 and _."
        case .handleTaken: return "That username is taken."
        case .recipientNotFound: return "No user with that username."
        case .recipientKeyChanged(let handle):
            return "@\(handle)'s security key has changed. Verify their fingerprint before sharing."
        case .senderKeyChanged(let handle):
            return "@\(handle)'s security key has changed. Verify their fingerprint before opening."
        case .unknownSender: return "The sender of this share no longer exists."
        case .shareNotFound: return "This share has expired, was already opened, or was revoked."
        case .shareExpired: return "This share has expired."
        case .shareSignatureInvalid: return "This share failed its authenticity check and was not opened."
        case .invalidDuration: return "Choose an expiry between 1 minute and 7 days."
        }
    }
}

public enum CryptoError: Error, Equatable {
    case authenticationFailed
    case failure(String)
}
