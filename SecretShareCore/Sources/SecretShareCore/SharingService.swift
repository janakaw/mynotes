import Foundation

public enum RegistrationState: Sendable, Equatable {
    case unregistered
    case registered(DirectoryProfile)
    /// Published keys don't match this vault (e.g. vault was recreated). Re-publish to fix.
    case keysOutdated(DirectoryProfile)
}

/// Orchestrates sharing: directory lookups with key pinning, sealing/opening via the vault,
/// and transport calls. Plaintext only ever exists inside VaultService and the UI.
public actor SharingService {
    private let vault: VaultService
    private let transport: ShareTransport
    private let pins: KeyPinStore
    private var profileCache: [UUID: DirectoryProfile] = [:]

    public init(vault: VaultService, transport: ShareTransport, pins: KeyPinStore = InMemoryKeyPinStore()) {
        self.vault = vault
        self.transport = transport
        self.pins = pins
    }

    // MARK: Registration

    public func registrationState() async throws -> RegistrationState {
        let me = try await transport.currentUserID()
        guard let profile = try await transport.profile(userID: me) else { return .unregistered }
        let keys = try await vault.publicIdentity()
        if profile.boxPublicKey == keys.boxPublicKey && profile.signPublicKey == keys.signPublicKey {
            return .registered(profile)
        }
        return .keysOutdated(profile)
    }

    /// Publishes (or re-publishes) this vault's public keys under a username.
    @discardableResult
    public func register(handle rawHandle: String) async throws -> DirectoryProfile {
        let handle = rawHandle.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard DirectoryProfile.isValidHandle(handle) else { throw VaultError.invalidHandle }
        let keys = try await vault.publicIdentity()
        try await transport.publishProfile(handle: handle, boxPublicKey: keys.boxPublicKey,
                                           signPublicKey: keys.signPublicKey)
        let me = try await transport.currentUserID()
        let profile = DirectoryProfile(userID: me, handle: handle,
                                       boxPublicKey: keys.boxPublicKey, signPublicKey: keys.signPublicKey)
        profileCache[me] = profile
        pins.pin(profile.fingerprint, for: me)
        return profile
    }

    // MARK: Recipients and key pinning

    /// Looks up a user and checks their key against the pinned one (pinning it on first contact).
    public func findRecipient(handle rawHandle: String) async throws -> (profile: DirectoryProfile, status: PinStatus) {
        let handle = rawHandle.trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "@"))
        guard DirectoryProfile.isValidHandle(handle) else { throw VaultError.invalidHandle }
        guard let profile = try await transport.profile(handle: handle) else {
            throw VaultError.recipientNotFound
        }
        profileCache[profile.userID] = profile
        return (profile, checkPin(profile))
    }

    /// User confirmed a changed key (after verifying the fingerprint out of band).
    public func trust(_ profile: DirectoryProfile) {
        pins.pin(profile.fingerprint, for: profile.userID)
    }

    private func checkPin(_ profile: DirectoryProfile) -> PinStatus {
        guard let pinned = pins.pinnedFingerprint(for: profile.userID) else {
            pins.pin(profile.fingerprint, for: profile.userID)
            return .new
        }
        return pinned == profile.fingerprint ? .verified : .changed
    }

    private func requireTrusted(_ profile: DirectoryProfile) throws {
        if let pinned = pins.pinnedFingerprint(for: profile.userID), pinned != profile.fingerprint {
            throw VaultError.recipientKeyChanged(profile.handle)
        }
    }

    // MARK: Send

    public func share(itemID: UUID, with recipient: DirectoryProfile,
                      duration: TimeInterval, viewOnce: Bool, now: Date = Date()) async throws {
        guard duration >= 60, duration <= ShareDuration.sevenDays.seconds else {
            throw VaultError.invalidDuration
        }
        try requireTrusted(recipient)
        let me = try await transport.currentUserID()
        let expires = Int64(now.timeIntervalSince1970 + duration)
        let outgoing = try await vault.sealShare(itemID: itemID, shareID: UUID(), senderID: me,
                                                 recipient: recipient, expiresAtUnix: expires,
                                                 viewOnce: viewOnce)
        try await transport.send(outgoing)
    }

    // MARK: Lists

    public func inbox(now: Date = Date()) async throws -> [ShareListEntry] {
        let summaries = try await transport.inbox().filter { $0.expiresAt > now }
        return try await entries(summaries, counterparty: \.senderID)
    }

    public func sent(now: Date = Date()) async throws -> [ShareListEntry] {
        let summaries = try await transport.sent().filter { $0.expiresAt > now }
        return try await entries(summaries, counterparty: \.recipientID)
    }

    private func entries(_ summaries: [ShareSummary],
                         counterparty: KeyPath<ShareSummary, UUID>) async throws -> [ShareListEntry] {
        var result: [ShareListEntry] = []
        for summary in summaries.sorted(by: { $0.expiresAtUnix < $1.expiresAtUnix }) {
            let profile = try await cachedProfile(summary[keyPath: counterparty])
            result.append(ShareListEntry(summary: summary, counterparty: profile))
        }
        return result
    }

    private func cachedProfile(_ userID: UUID) async throws -> DirectoryProfile? {
        if let cached = profileCache[userID] { return cached }
        let profile = try await transport.profile(userID: userID)
        if let profile { profileCache[userID] = profile }
        return profile
    }

    // MARK: Open / revoke

    /// Checks the sender's key pin *before* downloading (view-once shares are deleted on download),
    /// then verifies signature + expiry and decrypts.
    public func open(_ summary: ShareSummary, now: Date = Date()) async throws -> ReceivedSecret {
        guard summary.expiresAt > now else { throw VaultError.shareExpired }
        profileCache[summary.senderID] = nil // always fetch fresh keys for verification
        guard let sender = try await cachedProfile(summary.senderID) else { throw VaultError.unknownSender }
        if checkPin(sender) == .changed { throw VaultError.senderKeyChanged(sender.handle) }

        let me = try await transport.currentUserID()
        let sealed = try await transport.open(shareID: summary.id)
        guard sealed.summary.recipientID == me,
              sealed.summary.id == summary.id,
              sealed.summary.senderID == sender.userID else {
            throw VaultError.shareSignatureInvalid
        }
        return try await vault.openShare(sealed, sender: sender, now: now)
    }

    /// Sender: cancel a share. Recipient: dismiss it. Deletes it from the server.
    public func revoke(_ shareID: UUID) async throws {
        try await transport.revoke(shareID: shareID)
    }
}
