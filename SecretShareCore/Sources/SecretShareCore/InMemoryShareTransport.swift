import Foundation

/// In-memory "server" shared by several InMemoryShareTransport clients. For tests and previews.
/// Mirrors the Supabase rules: unique handles, recipient-only open, expiry hiding,
/// view-once delete-on-open, sender/recipient revoke.
public actor InMemoryShareHub {
    private var profiles: [UUID: DirectoryProfile] = [:]
    private var shares: [UUID: SealedShare] = [:]
    private var clockOffset: TimeInterval = 0

    public init() {}

    var now: Date { Date().addingTimeInterval(clockOffset) }

    /// Test helper: move the server clock forward.
    public func advanceClock(by seconds: TimeInterval) { clockOffset += seconds }

    /// Test helper: corrupt a stored envelope.
    public func tamperEnvelope(shareID: UUID) {
        guard let share = shares[shareID] else { return }
        var envelope = share.envelope
        envelope[envelope.startIndex + envelope.count / 2] ^= 0x01
        shares[shareID] = SealedShare(summary: share.summary, envelope: envelope, signature: share.signature)
    }

    /// Test helper: server tries to extend a share's expiry.
    public func extendExpiry(shareID: UUID, by seconds: Int64) {
        guard let share = shares[shareID] else { return }
        let s = share.summary
        let summary = ShareSummary(id: s.id, senderID: s.senderID, recipientID: s.recipientID,
                                   expiresAtUnix: s.expiresAtUnix + seconds, viewOnce: s.viewOnce,
                                   createdAtUnix: s.createdAtUnix)
        shares[shareID] = SealedShare(summary: summary, envelope: share.envelope, signature: share.signature)
    }

    func publish(_ profile: DirectoryProfile) throws {
        if let other = profiles.values.first(where: { $0.handle == profile.handle }),
           other.userID != profile.userID {
            throw VaultError.handleTaken
        }
        profiles[profile.userID] = profile
    }

    func profile(userID: UUID) -> DirectoryProfile? { profiles[userID] }
    func profile(handle: String) -> DirectoryProfile? { profiles.values.first { $0.handle == handle } }

    func send(_ share: OutgoingShare, from sender: UUID) throws {
        guard profiles[sender] != nil, profiles[share.recipientID] != nil else {
            throw VaultError.recipientNotFound
        }
        let summary = ShareSummary(id: share.id, senderID: sender, recipientID: share.recipientID,
                                   expiresAtUnix: share.expiresAtUnix, viewOnce: share.viewOnce,
                                   createdAtUnix: Int64(now.timeIntervalSince1970))
        shares[share.id] = SealedShare(summary: summary, envelope: share.envelope, signature: share.signature)
    }

    private func live(_ share: SealedShare) -> Bool { share.summary.expiresAt > now }

    func inbox(for user: UUID) -> [ShareSummary] {
        shares.values.filter { $0.summary.recipientID == user && live($0) }.map(\.summary)
    }

    func sent(by user: UUID) -> [ShareSummary] {
        shares.values.filter { $0.summary.senderID == user && live($0) }.map(\.summary)
    }

    func open(shareID: UUID, by user: UUID) throws -> SealedShare {
        guard let share = shares[shareID], share.summary.recipientID == user, live(share) else {
            throw VaultError.shareNotFound
        }
        if share.summary.viewOnce { shares[shareID] = nil }
        return share
    }

    func revoke(shareID: UUID, by user: UUID) {
        guard let share = shares[shareID] else { return }
        if share.summary.senderID == user || share.summary.recipientID == user {
            shares[shareID] = nil
        }
    }
}

public final class InMemoryShareTransport: ShareTransport, @unchecked Sendable {
    private let hub: InMemoryShareHub
    private let userID: UUID

    public init(hub: InMemoryShareHub, userID: UUID = UUID()) {
        self.hub = hub
        self.userID = userID
    }

    public func currentUserID() async throws -> UUID { userID }

    public func publishProfile(handle: String, boxPublicKey: Data, signPublicKey: Data) async throws {
        try await hub.publish(DirectoryProfile(userID: userID, handle: handle,
                                               boxPublicKey: boxPublicKey, signPublicKey: signPublicKey))
    }

    public func profile(userID: UUID) async throws -> DirectoryProfile? { await hub.profile(userID: userID) }
    public func profile(handle: String) async throws -> DirectoryProfile? { await hub.profile(handle: handle) }
    public func send(_ share: OutgoingShare) async throws { try await hub.send(share, from: userID) }
    public func inbox() async throws -> [ShareSummary] { await hub.inbox(for: userID) }
    public func sent() async throws -> [ShareSummary] { await hub.sent(by: userID) }
    public func open(shareID: UUID) async throws -> SealedShare { try await hub.open(shareID: shareID, by: userID) }
    public func revoke(shareID: UUID) async throws { await hub.revoke(shareID: shareID, by: userID) }
}
