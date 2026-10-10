import XCTest
@testable import SecretShareCore

final class SharingTests: XCTestCase {
    private struct User {
        let vault: VaultService
        let sharing: SharingService
        let transport: InMemoryShareTransport
        let pins: InMemoryKeyPinStore
    }

    private var hub: InMemoryShareHub!

    override func setUp() {
        hub = InMemoryShareHub()
    }

    private func makeUser(_ handle: String, secretByte: UInt8) async throws -> User {
        let vault = VaultService(store: InMemoryVaultStore())
        _ = try await vault.setup(with: StaticUnlocker(secret: [UInt8](repeating: secretByte, count: 32)))
        let transport = InMemoryShareTransport(hub: hub)
        let pins = InMemoryKeyPinStore()
        let sharing = SharingService(vault: vault, transport: transport, pins: pins)
        try await sharing.register(handle: handle)
        return User(vault: vault, sharing: sharing, transport: transport, pins: pins)
    }

    private func assertThrows<T>(_ expected: VaultError,
                                 file: StaticString = #filePath, line: UInt = #line,
                                 _ operation: () async throws -> T) async {
        do {
            _ = try await operation()
            XCTFail("Expected \(expected)", file: file, line: line)
        } catch let error as VaultError {
            XCTAssertEqual(error, expected, file: file, line: line)
        } catch {
            XCTFail("Unexpected error \(error)", file: file, line: line)
        }
    }

    func testShareRoundTrip() async throws {
        let alice = try await makeUser("alice", secretByte: 1)
        let bob = try await makeUser("bob", secretByte: 2)
        let item = try await alice.vault.create(title: "WiFi", secret: "correct horse")

        let (bobProfile, status) = try await alice.sharing.findRecipient(handle: "@Bob")
        XCTAssertEqual(status, .new)
        try await alice.sharing.share(itemID: item.id, with: bobProfile, duration: 3600, viewOnce: false)

        let sent = try await alice.sharing.sent()
        XCTAssertEqual(sent.count, 1)
        XCTAssertEqual(sent.first?.counterparty?.handle, "bob")

        let inbox = try await bob.sharing.inbox()
        XCTAssertEqual(inbox.count, 1)
        XCTAssertEqual(inbox.first?.counterparty?.handle, "alice")

        let received = try await bob.sharing.open(inbox[0].summary)
        XCTAssertEqual(received.title, "WiFi")
        XCTAssertEqual(received.secret, "correct horse")
        XCTAssertEqual(received.sender.handle, "alice")
        XCTAssertFalse(received.viewOnce)

        // Not view-once: can open again until expiry.
        let again = try await bob.sharing.open(inbox[0].summary)
        XCTAssertEqual(again.secret, "correct horse")
    }

    func testViewOnceDeletedAfterOpen() async throws {
        let alice = try await makeUser("alice", secretByte: 1)
        let bob = try await makeUser("bob", secretByte: 2)
        let item = try await alice.vault.create(title: "PIN", secret: "1234")
        let (bobProfile, _) = try await alice.sharing.findRecipient(handle: "bob")
        try await alice.sharing.share(itemID: item.id, with: bobProfile, duration: 3600, viewOnce: true)

        let summary = try await bob.sharing.inbox()[0].summary
        let received = try await bob.sharing.open(summary)
        XCTAssertTrue(received.viewOnce)
        await assertThrows(.shareNotFound) { try await bob.sharing.open(summary) }
        let inbox = try await bob.sharing.inbox()
        XCTAssertTrue(inbox.isEmpty)
        let sent = try await alice.sharing.sent()
        XCTAssertTrue(sent.isEmpty)
    }

    func testExpiryHidesAndBlocks() async throws {
        let alice = try await makeUser("alice", secretByte: 1)
        let bob = try await makeUser("bob", secretByte: 2)
        let item = try await alice.vault.create(title: "t", secret: "s")
        let (bobProfile, _) = try await alice.sharing.findRecipient(handle: "bob")
        try await alice.sharing.share(itemID: item.id, with: bobProfile, duration: 300, viewOnce: false)
        let summary = try await bob.sharing.inbox()[0].summary

        // Client-side clock past expiry.
        await assertThrows(.shareExpired) { try await bob.sharing.open(summary, now: Date().addingTimeInterval(301)) }

        // Server clock past expiry.
        await hub.advanceClock(by: 301)
        let inbox = try await bob.sharing.inbox(now: Date().addingTimeInterval(301))
        XCTAssertTrue(inbox.isEmpty)
        await assertThrows(.shareNotFound) { try await bob.sharing.open(summary) }
    }

    func testServerCannotExtendExpiry() async throws {
        let alice = try await makeUser("alice", secretByte: 1)
        let bob = try await makeUser("bob", secretByte: 2)
        let item = try await alice.vault.create(title: "t", secret: "s")
        let (bobProfile, _) = try await alice.sharing.findRecipient(handle: "bob")
        try await alice.sharing.share(itemID: item.id, with: bobProfile, duration: 300, viewOnce: false)
        let id = try await bob.sharing.inbox()[0].summary.id

        await hub.extendExpiry(shareID: id, by: 86_400)
        let summary = try await bob.sharing.inbox()[0].summary
        await assertThrows(.shareSignatureInvalid) { try await bob.sharing.open(summary) }
    }

    func testTamperedEnvelopeRejected() async throws {
        let alice = try await makeUser("alice", secretByte: 1)
        let bob = try await makeUser("bob", secretByte: 2)
        let item = try await alice.vault.create(title: "t", secret: "s")
        let (bobProfile, _) = try await alice.sharing.findRecipient(handle: "bob")
        try await alice.sharing.share(itemID: item.id, with: bobProfile, duration: 300, viewOnce: false)
        let summary = try await bob.sharing.inbox()[0].summary

        await hub.tamperEnvelope(shareID: summary.id)
        await assertThrows(.shareSignatureInvalid) { try await bob.sharing.open(summary) }
    }

    func testOnlyRecipientCanDecrypt() async throws {
        let alice = try await makeUser("alice", secretByte: 1)
        let bob = try await makeUser("bob", secretByte: 2)
        let eve = try await makeUser("eve", secretByte: 3)
        let item = try await alice.vault.create(title: "t", secret: "s")
        let (bobProfile, _) = try await alice.sharing.findRecipient(handle: "bob")
        try await alice.sharing.share(itemID: item.id, with: bobProfile, duration: 300, viewOnce: false)

        // Even if Eve obtains the sealed share, her vault can't open it.
        let summary = try await bob.sharing.inbox()[0].summary
        let sealed = try await bob.transport.open(shareID: summary.id)
        let aliceProfile = try await bob.sharing.findRecipient(handle: "alice").profile
        await assertThrows(.shareSignatureInvalid) { try await eve.vault.openShare(sealed, sender: aliceProfile) }
        // And the server won't hand it to her.
        await assertThrows(.shareNotFound) { try await eve.transport.open(shareID: summary.id) }
    }

    func testRecipientKeyChangeBlocksUntilTrusted() async throws {
        let alice = try await makeUser("alice", secretByte: 1)
        _ = try await makeUser("bob", secretByte: 2)
        let item = try await alice.vault.create(title: "t", secret: "s")
        let (bobOld, _) = try await alice.sharing.findRecipient(handle: "bob")

        // Bob's directory entry is replaced with different keys (new vault, or a malicious server).
        let bobUserID = bobOld.userID
        let newVault = VaultService(store: InMemoryVaultStore())
        _ = try await newVault.setup(with: StaticUnlocker(secret: [UInt8](repeating: 9, count: 32)))
        let bob2 = SharingService(vault: newVault, transport: InMemoryShareTransport(hub: hub, userID: bobUserID))
        try await bob2.register(handle: "bob")

        let (bobNew, status) = try await alice.sharing.findRecipient(handle: "bob")
        XCTAssertEqual(status, .changed)
        await assertThrows(.recipientKeyChanged("bob")) {
            try await alice.sharing.share(itemID: item.id, with: bobNew, duration: 300, viewOnce: false)
        }
        await alice.sharing.trust(bobNew)
        try await alice.sharing.share(itemID: item.id, with: bobNew, duration: 300, viewOnce: false)
        let inbox = try await bob2.inbox()
        let received = try await bob2.open(inbox[0].summary)
        XCTAssertEqual(received.secret, "s")
    }

    func testRevokeBySender() async throws {
        let alice = try await makeUser("alice", secretByte: 1)
        let bob = try await makeUser("bob", secretByte: 2)
        let item = try await alice.vault.create(title: "t", secret: "s")
        let (bobProfile, _) = try await alice.sharing.findRecipient(handle: "bob")
        try await alice.sharing.share(itemID: item.id, with: bobProfile, duration: 300, viewOnce: false)
        let summary = try await alice.sharing.sent()[0].summary

        try await alice.sharing.revoke(summary.id)
        let inbox = try await bob.sharing.inbox()
        XCTAssertTrue(inbox.isEmpty)
        await assertThrows(.shareNotFound) { try await bob.sharing.open(summary) }
    }

    func testRegistration() async throws {
        let alice = try await makeUser("alice", secretByte: 1)
        let state = try await alice.sharing.registrationState()
        guard case .registered(let profile) = state else { return XCTFail("expected registered") }
        XCTAssertEqual(profile.handle, "alice")
        XCTAssertEqual(profile.fingerprint.count, 24) // 5 groups of 4 + 4 spaces

        await assertThrows(.invalidHandle) { try await alice.sharing.register(handle: "A!") }
        let other = VaultService(store: InMemoryVaultStore())
        _ = try await other.setup(with: StaticUnlocker(secret: [UInt8](repeating: 5, count: 32)))
        let otherSharing = SharingService(vault: other, transport: InMemoryShareTransport(hub: hub))
        await assertThrows(.handleTaken) { try await otherSharing.register(handle: "alice") }
    }

    func testInvalidDuration() async throws {
        let alice = try await makeUser("alice", secretByte: 1)
        _ = try await makeUser("bob", secretByte: 2)
        let item = try await alice.vault.create(title: "t", secret: "s")
        let (bobProfile, _) = try await alice.sharing.findRecipient(handle: "bob")
        await assertThrows(.invalidDuration) {
            try await alice.sharing.share(itemID: item.id, with: bobProfile, duration: 8 * 86_400, viewOnce: false)
        }
    }
}
