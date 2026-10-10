import XCTest
@testable import SecretShareCore

final class VaultServiceTests: XCTestCase {
    private let secretA = [UInt8](repeating: 0xA1, count: 32)
    private let secretB = [UInt8](repeating: 0xB2, count: 32)

    private func makeVault(_ store: InMemoryVaultStore = InMemoryVaultStore(),
                           ledger: VersionLedger = InMemoryVersionLedger()) -> VaultService {
        VaultService(store: store, ledger: ledger)
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

    // MARK: Setup / unlock

    func testSetupCreateLockUnlockRoundTrip() async throws {
        let vault = makeVault()
        var status = try await vault.status()
        XCTAssertEqual(status, .noVault)

        let code = try await vault.setup(with: StaticUnlocker(secret: secretA))
        XCTAssertEqual(code.replacingOccurrences(of: "-", with: "").count, 32)

        let summary = try await vault.create(title: "Bank", secret: "hunter2")
        await vault.lock()
        status = try await vault.status()
        XCTAssertEqual(status, .locked)

        try await vault.unlock(with: StaticUnlocker(secret: secretA))
        let item = try await vault.item(id: summary.id)
        XCTAssertEqual(item.title, "Bank")
        XCTAssertEqual(item.secret, "hunter2")
        XCTAssertEqual(item.version, 1)
        let list = try await vault.list()
        XCTAssertEqual(list.map(\.title), ["Bank"])
    }

    func testSetupTwiceFails() async throws {
        let vault = makeVault()
        _ = try await vault.setup(with: StaticUnlocker(secret: secretA))
        await assertThrows(.vaultAlreadyExists) { try await vault.setup(with: StaticUnlocker(secret: secretA)) }
    }

    func testWrongSecretFails() async throws {
        let vault = makeVault()
        _ = try await vault.setup(with: StaticUnlocker(secret: secretA))
        await vault.lock()
        await assertThrows(.wrongCredential) { try await vault.unlock(with: StaticUnlocker(secret: secretB)) }
    }

    func testLockedOperationsThrow() async throws {
        let vault = makeVault()
        _ = try await vault.setup(with: StaticUnlocker(secret: secretA))
        await vault.lock()
        await assertThrows(.locked) { try await vault.create(title: "x", secret: "y") }
        await assertThrows(.locked) { try await vault.list() }
    }

    func testRecoveryCodeUnlock() async throws {
        let vault = makeVault()
        let code = try await vault.setup(with: StaticUnlocker(secret: secretA))
        let summary = try await vault.create(title: "Email", secret: "pw")
        await vault.lock()

        // Tolerant input: lowercase, no dashes, spaces.
        let messy = code.lowercased().replacingOccurrences(of: "-", with: " ")
        try await vault.unlock(recoveryCode: messy)
        let item = try await vault.item(id: summary.id)
        XCTAssertEqual(item.secret, "pw")

        await vault.lock()
        await assertThrows(.invalidRecoveryCode) { try await vault.unlock(recoveryCode: "not-a-code") }
        let wrong = RecoveryCode.encode([UInt8](repeating: 7, count: RecoveryCode.byteCount))
        await assertThrows(.wrongCredential) { try await vault.unlock(recoveryCode: wrong) }
    }

    func testRegenerateRecoveryCode() async throws {
        let vault = makeVault()
        let oldCode = try await vault.setup(with: StaticUnlocker(secret: secretA))
        let newCode = try await vault.regenerateRecoveryCode()
        XCTAssertNotEqual(oldCode, newCode)
        await vault.lock()
        await assertThrows(.wrongCredential) { try await vault.unlock(recoveryCode: oldCode) }
        try await vault.unlock(recoveryCode: newCode)
    }

    // MARK: Unlocker management

    func testAddAndRemoveUnlockers() async throws {
        let vault = makeVault()
        _ = try await vault.setup(with: StaticUnlocker(secret: secretA))
        let first = try await vault.unlockers().first { $0.kind == .devLocal }!
        _ = try await vault.addUnlocker(StaticUnlocker(secret: secretB))

        await vault.lock()
        try await vault.unlock(with: StaticUnlocker(secret: secretB))

        try await vault.removeUnlocker(id: first.id)
        await vault.lock()
        await assertThrows(.wrongCredential) { try await vault.unlock(with: StaticUnlocker(secret: secretA)) }
        try await vault.unlock(with: StaticUnlocker(secret: secretB))

        let remaining = try await vault.unlockers()
        let last = remaining.first { $0.kind == .devLocal }!
        await assertThrows(.cannotRemoveLastUnlocker) { try await vault.removeUnlocker(id: last.id) }
        let recovery = remaining.first { $0.kind == .recoveryCode }!
        await assertThrows(.cannotRemoveRecoveryCode) { try await vault.removeUnlocker(id: recovery.id) }
    }

    // MARK: Items

    func testUpdateAndDelete() async throws {
        let vault = makeVault()
        _ = try await vault.setup(with: StaticUnlocker(secret: secretA))
        let s = try await vault.create(title: "A", secret: "one")
        let updated = try await vault.update(id: s.id, title: "A2", secret: "two")
        XCTAssertEqual(updated.version, 2)
        let item = try await vault.item(id: s.id)
        XCTAssertEqual(item.title, "A2")
        XCTAssertEqual(item.secret, "two")
        XCTAssertEqual(item.created, s.modified)

        try await vault.delete(id: s.id)
        await assertThrows(.itemNotFound) { try await vault.item(id: s.id) }
        let list = try await vault.list()
        XCTAssertTrue(list.isEmpty)
    }

    func testValidation() async throws {
        let vault = makeVault()
        _ = try await vault.setup(with: StaticUnlocker(secret: secretA))
        await assertThrows(.titleEmpty) { try await vault.create(title: "  ", secret: "x") }
        await assertThrows(.secretEmpty) { try await vault.create(title: "t", secret: "") }
        await assertThrows(.titleTooLong) {
            try await vault.create(title: String(repeating: "t", count: 101), secret: "x")
        }
        await assertThrows(.secretTooLong) {
            try await vault.create(title: "t", secret: String(repeating: "s", count: 1025))
        }
        // Worst-case realistic content at the limit still fits the padded block.
        _ = try await vault.create(title: String(repeating: "é", count: 100),
                                   secret: String(repeating: "\u{1F512}", count: 1024))
        _ = try await vault.create(title: "quotes", secret: String(repeating: "\"", count: 1024))
    }

    func testAllPayloadsSameSize() async throws {
        let store = InMemoryVaultStore()
        let vault = makeVault(store)
        _ = try await vault.setup(with: StaticUnlocker(secret: secretA))
        let short = try await vault.create(title: "s", secret: "x")
        let long = try await vault.create(title: "l", secret: String(repeating: "y", count: 1024))
        let r1 = try await store.item(id: short.id)!
        let r2 = try await store.item(id: long.id)!
        XCTAssertEqual(r1.payload.count, r2.payload.count)
    }

    func testStoreNeverSeesPlaintext() async throws {
        let store = InMemoryVaultStore()
        let vault = makeVault(store)
        _ = try await vault.setup(with: StaticUnlocker(secret: secretA))
        let s = try await vault.create(title: "VisibleTitle", secret: "VisibleSecret")
        let record = try await store.item(id: s.id)!
        let blob = record.payload + record.wrappedKey
        XCTAssertNil(blob.range(of: Data("VisibleTitle".utf8)))
        XCTAssertNil(blob.range(of: Data("VisibleSecret".utf8)))
    }

    // MARK: Integrity

    func testTamperedPayloadDetected() async throws {
        let store = InMemoryVaultStore()
        let vault = makeVault(store)
        _ = try await vault.setup(with: StaticUnlocker(secret: secretA))
        let s = try await vault.create(title: "t", secret: "x")

        let record = try await store.item(id: s.id)!
        var payload = record.payload
        payload[payload.count / 2] ^= 0x01
        try await store.save(ItemRecord(id: record.id, wrappedKey: record.wrappedKey,
                                        payload: payload, version: record.version))

        await assertThrows(.integrityFailure(s.id)) { try await vault.item(id: s.id) }
        try await vault.reloadIndex()
        let failed = try await vault.failedItemIDs()
        XCTAssertEqual(failed, [s.id])
    }

    func testSwappedPayloadDetected() async throws {
        let store = InMemoryVaultStore()
        let vault = makeVault(store)
        _ = try await vault.setup(with: StaticUnlocker(secret: secretA))
        let a = try await vault.create(title: "a", secret: "aaa")
        let b = try await vault.create(title: "b", secret: "bbb")
        let ra = try await store.item(id: a.id)!
        let rb = try await store.item(id: b.id)!
        // Put b's ciphertext under a's record ID.
        try await store.save(ItemRecord(id: a.id, wrappedKey: rb.wrappedKey, payload: rb.payload, version: ra.version))
        await assertThrows(.integrityFailure(a.id)) { try await vault.item(id: a.id) }
    }

    func testVersionFieldTamperDetected() async throws {
        let store = InMemoryVaultStore()
        let vault = makeVault(store)
        _ = try await vault.setup(with: StaticUnlocker(secret: secretA))
        let s = try await vault.create(title: "t", secret: "x")
        let r = try await store.item(id: s.id)!
        try await store.save(ItemRecord(id: r.id, wrappedKey: r.wrappedKey, payload: r.payload, version: 5))
        await assertThrows(.integrityFailure(s.id)) { try await vault.item(id: s.id) }
    }

    func testRollbackDetected() async throws {
        let store = InMemoryVaultStore()
        let vault = makeVault(store)
        _ = try await vault.setup(with: StaticUnlocker(secret: secretA))
        let s = try await vault.create(title: "t", secret: "v1")
        let v1 = try await store.item(id: s.id)!
        _ = try await vault.update(id: s.id, title: "t", secret: "v2")

        try await store.save(v1) // server serves the old version
        await assertThrows(.rollbackDetected(s.id)) { try await vault.item(id: s.id) }
    }

    func testResurrectedDeletedItemDetected() async throws {
        let store = InMemoryVaultStore()
        let vault = makeVault(store)
        _ = try await vault.setup(with: StaticUnlocker(secret: secretA))
        let s = try await vault.create(title: "t", secret: "x")
        let old = try await store.item(id: s.id)!
        try await vault.delete(id: s.id)

        try await store.save(old) // server brings it back
        try await vault.reloadIndex()
        let failed = try await vault.failedItemIDs()
        XCTAssertEqual(failed, [s.id])
        let list = try await vault.list()
        XCTAssertTrue(list.isEmpty)
    }

    func testFileStorePersistsAcrossInstances() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let ledger = InMemoryVersionLedger()

        let v1 = VaultService(store: FileVaultStore(directory: dir), ledger: ledger)
        _ = try await v1.setup(with: StaticUnlocker(secret: secretA))
        let s = try await v1.create(title: "Persisted", secret: "yes")

        let v2 = VaultService(store: FileVaultStore(directory: dir), ledger: ledger)
        let status = try await v2.status()
        XCTAssertEqual(status, .locked)
        try await v2.unlock(with: StaticUnlocker(secret: secretA))
        let item = try await v2.item(id: s.id)
        XCTAssertEqual(item.secret, "yes")
    }
}

final class RecoveryCodeTests: XCTestCase {
    func testRoundTrip() {
        for _ in 0..<200 {
            let bytes = (0..<RecoveryCode.byteCount).map { _ in UInt8.random(in: 0...255) }
            let code = RecoveryCode.encode(bytes)
            XCTAssertEqual(code.count, 32 + 7) // 8 groups of 4 + 7 dashes
            XCTAssertEqual(RecoveryCode.decode(code), bytes)
        }
    }

    func testAmbiguousCharactersAccepted() {
        let bytes = [UInt8](repeating: 0, count: RecoveryCode.byteCount)
        let code = RecoveryCode.encode(bytes) // all zeros
        XCTAssertEqual(RecoveryCode.decode(code.replacingOccurrences(of: "0", with: "o")), bytes)
    }

    func testRejectsBadInput() {
        XCTAssertNil(RecoveryCode.decode("UUUU")) // U is not in the alphabet
        XCTAssertNil(RecoveryCode.decode("0000"))  // too short
    }
}
