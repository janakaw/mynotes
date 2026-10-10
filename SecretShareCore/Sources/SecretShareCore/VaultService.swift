import Foundation

/// The only API the UI talks to. Owns the unlocked keys (in memory only) and
/// guarantees everything handed to the VaultStore is already encrypted.
///
/// Key hierarchy:
///   unlocker secret (passkey PRF / recovery code / dev key)
///     → HKDF → wrap key → unwraps Master Key (MK)
///   MK → wraps identity keys (X25519 + Ed25519) and one Item Key per item
///   Item Key → encrypts the padded item payload
public actor VaultService {
    private let store: VaultStore
    private let crypto: CryptoEngine
    private let ledger: VersionLedger

    private struct Session {
        var masterKey: [UInt8]
        var boxSecretKey: [UInt8]
        var signSecretKey: [UInt8]
        var header: VaultHeader
    }

    private var session: Session?
    private var index: [UUID: ItemSummary] = [:]
    private var failures: [UUID] = []

    public init(store: VaultStore,
                crypto: CryptoEngine = SodiumCryptoEngine(),
                ledger: VersionLedger = InMemoryVersionLedger()) {
        self.store = store
        self.crypto = crypto
        self.ledger = ledger
    }

    // MARK: - Status

    public func status() async throws -> VaultStatus {
        if session != nil { return .unlocked }
        return try await store.loadHeader() == nil ? .noVault : .locked
    }

    /// Unlock methods enrolled in the vault (public data; usable while locked).
    public func enrolledKinds() async throws -> Set<UnlockerKind> {
        guard let header = try await store.loadHeader() else { return [] }
        return Set(header.unlockers.map(\.kind))
    }

    // MARK: - Setup

    /// Creates a new vault. Returns the recovery code, which must be shown to the user once.
    public func setup(with unlocker: Unlocker) async throws -> String {
        if try await store.loadHeader() != nil { throw VaultError.vaultAlreadyExists }

        var enrollment = try await unlocker.enroll()
        defer { crypto.wipe(&enrollment.secret) }

        let masterKey = crypto.randomBytes(32)
        let box = try crypto.boxKeyPair()
        let sign = try crypto.signKeyPair()

        var identity = box.secretKey + sign.secretKey
        defer { crypto.wipe(&identity) }
        let wrappedIdentity = try crypto.seal(identity, key: masterKey, ad: AD.identity)

        let primary = try makeEntry(kind: unlocker.kind, label: enrollment.label,
                                    secret: enrollment.secret, credentialID: enrollment.credentialID,
                                    prfSalt: enrollment.prfSalt, masterKey: masterKey)

        var recoveryBytes = crypto.randomBytes(RecoveryCode.byteCount)
        defer { crypto.wipe(&recoveryBytes) }
        let recovery = try makeEntry(kind: .recoveryCode, label: "Recovery code",
                                     secret: recoveryBytes, credentialID: nil,
                                     prfSalt: nil, masterKey: masterKey)

        let header = VaultHeader(formatVersion: VaultHeader.currentFormat,
                                 unlockers: [primary, recovery],
                                 wrappedIdentity: Data(wrappedIdentity),
                                 boxPublicKey: Data(box.publicKey),
                                 signPublicKey: Data(sign.publicKey))
        try await store.saveHeader(header)

        ledger.removeAll()
        session = Session(masterKey: masterKey, boxSecretKey: box.secretKey,
                          signSecretKey: sign.secretKey, header: header)
        index = [:]
        failures = []
        return RecoveryCode.encode(recoveryBytes)
    }

    // MARK: - Unlock / lock

    public func unlock(with unlocker: Unlocker) async throws {
        let header = try await requireHeader()
        let candidates = header.unlockers.filter { $0.kind == unlocker.kind }
        guard !candidates.isEmpty else { throw VaultError.noMatchingUnlocker }

        var result = try await unlocker.secret(for: candidates)
        defer { crypto.wipe(&result.secret) }

        var narrowed = candidates
        if let credentialID = result.credentialID {
            narrowed = candidates.filter { $0.credentialID == credentialID }
        }
        let masterKey = try unwrapMasterKey(from: narrowed, secret: result.secret)
        try await openSession(header: header, masterKey: masterKey)
    }

    public func unlock(recoveryCode: String) async throws {
        guard var bytes = RecoveryCode.decode(recoveryCode) else { throw VaultError.invalidRecoveryCode }
        defer { crypto.wipe(&bytes) }
        let header = try await requireHeader()
        let candidates = header.unlockers.filter { $0.kind == .recoveryCode }
        let masterKey = try unwrapMasterKey(from: candidates, secret: bytes)
        try await openSession(header: header, masterKey: masterKey)
    }

    /// Wipes all keys and decrypted data from memory.
    public func lock() {
        if session != nil {
            crypto.wipe(&session!.masterKey)
            crypto.wipe(&session!.boxSecretKey)
            crypto.wipe(&session!.signSecretKey)
        }
        session = nil
        index = [:]
        failures = []
    }

    // MARK: - Items

    public func list() throws -> [ItemSummary] {
        _ = try requireSession()
        return index.values.sorted {
            $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending
        }
    }

    /// IDs of items that failed decryption, integrity or rollback checks on last load.
    public func failedItemIDs() throws -> [UUID] {
        _ = try requireSession()
        return failures
    }

    public func reloadIndex() async throws {
        _ = try requireSession()
        let records = try await store.allItems()
        let masterKey = try currentMasterKey()
        var newIndex: [UUID: ItemSummary] = [:]
        var newFailures: [UUID] = []
        for record in records {
            do {
                let plain = try decrypt(record, masterKey: masterKey)
                newIndex[record.id] = Self.summary(record.id, plain)
            } catch {
                newFailures.append(record.id)
            }
        }
        index = newIndex
        failures = newFailures
    }

    public func item(id: UUID) async throws -> VaultItem {
        _ = try requireSession()
        guard let record = try await store.item(id: id) else { throw VaultError.itemNotFound }
        let plain = try decrypt(record, masterKey: try currentMasterKey())
        return VaultItem(id: id, title: plain.title, secret: plain.secret,
                         created: plain.created, modified: plain.modified, version: plain.version)
    }

    @discardableResult
    public func create(title: String, secret: String) async throws -> ItemSummary {
        _ = try requireSession()
        let (cleanTitle, cleanSecret) = try Self.validate(title: title, secret: secret)
        let id = UUID()
        let now = Date()
        var itemKey = crypto.randomBytes(32)
        defer { crypto.wipe(&itemKey) }

        let plain = ItemPlaintext(title: cleanTitle, secret: cleanSecret,
                                  created: now, modified: now, version: 1)
        let record = try encrypt(plain, id: id, itemKey: itemKey, masterKey: try currentMasterKey())
        try await store.save(record)

        ledger.record(version: 1, for: id)
        let summary = Self.summary(id, plain)
        index[id] = summary
        return summary
    }

    @discardableResult
    public func update(id: UUID, title: String, secret: String) async throws -> ItemSummary {
        _ = try requireSession()
        let (cleanTitle, cleanSecret) = try Self.validate(title: title, secret: secret)
        guard let record = try await store.item(id: id) else { throw VaultError.itemNotFound }

        let masterKey = try currentMasterKey()
        let old = try decrypt(record, masterKey: masterKey)
        var itemKey = try unwrapItemKey(record, masterKey: masterKey)
        defer { crypto.wipe(&itemKey) }

        let plain = ItemPlaintext(title: cleanTitle, secret: cleanSecret,
                                  created: old.created, modified: Date(), version: old.version + 1)
        let newRecord = try encrypt(plain, id: id, itemKey: itemKey, masterKey: masterKey)
        try await store.save(newRecord)

        ledger.record(version: plain.version, for: id)
        let summary = Self.summary(id, plain)
        index[id] = summary
        return summary
    }

    public func delete(id: UUID) async throws {
        _ = try requireSession()
        try await store.delete(id: id)
        ledger.markDeleted(id)
        index[id] = nil
        failures.removeAll { $0 == id }
    }

    // MARK: - Unlock method management

    public func unlockers() throws -> [UnlockerEntry] {
        try requireSession().header.unlockers
    }

    @discardableResult
    public func addUnlocker(_ unlocker: Unlocker) async throws -> UnlockerEntry {
        _ = try requireSession()
        var enrollment = try await unlocker.enroll()
        defer { crypto.wipe(&enrollment.secret) }

        let entry = try makeEntry(kind: unlocker.kind, label: enrollment.label,
                                  secret: enrollment.secret, credentialID: enrollment.credentialID,
                                  prfSalt: enrollment.prfSalt, masterKey: try currentMasterKey())
        var header = try requireSession().header
        header.unlockers.append(entry)
        try await store.saveHeader(header)
        session?.header = header
        return entry
    }

    /// Removes one wrapped copy of the master key.
    /// Note: an old header copy plus the removed credential could still unwrap MK.
    /// Full revocation needs master-key rotation (post-MVP).
    public func removeUnlocker(id: UUID) async throws {
        var header = try requireSession().header
        guard let entry = header.unlockers.first(where: { $0.id == id }) else { return }
        if entry.kind == .recoveryCode { throw VaultError.cannotRemoveRecoveryCode }
        let remaining = header.unlockers.filter { $0.id != id && $0.kind != .recoveryCode }
        guard !remaining.isEmpty else { throw VaultError.cannotRemoveLastUnlocker }

        header.unlockers.removeAll { $0.id == id }
        try await store.saveHeader(header)
        session?.header = header
    }

    /// Replaces the recovery code. The old code stops working.
    public func regenerateRecoveryCode() async throws -> String {
        var header = try requireSession().header
        var bytes = crypto.randomBytes(RecoveryCode.byteCount)
        defer { crypto.wipe(&bytes) }
        let entry = try makeEntry(kind: .recoveryCode, label: "Recovery code", secret: bytes,
                                  credentialID: nil, prfSalt: nil, masterKey: try currentMasterKey())
        header.unlockers.removeAll { $0.kind == .recoveryCode }
        header.unlockers.append(entry)
        try await store.saveHeader(header)
        session?.header = header
        return RecoveryCode.encode(bytes)
    }

    /// Short fingerprint of this vault's public identity keys (for sharing/verification later).
    public func identityFingerprint() throws -> String {
        let header = try requireSession().header
        let digest = crypto.sha256(Array(header.boxPublicKey) + Array(header.signPublicKey))
        let hex = digest.prefix(10).map { String(format: "%02X", $0) }.joined()
        return stride(from: 0, to: hex.count, by: 4).map { offset -> String in
            let start = hex.index(hex.startIndex, offsetBy: offset)
            let end = hex.index(start, offsetBy: min(4, hex.count - offset))
            return String(hex[start..<end])
        }.joined(separator: " ")
    }

    /// Deletes the whole vault (header + items) and locks.
    public func destroyVault() async throws {
        lock()
        try await store.deleteAll()
        ledger.removeAll()
    }

    // MARK: - Internals

    private func requireSession() throws -> Session {
        guard let session else { throw VaultError.locked }
        return session
    }

    private func currentMasterKey() throws -> [UInt8] {
        try requireSession().masterKey
    }

    private func requireHeader() async throws -> VaultHeader {
        guard let header = try await store.loadHeader() else { throw VaultError.noVault }
        guard header.formatVersion == VaultHeader.currentFormat else { throw VaultError.corruptHeader }
        return header
    }

    private func openSession(header: VaultHeader, masterKey: [UInt8]) async throws {
        var identity: [UInt8]
        do {
            identity = try crypto.open(Array(header.wrappedIdentity), key: masterKey, ad: AD.identity)
        } catch {
            throw VaultError.corruptHeader
        }
        defer { crypto.wipe(&identity) }
        guard identity.count == 32 + 64 else { throw VaultError.corruptHeader }

        session = Session(masterKey: masterKey,
                          boxSecretKey: Array(identity[0..<32]),
                          signSecretKey: Array(identity[32...]),
                          header: header)
        try await reloadIndex()
    }

    private func makeEntry(kind: UnlockerKind, label: String, secret: [UInt8],
                           credentialID: Data?, prfSalt: Data?,
                           masterKey: [UInt8]) throws -> UnlockerEntry {
        guard secret.count >= 16 else { throw VaultError.unlockerFailed("Unlock secret is too short.") }
        let id = UUID()
        let hkdfSalt = crypto.randomBytes(32)
        var wrapKey = crypto.hkdfSHA256(secret, salt: hkdfSalt, info: Self.hkdfInfo(kind), length: 32)
        defer { crypto.wipe(&wrapKey) }
        let wrapped = try crypto.seal(masterKey, key: wrapKey, ad: AD.masterKey(id))
        return UnlockerEntry(id: id, kind: kind, label: label, credentialID: credentialID,
                             prfSalt: prfSalt, hkdfSalt: Data(hkdfSalt),
                             wrappedMK: Data(wrapped), created: Date())
    }

    private func unwrapMasterKey(from candidates: [UnlockerEntry], secret: [UInt8]) throws -> [UInt8] {
        for entry in candidates {
            var wrapKey = crypto.hkdfSHA256(secret, salt: Array(entry.hkdfSalt),
                                            info: Self.hkdfInfo(entry.kind), length: 32)
            defer { crypto.wipe(&wrapKey) }
            if let masterKey = try? crypto.open(Array(entry.wrappedMK), key: wrapKey, ad: AD.masterKey(entry.id)) {
                return masterKey
            }
        }
        throw VaultError.wrongCredential
    }

    private func encrypt(_ plain: ItemPlaintext, id: UUID, itemKey: [UInt8],
                         masterKey: [UInt8]) throws -> ItemRecord {
        var json = Array(try JSONEncoder().encode(plain))
        defer { crypto.wipe(&json) }
        guard json.count < Limits.paddedPayloadSize else { throw VaultError.payloadTooLarge }

        var padded = try crypto.pad(json, blockSize: Limits.paddedPayloadSize)
        defer { crypto.wipe(&padded) }

        let payload = try crypto.seal(padded, key: itemKey, ad: AD.payload(id, plain.version))
        let wrappedKey = try crypto.seal(itemKey, key: masterKey, ad: AD.itemKey(id))
        return ItemRecord(id: id, wrappedKey: Data(wrappedKey), payload: Data(payload), version: plain.version)
    }

    private func unwrapItemKey(_ record: ItemRecord, masterKey: [UInt8]) throws -> [UInt8] {
        do {
            return try crypto.open(Array(record.wrappedKey), key: masterKey, ad: AD.itemKey(record.id))
        } catch {
            throw VaultError.integrityFailure(record.id)
        }
    }

    /// Decrypts and verifies one record: AEAD tag, record-ID/version binding, padding,
    /// version consistency, and rollback against the local ledger.
    private func decrypt(_ record: ItemRecord, masterKey: [UInt8]) throws -> ItemPlaintext {
        var itemKey = try unwrapItemKey(record, masterKey: masterKey)
        defer { crypto.wipe(&itemKey) }

        var padded: [UInt8]
        do {
            padded = try crypto.open(Array(record.payload), key: itemKey, ad: AD.payload(record.id, record.version))
        } catch {
            throw VaultError.integrityFailure(record.id)
        }
        defer { crypto.wipe(&padded) }

        var json: [UInt8]
        do {
            json = try crypto.unpad(padded, blockSize: Limits.paddedPayloadSize)
        } catch {
            throw VaultError.integrityFailure(record.id)
        }
        defer { crypto.wipe(&json) }

        let plain: ItemPlaintext
        do {
            plain = try JSONDecoder().decode(ItemPlaintext.self, from: Data(json))
        } catch {
            throw VaultError.integrityFailure(record.id)
        }
        guard plain.version == record.version else { throw VaultError.integrityFailure(record.id) }
        if record.version < ledger.highestVersion(for: record.id) {
            throw VaultError.rollbackDetected(record.id)
        }
        ledger.record(version: record.version, for: record.id)
        return plain
    }

    static func validate(title: String, secret: String) throws -> (String, String) {
        let cleanTitle = title.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleanTitle.isEmpty else { throw VaultError.titleEmpty }
        guard cleanTitle.count <= Limits.maxTitleLength else { throw VaultError.titleTooLong }
        guard !secret.isEmpty else { throw VaultError.secretEmpty }
        guard secret.count <= Limits.maxSecretLength else { throw VaultError.secretTooLong }
        return (cleanTitle, secret)
    }

    private static func summary(_ id: UUID, _ plain: ItemPlaintext) -> ItemSummary {
        ItemSummary(id: id, title: plain.title, modified: plain.modified, version: plain.version)
    }

    static func hkdfInfo(_ kind: UnlockerKind) -> String {
        "secretshare/unlock/v1/\(kind.rawValue)"
    }
}

/// Associated data: binds every ciphertext to its purpose, record ID and version,
/// so ciphertexts can't be swapped between records or replayed as another version.
enum AD {
    static let identity = Array("ss/identity/v1".utf8)
    static func masterKey(_ entryID: UUID) -> [UInt8] { Array("ss/mk/v1/\(entryID.uuidString)".utf8) }
    static func itemKey(_ id: UUID) -> [UInt8] { Array("ss/ik/v1/\(id.uuidString)".utf8) }
    static func payload(_ id: UUID, _ version: Int) -> [UInt8] {
        Array("ss/item/v1/\(id.uuidString)/\(version)".utf8)
    }
}

// MARK: - Sharing crypto (identity keys never leave this actor)

extension VaultService {
    public func publicIdentity() throws -> (boxPublicKey: Data, signPublicKey: Data) {
        let header = try requireSession().header
        return (header.boxPublicKey, header.signPublicKey)
    }

    /// Encrypts one vault item to the recipient's public key and signs it.
    public func sealShare(itemID: UUID, shareID: UUID, senderID: UUID,
                          recipient: DirectoryProfile, expiresAtUnix: Int64,
                          viewOnce: Bool) async throws -> OutgoingShare {
        let item = try await self.item(id: itemID)
        let session = try requireSession()

        let plain = SharePlaintext(title: item.title, secret: item.secret, sharedAt: Date())
        var json = Array(try JSONEncoder().encode(plain))
        defer { crypto.wipe(&json) }
        guard json.count < Limits.paddedPayloadSize else { throw VaultError.payloadTooLarge }
        var padded = try crypto.pad(json, blockSize: Limits.paddedPayloadSize)
        defer { crypto.wipe(&padded) }

        let envelope = try crypto.sealToPublicKey(padded, publicKey: Array(recipient.boxPublicKey))
        let message = ShareSigning.message(shareID: shareID, senderID: senderID,
                                           recipientID: recipient.userID,
                                           expiresAtUnix: expiresAtUnix, viewOnce: viewOnce,
                                           envelopeHash: crypto.sha256(envelope))
        let signature = try crypto.sign(message, secretKey: session.signSecretKey)
        return OutgoingShare(id: shareID, recipientID: recipient.userID,
                             expiresAtUnix: expiresAtUnix, viewOnce: viewOnce,
                             envelope: Data(envelope), signature: Data(signature))
    }

    /// Verifies the sender's signature and expiry, then decrypts with this vault's identity key.
    public func openShare(_ sealed: SealedShare, sender: DirectoryProfile,
                          now: Date = Date()) throws -> ReceivedSecret {
        let session = try requireSession()
        let summary = sealed.summary
        guard sender.userID == summary.senderID else { throw VaultError.shareSignatureInvalid }

        let envelope = Array(sealed.envelope)
        let message = ShareSigning.message(shareID: summary.id, senderID: summary.senderID,
                                           recipientID: summary.recipientID,
                                           expiresAtUnix: summary.expiresAtUnix,
                                           viewOnce: summary.viewOnce,
                                           envelopeHash: crypto.sha256(envelope))
        guard crypto.verify(message, signature: Array(sealed.signature),
                            publicKey: Array(sender.signPublicKey)) else {
            throw VaultError.shareSignatureInvalid
        }
        guard now < summary.expiresAt else { throw VaultError.shareExpired }

        var padded: [UInt8]
        do {
            padded = try crypto.openSealed(envelope, publicKey: Array(session.header.boxPublicKey),
                                           secretKey: session.boxSecretKey)
        } catch {
            throw VaultError.shareSignatureInvalid
        }
        defer { crypto.wipe(&padded) }
        var json = try crypto.unpad(padded, blockSize: Limits.paddedPayloadSize)
        defer { crypto.wipe(&json) }
        let plain = try JSONDecoder().decode(SharePlaintext.self, from: Data(json))
        return ReceivedSecret(shareID: summary.id, title: plain.title, secret: plain.secret,
                              sender: sender, sharedAt: plain.sharedAt,
                              expiresAt: summary.expiresAt, viewOnce: summary.viewOnce)
    }
}
