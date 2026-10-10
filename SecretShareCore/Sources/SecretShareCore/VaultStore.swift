import Foundation

/// Storage backend. Only ever receives ciphertext and public data.
/// Implementations: InMemoryVaultStore (tests), FileVaultStore (MVP), CloudKitVaultStore (next).
public protocol VaultStore: Sendable {
    func loadHeader() async throws -> VaultHeader?
    func saveHeader(_ header: VaultHeader) async throws
    func allItems() async throws -> [ItemRecord]
    func item(id: UUID) async throws -> ItemRecord?
    func save(_ record: ItemRecord) async throws
    func delete(id: UUID) async throws
    func deleteAll() async throws
}

public actor InMemoryVaultStore: VaultStore {
    private var header: VaultHeader?
    private var items: [UUID: ItemRecord] = [:]

    public init() {}

    public func loadHeader() async throws -> VaultHeader? { header }
    public func saveHeader(_ header: VaultHeader) async throws { self.header = header }
    public func allItems() async throws -> [ItemRecord] { Array(items.values) }
    public func item(id: UUID) async throws -> ItemRecord? { items[id] }
    public func save(_ record: ItemRecord) async throws { items[record.id] = record }
    public func delete(id: UUID) async throws { items[id] = nil }
    public func deleteAll() async throws {
        header = nil
        items.removeAll()
    }
}

/// Stores the vault as JSON files under Application Support (iOS file protection on).
public actor FileVaultStore: VaultStore {
    private let root: URL
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    public init(directory: URL) {
        self.root = directory
    }

    public static func defaultDirectory() throws -> URL {
        try FileManager.default
            .url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
            .appendingPathComponent("Vault", isDirectory: true)
    }

    private var headerURL: URL { root.appendingPathComponent("header.json") }
    private var itemsURL: URL { root.appendingPathComponent("items", isDirectory: true) }
    private func itemURL(_ id: UUID) -> URL { itemsURL.appendingPathComponent("\(id.uuidString).json") }

    private var writeOptions: Data.WritingOptions {
        #if os(iOS)
        return [.atomic, .completeFileProtection]
        #else
        return [.atomic]
        #endif
    }

    private func ensureDirectories() throws {
        try FileManager.default.createDirectory(at: itemsURL, withIntermediateDirectories: true)
    }

    public func loadHeader() async throws -> VaultHeader? {
        guard FileManager.default.fileExists(atPath: headerURL.path) else { return nil }
        return try decoder.decode(VaultHeader.self, from: Data(contentsOf: headerURL))
    }

    public func saveHeader(_ header: VaultHeader) async throws {
        try ensureDirectories()
        try encoder.encode(header).write(to: headerURL, options: writeOptions)
    }

    public func allItems() async throws -> [ItemRecord] {
        guard FileManager.default.fileExists(atPath: itemsURL.path) else { return [] }
        let files = try FileManager.default.contentsOfDirectory(at: itemsURL, includingPropertiesForKeys: nil)
        return try files
            .filter { $0.pathExtension == "json" }
            .map { try decoder.decode(ItemRecord.self, from: Data(contentsOf: $0)) }
    }

    public func item(id: UUID) async throws -> ItemRecord? {
        let url = itemURL(id)
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        return try decoder.decode(ItemRecord.self, from: Data(contentsOf: url))
    }

    public func save(_ record: ItemRecord) async throws {
        try ensureDirectories()
        try encoder.encode(record).write(to: itemURL(record.id), options: writeOptions)
    }

    public func delete(id: UUID) async throws {
        let url = itemURL(id)
        if FileManager.default.fileExists(atPath: url.path) {
            try FileManager.default.removeItem(at: url)
        }
    }

    public func deleteAll() async throws {
        if FileManager.default.fileExists(atPath: root.path) {
            try FileManager.default.removeItem(at: root)
        }
    }
}
