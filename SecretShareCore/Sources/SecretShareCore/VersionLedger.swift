import Foundation

/// Remembers the highest version seen per item on this device, to detect rollback/replay.
public protocol VersionLedger: AnyObject {
    func highestVersion(for id: UUID) -> Int
    func record(version: Int, for id: UUID)
    /// Tombstone: any later appearance of this item is treated as a replay.
    func markDeleted(_ id: UUID)
    func removeAll()
}

public final class InMemoryVersionLedger: VersionLedger {
    private var versions: [UUID: Int] = [:]

    public init() {}

    public func highestVersion(for id: UUID) -> Int { versions[id] ?? 0 }

    public func record(version: Int, for id: UUID) {
        versions[id] = max(versions[id] ?? 0, version)
    }

    public func markDeleted(_ id: UUID) { versions[id] = Int.max }

    public func removeAll() { versions.removeAll() }
}

/// Persists the ledger in UserDefaults. Holds only item IDs and version numbers.
public final class UserDefaultsVersionLedger: VersionLedger {
    private let defaults: UserDefaults
    private let key: String

    public init(defaults: UserDefaults = .standard, key: String = "secretshare.versionLedger") {
        self.defaults = defaults
        self.key = key
    }

    private var map: [String: Int] {
        get { defaults.dictionary(forKey: key) as? [String: Int] ?? [:] }
        set { defaults.set(newValue, forKey: key) }
    }

    public func highestVersion(for id: UUID) -> Int { map[id.uuidString] ?? 0 }

    public func record(version: Int, for id: UUID) {
        var m = map
        m[id.uuidString] = max(m[id.uuidString] ?? 0, version)
        map = m
    }

    public func markDeleted(_ id: UUID) {
        var m = map
        m[id.uuidString] = Int.max
        map = m
    }

    public func removeAll() { defaults.removeObject(forKey: key) }
}
