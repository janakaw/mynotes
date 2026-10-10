import SwiftUI
import SecretShareCore

enum AppError: LocalizedError {
    case passkeyNotConfigured
    var errorDescription: String? {
        "Passkeys aren't configured. Set AppConfig.relyingPartyID to your domain."
    }
}

@MainActor
final class AppModel: ObservableObject {
    enum Screen { case loading, setup, locked, unlocked }

    @Published var screen: Screen = .loading
    @Published var items: [ItemSummary] = []
    @Published var failedItemIDs: [UUID] = []
    @Published var enrolledKinds: Set<UnlockerKind> = []
    @Published var unlockerEntries: [UnlockerEntry] = []
    @Published var fingerprint: String = ""
    @Published var recoveryCodeToShow: String?
    @Published var unlockedViaRecovery = false
    @Published var errorMessage: String?
    @Published var busy = false
    @Published var obscured = false

    // Sharing
    @Published var registration: RegistrationState?
    @Published var inbox: [ShareListEntry] = []
    @Published var sent: [ShareListEntry] = []

    let vault: VaultService
    let sharing: SharingService?

    /// Designated init (also used by previews and tests with in-memory dependencies).
    init(vault: VaultService, sharing: SharingService?) {
        self.vault = vault
        self.sharing = sharing
    }

    /// Production dependencies: encrypted files on disk + Supabase (if configured).
    convenience init() {
        let store: VaultStore
        if let dir = try? FileVaultStore.defaultDirectory() {
            store = FileVaultStore(directory: dir)
        } else {
            store = InMemoryVaultStore()
        }
        let vault = VaultService(store: store, ledger: UserDefaultsVersionLedger())

        var sharing: SharingService?
        if let urlString = AppConfig.supabaseURL, let url = URL(string: urlString),
           let key = AppConfig.supabaseAnonKey {
            sharing = SharingService(vault: vault,
                                     transport: SupabaseShareTransport(url: url, anonKey: key),
                                     pins: UserDefaultsKeyPinStore())
        }
        self.init(vault: vault, sharing: sharing)
    }

    /// Previews only: used instead of the device-key / passkey unlockers.
    var previewUnlocker: Unlocker?

    var passkeysAvailable: Bool { AppConfig.relyingPartyID != nil }

    // MARK: - Lifecycle

    func start() async {
        await refreshStatus()
    }

    func refreshStatus() async {
        do {
            switch try await vault.status() {
            case .noVault:
                screen = .setup
            case .locked:
                enrolledKinds = try await vault.enrolledKinds()
                screen = .locked
            case .unlocked:
                await loadUnlockedState()
                screen = .unlocked
            }
        } catch {
            show(error)
        }
    }

    func handleScenePhase(_ phase: ScenePhase) {
        switch phase {
        case .active:
            obscured = false
        case .inactive:
            // Hide content in the app switcher. (Passkey sheets also trigger .inactive.)
            obscured = (screen == .unlocked)
        case .background:
            Task { await lock() }
        @unknown default:
            break
        }
    }

    // MARK: - Setup / unlock

    func makeUnlocker(_ kind: UnlockerKind) throws -> Unlocker {
        if let previewUnlocker { return previewUnlocker }
        switch kind {
        case .passkeyPRF:
            guard let rp = AppConfig.relyingPartyID else { throw AppError.passkeyNotConfigured }
            return PasskeyPRFUnlocker(relyingPartyID: rp)
        case .devLocal:
            return DevLocalUnlocker()
        case .recoveryCode:
            throw VaultError.noMatchingUnlocker
        }
    }

    func setup(kind: UnlockerKind) async {
        await run {
            let code = try await vault.setup(with: makeUnlocker(kind))
            await loadUnlockedState()
            screen = .unlocked
            recoveryCodeToShow = code
        }
    }

    func unlock(kind: UnlockerKind) async {
        await run {
            try await vault.unlock(with: makeUnlocker(kind))
            unlockedViaRecovery = false
            await loadUnlockedState()
            screen = .unlocked
        }
    }

    /// Returns true on success.
    func unlock(recoveryCode: String) async -> Bool {
        var ok = false
        await run {
            try await vault.unlock(recoveryCode: recoveryCode)
            unlockedViaRecovery = true
            await loadUnlockedState()
            screen = .unlocked
            ok = true
        }
        return ok
    }

    func lock() async {
        await vault.lock()
        items = []
        failedItemIDs = []
        unlockerEntries = []
        fingerprint = ""
        unlockedViaRecovery = false
        registration = nil
        inbox = []
        sent = []
        if screen == .unlocked {
            enrolledKinds = (try? await vault.enrolledKinds()) ?? []
            screen = .locked
        }
    }

    // MARK: - Items

    func loadUnlockedState() async {
        do {
            items = try await vault.list()
            failedItemIDs = try await vault.failedItemIDs()
            unlockerEntries = try await vault.unlockers()
            fingerprint = try await vault.identityFingerprint()
        } catch {
            show(error)
        }
    }

    func reload() async {
        await run {
            try await vault.reloadIndex()
            await loadUnlockedState()
        }
    }

    func loadItem(_ id: UUID) async -> VaultItem? {
        do {
            return try await vault.item(id: id)
        } catch {
            show(error)
            return nil
        }
    }

    /// Creates (id == nil) or updates an item. Returns true on success.
    func save(id: UUID?, title: String, secret: String) async -> Bool {
        var ok = false
        await run {
            if let id {
                try await vault.update(id: id, title: title, secret: secret)
            } else {
                try await vault.create(title: title, secret: secret)
            }
            items = try await vault.list()
            ok = true
        }
        return ok
    }

    func delete(_ id: UUID) async {
        await run {
            try await vault.delete(id: id)
            items = try await vault.list()
            failedItemIDs = try await vault.failedItemIDs()
        }
    }

    // MARK: - Unlock methods

    /// Single-key policy: adding a passkey replaces the existing device key.
    func addUnlocker(_ kind: UnlockerKind) async {
        await run {
            let old = unlockerEntries.filter { $0.kind != .recoveryCode }
            try await vault.addUnlocker(makeUnlocker(kind))
            for entry in old { try await vault.removeUnlocker(id: entry.id) }
            unlockerEntries = try await vault.unlockers()
        }
    }

    /// Locks (wiping keys from memory) and terminates the app.
    /// Note: Apple discourages programmatic quit; fine for TestFlight/testing,
    /// may need to become "Lock" only for App Store review.
    func quit() async {
        await vault.lock()
        items = []
        exit(0)
    }

    func removeUnlocker(_ id: UUID) async {
        await run {
            try await vault.removeUnlocker(id: id)
            unlockerEntries = try await vault.unlockers()
        }
    }

    func regenerateRecoveryCode() async {
        await run {
            recoveryCodeToShow = try await vault.regenerateRecoveryCode()
            unlockerEntries = try await vault.unlockers()
        }
    }

    func destroyVault() async {
        await run {
            try await vault.destroyVault()
            DevLocalUnlocker.deleteAllKeys()
            registration = nil
            inbox = []
            sent = []
            items = []
            unlockerEntries = []
            screen = .setup
        }
    }

    // MARK: - Helpers

    func run(_ operation: () async throws -> Void) async {
        busy = true
        defer { busy = false }
        do {
            try await operation()
        } catch {
            show(error)
        }
    }

    func show(_ error: Error) {
        if let vaultError = error as? VaultError, vaultError == .cancelled { return }
        errorMessage = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
    }
}
