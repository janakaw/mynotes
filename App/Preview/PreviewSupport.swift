import SwiftUI
import SecretShareCore

/// Which situation a preview shows. All data is in memory: no files, Keychain or network.
enum PreviewState {
    /// No vault yet (Setup screen).
    case setup
    /// Vault with sample secrets, locked.
    case locked
    /// Vault with sample secrets, unlocked, registered for sharing, with received + sent shares.
    case unlocked
    /// Unlocked vault with no secrets and no shares.
    case empty
    /// Unlocked, sharing configured but no username chosen yet.
    case unregistered
    /// Unlocked, sharing not configured (no Supabase).
    case sharingOff
}

enum PreviewData {
    static let mySecret = [UInt8](repeating: 0x11, count: 32)
    static let aliceSecret = [UInt8](repeating: 0x22, count: 32)

    static let items: [(title: String, secret: String)] = [
        ("Bank – NetBank", "Xk9#mP2$vL7q"),
        ("Home Wi-Fi", "sunny-garden-4821"),
        ("Netflix", "family-movie-night"),
        ("Door code", "1975#"),
        ("Server root", "ssh root@10.0.0.4\npass: T7!qz-88-Lm\nport 2222"),
    ]
}

/// Holds an in-memory AppModel plus a fake sharing server with a second user ("alice").
@MainActor
final class PreviewContext: ObservableObject {
    let model: AppModel
    let hub: InMemoryShareHub
    @Published var ready = false
    /// First sample secret (decrypted), for detail / editor / share previews.
    var sampleItem: VaultItem?

    var receivedEntry: ShareListEntry? { model.inbox.first { !$0.summary.viewOnce } }
    var viewOnceEntry: ShareListEntry? { model.inbox.first { $0.summary.viewOnce } }

    init(sharingEnabled: Bool) {
        let hub = InMemoryShareHub()
        let vault = VaultService(store: InMemoryVaultStore())
        let sharing = sharingEnabled
            ? SharingService(vault: vault, transport: InMemoryShareTransport(hub: hub), pins: InMemoryKeyPinStore())
            : nil
        self.hub = hub
        self.model = AppModel(vault: vault, sharing: sharing)
        model.previewUnlocker = StaticUnlocker(secret: PreviewData.mySecret)
    }

    func seed(_ state: PreviewState) async {
        guard !ready else { return }
        defer { ready = true }
        let vault = model.vault

        if state == .setup {
            model.screen = .setup
            return
        }

        _ = try? await vault.setup(with: StaticUnlocker(secret: PreviewData.mySecret))
        if state != .empty {
            for sample in PreviewData.items {
                _ = try? await vault.create(title: sample.title, secret: sample.secret)
            }
        }
        if let first = (try? await vault.list())?.first {
            sampleItem = try? await vault.item(id: first.id)
        }

        if let sharing = model.sharing, state != .unregistered {
            _ = try? await sharing.register(handle: "janaka")
            if state != .empty {
                await seedShares(me: sharing)
            }
        }

        if state == .locked {
            await vault.lock()
            model.enrolledKinds = (try? await vault.enrolledKinds()) ?? []
            model.screen = .locked
        } else {
            model.screen = .unlocked
            await model.loadUnlockedState()
            await model.refreshSharing()
        }
    }

    /// Alice shares two secrets with me (one view-once); I share one with Alice.
    private func seedShares(me: SharingService) async {
        let aliceVault = VaultService(store: InMemoryVaultStore())
        _ = try? await aliceVault.setup(with: StaticUnlocker(secret: PreviewData.aliceSecret))
        let alice = SharingService(vault: aliceVault, transport: InMemoryShareTransport(hub: hub))
        _ = try? await alice.register(handle: "alice")

        guard let wifi = try? await aliceVault.create(title: "Office Wi-Fi", secret: "c0rrect-h0rse-battery-staple"),
              let alarm = try? await aliceVault.create(title: "Alarm code", secret: "4821#"),
              let meProfile = try? await alice.findRecipient(handle: "janaka").profile else { return }
        try? await alice.share(itemID: wifi.id, with: meProfile, duration: 3600, viewOnce: false)
        try? await alice.share(itemID: alarm.id, with: meProfile, duration: 300, viewOnce: true)

        if let aliceProfile = try? await me.findRecipient(handle: "alice").profile, let item = sampleItem {
            try? await me.share(itemID: item.id, with: aliceProfile, duration: 86_400, viewOnce: true)
        }
    }
}

/// Wraps a view for #Preview: builds in-memory data for `state`, then shows the view
/// with the AppModel injected.
///
///     #Preview { PreviewHost(.unlocked) { _ in ItemListView() } }
///     #Preview { PreviewHost { ctx in ItemDetailView(itemID: ctx.sampleItem!.id) } }
struct PreviewHost<Content: View>: View {
    private let state: PreviewState
    private let content: (PreviewContext) -> Content
    @StateObject private var context: PreviewContext

    init(_ state: PreviewState = .unlocked, @ViewBuilder content: @escaping (PreviewContext) -> Content) {
        self.state = state
        self.content = content
        _context = StateObject(wrappedValue: PreviewContext(sharingEnabled: state != .sharingOff))
    }

    var body: some View {
        Group {
            if context.ready {
                content(context)
            } else {
                ProgressView("Preparing preview…")
            }
        }
        .environmentObject(context.model)
        .task { await context.seed(state) }
    }
}
