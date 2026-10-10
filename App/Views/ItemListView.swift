import SwiftUI
import SecretShareCore

struct ItemListView: View {
    @EnvironmentObject private var model: AppModel
    @State private var showNew = false
    @State private var showSettings = false
    @State private var showQuit = false

    var body: some View {
        NavigationStack {
            List {
                if model.unlockedViaRecovery {
                    Section {
                        Label("Unlocked with recovery code. Add a new passkey in Settings and remove the lost one.",
                              systemImage: "key.horizontal")
                            .font(.footnote)
                    }
                }
                if !model.failedItemIDs.isEmpty {
                    Section {
                        Label("\(model.failedItemIDs.count) item(s) failed the integrity check and are hidden.",
                              systemImage: "exclamationmark.shield")
                            .foregroundStyle(.red)
                            .font(.footnote)
                    }
                }
                ForEach(model.items) { item in
                    NavigationLink(value: item.id) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(item.title)
                            Text(item.modified, style: .relative)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                .onDelete { offsets in
                    let ids = offsets.map { model.items[$0].id }
                    Task { for id in ids { await model.delete(id) } }
                }
            }
            .overlay {
                if model.items.isEmpty {
                    ContentUnavailableView("No secrets yet",
                                           systemImage: "key",
                                           description: Text("Tap + to add your first one."))
                }
            }
            .refreshable { await model.reload() }
            .navigationTitle("Vault")
            .navigationDestination(for: UUID.self) { id in
                ItemDetailView(itemID: id)
            }
            .toolbar {
                ToolbarItemGroup(placement: .topBarLeading) {
                    Button { showSettings = true } label: { Image(systemName: "gearshape") }
                    Button { showQuit = true } label: { Image(systemName: "power") }
                }
                ToolbarItemGroup(placement: .topBarTrailing) {
                    Button { Task { await model.lock() } } label: { Image(systemName: "lock") }
                    Button { showNew = true } label: { Image(systemName: "plus") }
                }
            }
            .sheet(isPresented: $showNew) {
                ItemEditorView(existing: nil)
            }
            .sheet(isPresented: $showSettings) {
                SettingsView()
            }
            .confirmationDialog("Lock the vault and quit?", isPresented: $showQuit, titleVisibility: .visible) {
                Button("Lock & Quit", role: .destructive) { Task { await model.quit() } }
            }
        }
    }
}

#Preview("With secrets") {
    PreviewHost(.unlocked) { _ in ItemListView() }
}

#Preview("Empty") {
    PreviewHost(.empty) { _ in ItemListView() }
}
