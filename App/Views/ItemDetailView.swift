import SwiftUI
import UniformTypeIdentifiers
import SecretShareCore

struct ItemDetailView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let itemID: UUID

    @State private var item: VaultItem?
    @State private var revealed = false
    @State private var showEditor = false
    @State private var showShare = false
    @State private var confirmDelete = false
    @State private var copied = false

    var body: some View {
        Group {
            if let item {
                List {
                    Section("Secret") {
                        Text(revealed ? item.secret : String(repeating: "•", count: min(item.secret.count, 16)))
                            .font(.system(.body, design: .monospaced))
                            .textSelection(.enabled)
                        Button(revealed ? "Hide" : "Reveal") { revealed.toggle() }
                        Button(copied ? "Copied (clears in \(Int(AppConfig.clipboardExpiry))s)" : "Copy") {
                            copy(item.secret)
                        }
                    }
                    Section("Details") {
                        LabeledContent("Created", value: item.created.formatted(date: .abbreviated, time: .shortened))
                        LabeledContent("Modified", value: item.modified.formatted(date: .abbreviated, time: .shortened))
                        LabeledContent("Version", value: "\(item.version)")
                        LabeledContent("Length", value: "\(item.secret.count) / \(Limits.maxSecretLength)")
                        Label("Integrity verified", systemImage: "checkmark.shield")
                            .foregroundStyle(.green)
                    }
                    Section {
                        Button("Delete", role: .destructive) { confirmDelete = true }
                    }
                }
                .navigationTitle(item.title)
                .toolbar {
                    ToolbarItemGroup(placement: .topBarTrailing) {
                        Button { showShare = true } label: { Image(systemName: "square.and.arrow.up") }
                        Button("Edit") { showEditor = true }
                    }
                }
                .sheet(isPresented: $showShare) {
                    ShareComposerView(item: item)
                }
                .sheet(isPresented: $showEditor, onDismiss: { Task { await load() } }) {
                    ItemEditorView(existing: item)
                }
                .confirmationDialog("Delete this secret?", isPresented: $confirmDelete, titleVisibility: .visible) {
                    Button("Delete", role: .destructive) {
                        Task {
                            await model.delete(item.id)
                            dismiss()
                        }
                    }
                }
            } else {
                ProgressView()
            }
        }
        .task { await load() }
    }

    private func load() async {
        item = await model.loadItem(itemID)
        if item == nil { dismiss() }
    }

    private func copy(_ secret: String) {
        UIPasteboard.general.setItems(
            [[UTType.plainText.identifier: secret]],
            options: [
                .localOnly: true,
                .expirationDate: Date().addingTimeInterval(AppConfig.clipboardExpiry),
            ])
        copied = true
    }
}

#Preview {
    PreviewHost(.unlocked) { ctx in
        NavigationStack {
            if let item = ctx.sampleItem {
                ItemDetailView(itemID: item.id)
            }
        }
    }
}
