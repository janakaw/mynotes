import SwiftUI
import SecretShareCore

struct SettingsView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var confirmRegenerate = false
    @State private var confirmDestroy = false

    var body: some View {
        NavigationStack {
            List {
                Section {
                    ForEach(model.unlockerEntries) { entry in
                        VStack(alignment: .leading, spacing: 2) {
                            Label(entry.label, systemImage: icon(for: entry.kind))
                            Text("Added \(entry.created.formatted(date: .abbreviated, time: .shortened))")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    if model.passkeysAvailable
                        && !model.unlockerEntries.contains(where: { $0.kind == .passkeyPRF }) {
                        Button {
                            Task { await model.addUnlocker(.passkeyPRF) }
                        } label: {
                            Label("Switch to passkey", systemImage: "person.badge.key")
                        }
                    }
                    Button("Regenerate recovery code") { confirmRegenerate = true }
                } header: {
                    Text("Unlock methods")
                } footer: {
                    Text("One device key plus your recovery code. Each holds its own encrypted copy of your vault key.")
                }

                Section {
                    if let profile = model.myProfile {
                        LabeledContent("Username", value: "@\(profile.handle)")
                    }
                    LabeledContent("Fingerprint") {
                        Text(model.fingerprint)
                            .font(.system(.footnote, design: .monospaced))
                    }
                } header: {
                    Text("Identity")
                } footer: {
                    Text("Your public-key fingerprint. When sharing with someone for the first time, compare fingerprints in person or on a call.")
                }

                if model.passkeysAvailable, let rp = AppConfig.relyingPartyID {
                    Section("Diagnostics") {
                        NavigationLink("PRF stability test") {
                            PRFTestView(unlocker: PasskeyPRFUnlocker(relyingPartyID: rp))
                        }
                    }
                }

                Section {
                    Button("Delete vault", role: .destructive) { confirmDestroy = true }
                }
            }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                Button("Done") { dismiss() }
            }
            .disabled(model.busy)
            .confirmationDialog("Your current recovery code will stop working.",
                                isPresented: $confirmRegenerate, titleVisibility: .visible) {
                Button("Regenerate") {
                    Task {
                        await model.regenerateRecoveryCode()
                        dismiss()
                    }
                }
            }
            .confirmationDialog("Delete the vault and all secrets? This can't be undone.",
                                isPresented: $confirmDestroy, titleVisibility: .visible) {
                Button("Delete everything", role: .destructive) {
                    Task {
                        await model.destroyVault()
                        dismiss()
                    }
                }
            }
        }
    }

    private func icon(for kind: UnlockerKind) -> String {
        switch kind {
        case .passkeyPRF: return "person.badge.key"
        case .recoveryCode: return "doc.text"
        case .devLocal: return "hammer"
        }
    }
}

#Preview {
    PreviewHost(.unlocked) { _ in SettingsView() }
}
