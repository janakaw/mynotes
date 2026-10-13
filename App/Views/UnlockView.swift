import SwiftUI
import SecretShareCore

struct UnlockView: View {
    @EnvironmentObject private var model: AppModel
    @State private var showRecovery = false
    @State private var confirmReset = false

    var body: some View {
        VStack(spacing: 20) {
            Spacer()
            Image(systemName: "lock.fill")
                .font(.system(size: 64))
                .foregroundStyle(.tint)
            Text("Vault locked")
                .font(.title.bold())
            Spacer()

            if model.enrolledKinds.contains(.passkeyPRF) && model.passkeysAvailable {
                Button {
                    Task { await model.unlock(kind: .passkeyPRF) }
                } label: {
                    Label("Unlock with passkey", systemImage: "person.badge.key")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
            }

            if model.enrolledKinds.contains(.devLocal) {
                Button {
                    Task { await model.unlock(kind: .devLocal) }
                } label: {
                    Label("Unlock with device key (dev)", systemImage: "hammer")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .controlSize(.large)
            }

            Button("Use recovery code") { showRecovery = true }

            Button("Quit") { Task { await model.quit() } }

            Button("Delete vault and start over", role: .destructive) { confirmReset = true }
                .font(.footnote)
        }
        .padding(24)
        .disabled(model.busy)
        .overlay { if model.busy { ProgressView() } }
        .sheet(isPresented: $showRecovery) {
            RecoveryEntryView()
        }
        .confirmationDialog("Delete the vault and all secrets? This can't be undone.",
                            isPresented: $confirmReset, titleVisibility: .visible) {
            Button("Delete everything", role: .destructive) {
                Task { await model.destroyVault() }
            }
        }
    }
}

struct RecoveryEntryView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var code = ""

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("XXXX-XXXX-XXXX-…", text: $code, axis: .vertical)
                        .font(.body.monospacedDigit())
                        .textInputAutocapitalization(.characters)
                        .autocorrectionDisabled()
                } footer: {
                    Text("After unlocking, add a new passkey in Settings and remove the lost one.")
                }
            }
            .navigationTitle("Recovery code")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Unlock") {
                        Task {
                            if await model.unlock(recoveryCode: code) { dismiss() }
                        }
                    }
                    .disabled(code.trimmingCharacters(in: .whitespaces).isEmpty || model.busy)
                }
            }
        }
    }
}

#Preview("Locked") {
    PreviewHost(.locked) { _ in UnlockView() }
}

#Preview("Recovery code entry") {
    PreviewHost(.locked) { _ in RecoveryEntryView() }
}
