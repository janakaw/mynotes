import SwiftUI
import SecretShareCore

/// New / edit secret sheet, styled after the iOS 26 Reminders "New Reminder" sheet:
/// inline title, X (close) on the left, prominent ✓ (confirm) on the right,
/// and Title + multi-line field together in one inset card.
struct ItemEditorView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let existing: VaultItem?

    @State private var title: String
    @State private var secret: String
    @State private var confirmDiscard = false
    @FocusState private var focus: Field?

    private enum Field { case title, secret }

    init(existing: VaultItem?) {
        self.existing = existing
        _title = State(initialValue: existing?.title ?? "")
        _secret = State(initialValue: existing?.secret ?? "")
    }

    private var trimmedTitle: String { title.trimmingCharacters(in: .whitespacesAndNewlines) }

    private var isValid: Bool {
        !trimmedTitle.isEmpty && trimmedTitle.count <= Limits.maxTitleLength
            && !secret.isEmpty && secret.count <= Limits.maxSecretLength
    }

    private var hasChanges: Bool {
        title != (existing?.title ?? "") || secret != (existing?.secret ?? "")
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Title", text: $title)
                        .focused($focus, equals: .title)
                        .submitLabel(.next)
                        .onSubmit { focus = .secret }

                    TextField("Secret", text: $secret, axis: .vertical)
                        .lineLimit(3...12)
                        .focused($focus, equals: .secret)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                } footer: {
                    HStack {
                        if trimmedTitle.count > Limits.maxTitleLength {
                            Text("Title is too long")
                        }
                        Spacer()
                        Text("\(secret.count)/\(Limits.maxSecretLength)")
                            .monospacedDigit()
                    }
                    .foregroundStyle(secret.count > Limits.maxSecretLength
                                     || trimmedTitle.count > Limits.maxTitleLength ? .red : .secondary)
                }
            }
            .navigationTitle(existing == nil ? "New Secret" : "Edit Secret")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    SheetCloseButton {
                        if hasChanges { confirmDiscard = true } else { dismiss() }
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    SheetConfirmButton {
                        Task { await save() }
                    }
                    .disabled(!isValid || model.busy)
                }
            }
            .confirmationDialog("Discard changes?", isPresented: $confirmDiscard, titleVisibility: .hidden) {
                Button("Discard Changes", role: .destructive) { dismiss() }
                Button("Keep Editing", role: .cancel) {}
            }
        }
        // Like Reminders: no accidental swipe-to-dismiss while there are unsaved edits.
        .interactiveDismissDisabled(hasChanges)
        .onAppear {
            if existing == nil { focus = .title }
        }
    }

    private func save() async {
        if await model.save(id: existing?.id, title: title, secret: secret) {
            dismiss()
        }
    }
}

// MARK: - System sheet buttons (reusable in any sheet)

/// System X button (Liquid Glass).
struct SheetCloseButton: View {
    let action: () -> Void

    var body: some View {
        Button(role: .close, action: action)
    }
}

/// System prominent ✓ button (tinted glass, greys out when disabled).
struct SheetConfirmButton: View {
    let action: () -> Void

    var body: some View {
        Button(role: .confirm, action: action)
    }
}

#Preview("New") {
    PreviewHost(.unlocked) { _ in ItemEditorView(existing: nil) }
}

#Preview("Edit") {
    PreviewHost(.unlocked) { ctx in ItemEditorView(existing: ctx.sampleItem) }
}
