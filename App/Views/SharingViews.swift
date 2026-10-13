import SwiftUI
import SecretShareCore

// MARK: - Tabs

struct UnlockedTabsView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        TabView {
            ItemListView()
                .tabItem { Label("Vault", systemImage: "key") }
            InboxView()
                .tabItem { Label("Received", systemImage: "tray") }
                .badge(model.inbox.count)
            SentView()
                .tabItem { Label("Sent", systemImage: "paperplane") }
        }
        .task { await model.refreshSharing() }
    }
}

// MARK: - Gate: configured + registered

struct SharingGate<Content: View>: View {
    @EnvironmentObject private var model: AppModel
    @ViewBuilder let content: () -> Content

    var body: some View {
        if !model.sharingConfigured {
            ContentUnavailableView(
                "Sharing isn't set up",
                systemImage: "network.slash",
                description: Text("Add your Supabase URL and key in AppConfig.swift and run supabase/schema.sql."))
        } else {
            switch model.registration {
            case .none:
                VStack(spacing: 16) {
                    ProgressView()
                    Button("Retry") { Task { await model.refreshSharing() } }
                        .font(.footnote)
                }
            case .unregistered:
                RegisterView(existingHandle: nil)
            case .keysOutdated(let profile):
                RegisterView(existingHandle: profile.handle)
            case .registered:
                content()
            }
        }
    }
}

struct RegisterView: View {
    @EnvironmentObject private var model: AppModel
    let existingHandle: String?
    @State private var handle = ""

    private var normalized: String { handle.trimmingCharacters(in: .whitespaces).lowercased() }

    var body: some View {
        Form {
            Section {
                TextField("username", text: $handle)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
            } header: {
                Text(existingHandle == nil ? "Choose a username" : "Republish your keys")
            } footer: {
                if let existingHandle {
                    Text("This vault's keys don't match the ones published for @\(existingHandle). Republish so people can share with you. Your contacts will see a key-change warning.")
                } else {
                    Text("People share with you using this name. 3–20 characters: a–z, 0–9 and _. Only your public keys are published.")
                }
            }
            Section {
                Button(existingHandle == nil ? "Publish" : "Republish") {
                    Task { _ = await model.register(handle: normalized) }
                }
                .disabled(!DirectoryProfile.isValidHandle(normalized) || model.busy)
            }
        }
        .onAppear { if let existingHandle, handle.isEmpty { handle = existingHandle } }
    }
}

// MARK: - Rows

struct ShareRow: View {
    let entry: ShareListEntry
    let incoming: Bool

    private var handle: String { entry.counterparty?.handle ?? "unknown" }

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(incoming ? "From @\(handle)" : "To @\(handle)")
                .font(.body.weight(.medium))
            HStack(spacing: 10) {
                Label {
                    Text("expires \(entry.summary.expiresAt, style: .relative)")
                } icon: {
                    Image(systemName: "timer")
                }
                if entry.summary.viewOnce {
                    Label("view once", systemImage: "eye")
                }
            }
            .font(.caption)
            .foregroundStyle(.secondary)
        }
        .padding(.vertical, 2)
    }
}

// MARK: - Inbox

struct InboxView: View {
    @EnvironmentObject private var model: AppModel
    @State private var opening: ShareListEntry?

    var body: some View {
        NavigationStack {
            SharingGate {
                List {
                    ForEach(model.inbox) { entry in
                        Button { opening = entry } label: {
                            ShareRow(entry: entry, incoming: true)
                        }
                        .tint(.primary)
                    }
                    .onDelete { offsets in
                        let ids = offsets.map { model.inbox[$0].id }
                        Task { for id in ids { await model.revokeShare(id) } }
                    }
                }
                .overlay {
                    if model.inbox.isEmpty {
                        ContentUnavailableView("Nothing shared with you", systemImage: "tray",
                                               description: Text("Pull down to refresh."))
                    }
                }
                .refreshable { await model.refreshSharing() }
            }
            .navigationTitle("Received")
            .sheet(item: $opening) { entry in
                ReceivedSecretView(entry: entry)
            }
        }
        .task { await model.refreshSharing() }
    }
}

// MARK: - Sent

struct SentView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        NavigationStack {
            SharingGate {
                List {
                    Section {
                        ForEach(model.sent) { entry in
                            ShareRow(entry: entry, incoming: false)
                        }
                        .onDelete { offsets in
                            let ids = offsets.map { model.sent[$0].id }
                            Task { for id in ids { await model.revokeShare(id) } }
                        }
                    } footer: {
                        if !model.sent.isEmpty {
                            Text("Swipe to revoke. Shares disappear when they expire, and view-once shares disappear once opened.")
                        }
                    }
                }
                .overlay {
                    if model.sent.isEmpty {
                        ContentUnavailableView("No active shares", systemImage: "paperplane",
                                               description: Text("Open a secret in your vault and tap Share."))
                    }
                }
                .refreshable { await model.refreshSharing() }
            }
            .navigationTitle("Sent")
        }
        .task { await model.refreshSharing() }
    }
}

// MARK: - Opening a received secret

struct ReceivedSecretView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let entry: ShareListEntry

    @State private var received: ReceivedSecret?
    @State private var confirmed: Bool
    @State private var revealed = false
    @State private var copied = false

    init(entry: ShareListEntry) {
        self.entry = entry
        _confirmed = State(initialValue: !entry.summary.viewOnce)
    }

    var body: some View {
        NavigationStack {
            Group {
                if let received {
                    secretView(received)
                } else if !confirmed {
                    viewOnceWarning
                } else {
                    ProgressView().task { await open() }
                }
            }
            .navigationTitle("Shared secret")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                Button("Close") { dismiss() }
            }
        }
        .onDisappear {
            received = nil
            Task { await model.refreshSharing() }
        }
    }

    private var viewOnceWarning: some View {
        VStack(spacing: 16) {
            Image(systemName: "eye.trianglebadge.exclamationmark")
                .font(.system(size: 48))
                .foregroundStyle(.orange)
            Text("View once").font(.title2.bold())
            Text("@\(entry.counterparty?.handle ?? "unknown") shared a secret you can open only once. When you close it, it's gone.")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
            Button("Open now") { confirmed = true }
                .buttonStyle(.borderedProminent)
        }
        .padding(24)
    }

    private func secretView(_ received: ReceivedSecret) -> some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let remaining = received.expiresAt.timeIntervalSince(context.date)
            if remaining <= 0 {
                ContentUnavailableView("Expired", systemImage: "timer",
                                       description: Text("This secret is no longer available."))
            } else {
                List {
                    Section {
                        Text(received.title).font(.headline)
                        Text(revealed ? received.secret : String(repeating: "•", count: min(received.secret.count, 16)))
                            .font(.body.monospacedDigit())
                            .textSelection(.enabled)
                        Button(revealed ? "Hide" : "Reveal") { revealed.toggle() }
                        Button(copied ? "Copied" : "Copy") {
                            Clipboard.copy(received.secret, expiresIn: min(AppConfig.clipboardExpiry, remaining))
                            copied = true
                        }
                    }
                    Section {
                        LabeledContent("From", value: "@\(received.sender.handle)")
                        LabeledContent("Fingerprint") {
                            Text(received.sender.fingerprint)
                                .font(.caption.monospacedDigit())
                        }
                        LabeledContent("Expires in",
                                       value: Duration.seconds(remaining).formatted(.time(pattern: .hourMinuteSecond)))
                        if received.viewOnce {
                            Label("View once: gone when you close this", systemImage: "eye")
                                .foregroundStyle(.orange)
                        }
                        Label("Sender signature verified", systemImage: "checkmark.seal")
                            .foregroundStyle(.green)
                    }
                }
            }
        }
    }

    private func open() async {
        received = await model.openShare(entry)
        if received == nil { dismiss() }
    }
}

// MARK: - Composing a share

struct ShareComposerView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let item: VaultItem

    @State private var handle = ""
    @State private var recipient: DirectoryProfile?
    @State private var status: PinStatus?
    @State private var duration: ShareDuration = .oneHour
    @State private var viewOnce = true

    var body: some View {
        NavigationStack {
            SharingGate {
                Form {
                    Section("Recipient") {
                        HStack {
                            TextField("@username", text: $handle)
                                .textInputAutocapitalization(.never)
                                .autocorrectionDisabled()
                                .onSubmit { Task { await find() } }
                            Button("Find") { Task { await find() } }
                                .disabled(handle.isEmpty || model.busy)
                        }
                        if let recipient, let status {
                            recipientInfo(recipient, status: status)
                        }
                    }

                    Section {
                        Picker("Expires after", selection: $duration) {
                            ForEach(ShareDuration.allCases) { Text($0.label).tag($0) }
                        }
                        Toggle("View once", isOn: $viewOnce)
                    } header: {
                        Text("Expiry")
                    } footer: {
                        Text("After this the server deletes it and their app refuses to show it. Anything they've already seen or copied can't be taken back.")
                    }

                    Section {
                        Button("Send “\(item.title)”") { Task { await send() } }
                            .disabled(recipient == nil || status == .changed || model.busy)
                    }
                }
            }
            .navigationTitle("Share")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
            .onChange(of: handle) { _, _ in
                recipient = nil
                status = nil
            }
        }
    }

    @ViewBuilder
    private func recipientInfo(_ profile: DirectoryProfile, status: PinStatus) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("@\(profile.handle)").font(.headline)
            Text(profile.fingerprint).font(.caption.monospacedDigit())
            switch status {
            case .new:
                Label("First time sharing with them. Compare this fingerprint with theirs (Settings) to be sure.",
                      systemImage: "info.circle")
                    .font(.caption).foregroundStyle(.secondary)
            case .verified:
                Label("Same key as last time", systemImage: "checkmark.shield")
                    .font(.caption).foregroundStyle(.green)
            case .changed:
                Label("Their key has changed since you last shared. This can mean a new device, or an attack.",
                      systemImage: "exclamationmark.triangle")
                    .font(.caption).foregroundStyle(.red)
                Button("I've verified the new fingerprint — trust it") {
                    Task {
                        await model.trust(profile)
                        self.status = .verified
                    }
                }
                .font(.caption)
            }
        }
        .padding(.vertical, 4)
    }

    private func find() async {
        guard let result = await model.findRecipient(handle) else { return }
        recipient = result.profile
        status = result.status
    }

    private func send() async {
        guard let recipient else { return }
        if await model.share(itemID: item.id, with: recipient, duration: duration, viewOnce: viewOnce) {
            dismiss()
        }
    }
}

#Preview("Tabs") {
    PreviewHost(.unlocked) { _ in UnlockedTabsView() }
}

#Preview("Received") {
    PreviewHost(.unlocked) { _ in InboxView() }
}

#Preview("Sent") {
    PreviewHost(.unlocked) { _ in SentView() }
}

#Preview("Choose username") {
    PreviewHost(.unregistered) { _ in InboxView() }
}

#Preview("Sharing not set up") {
    PreviewHost(.sharingOff) { _ in InboxView() }
}

#Preview("Received secret") {
    PreviewHost(.unlocked) { ctx in
        if let entry = ctx.receivedEntry {
            ReceivedSecretView(entry: entry)
        }
    }
}

#Preview("View-once warning") {
    PreviewHost(.unlocked) { ctx in
        if let entry = ctx.viewOnceEntry {
            ReceivedSecretView(entry: entry)
        }
    }
}

#Preview("Share composer") {
    PreviewHost(.unlocked) { ctx in
        if let item = ctx.sampleItem {
            ShareComposerView(item: item)
        }
    }
}
