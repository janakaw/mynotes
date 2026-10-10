import SwiftUI
import SecretShareCore

extension AppModel {
    var sharingConfigured: Bool { sharing != nil }

    var myProfile: DirectoryProfile? {
        if case .registered(let profile) = registration { return profile }
        return nil
    }

    func refreshSharing() async {
        guard let sharing, screen == .unlocked else { return }
        do {
            let state = try await sharing.registrationState()
            registration = state
            if case .registered = state {
                inbox = try await sharing.inbox()
                sent = try await sharing.sent()
            }
        } catch {
            show(error)
        }
    }

    func register(handle: String) async -> Bool {
        guard let sharing else { return false }
        var ok = false
        await run {
            try await sharing.register(handle: handle)
            ok = true
        }
        if ok { await refreshSharing() }
        return ok
    }

    func findRecipient(_ handle: String) async -> (profile: DirectoryProfile, status: PinStatus)? {
        guard let sharing else { return nil }
        var result: (profile: DirectoryProfile, status: PinStatus)?
        await run {
            result = try await sharing.findRecipient(handle: handle)
        }
        return result
    }

    func trust(_ profile: DirectoryProfile) async {
        await sharing?.trust(profile)
    }

    func share(itemID: UUID, with recipient: DirectoryProfile,
               duration: ShareDuration, viewOnce: Bool) async -> Bool {
        guard let sharing else { return false }
        var ok = false
        await run {
            try await sharing.share(itemID: itemID, with: recipient,
                                    duration: duration.seconds, viewOnce: viewOnce)
            sent = try await sharing.sent()
            ok = true
        }
        return ok
    }

    func openShare(_ entry: ShareListEntry) async -> ReceivedSecret? {
        guard let sharing else { return nil }
        var received: ReceivedSecret?
        await run {
            received = try await sharing.open(entry.summary)
        }
        return received
    }

    func revokeShare(_ id: UUID) async {
        guard let sharing else { return }
        await run {
            try await sharing.revoke(id)
        }
        await refreshSharing()
    }
}

enum Clipboard {
    /// Copies text that stays on this device only and clears itself after `seconds`.
    static func copy(_ text: String, expiresIn seconds: TimeInterval) {
        UIPasteboard.general.setItems(
            [["public.utf8-plain-text": text]],
            options: [
                .localOnly: true,
                .expirationDate: Date().addingTimeInterval(max(1, seconds)),
            ])
    }
}
