import SwiftUI
import CryptoKit

/// Spike from the design review: confirm the passkey PRF output is identical on every
/// device the passkey syncs to. Run step 1 on device A, step 2 on A and on device B
/// (same Apple Account, iCloud Keychain on). The fingerprints must match.
struct PRFTestView: View {
    let unlocker: PasskeyPRFUnlocker
    @State private var log: [String] = []
    @State private var running = false

    private let salt = Data(SHA256.hash(data: Data("secretshare/prf-spike/v1".utf8)))

    var body: some View {
        List {
            Section {
                Button("1. Create test passkey") { Task { await createPasskey() } }
                Button("2. Evaluate PRF (pick a SecretShare passkey)") { Task { await evaluate() } }
            } footer: {
                Text("Fingerprint = first 8 bytes of SHA-256(PRF output). The PRF output itself is never shown.")
            }
            Section("Results") {
                if log.isEmpty {
                    Text("No results yet").foregroundStyle(.secondary)
                }
                ForEach(Array(log.enumerated()), id: \.offset) { _, line in
                    Text(line).font(.footnote.monospacedDigit())
                }
            }
        }
        .navigationTitle("PRF test")
        .disabled(running)
    }

    private func createPasskey() async {
        running = true
        defer { running = false }
        do {
            let id = try await unlocker.registerPasskey(name: "SecretShare PRF test")
            log.append("Created passkey \(short(id))")
        } catch {
            log.append("Create failed: \(error.localizedDescription)")
        }
    }

    private func evaluate() async {
        running = true
        defer { running = false }
        do {
            let result = try await unlocker.evaluatePRFDiscoverable(salt: salt)
            let digest = SHA256.hash(data: result.secret)
            let fp = digest.prefix(8).map { String(format: "%02X", $0) }.joined()
            log.append("Passkey \(short(result.credentialID)) → \(fp)")
        } catch {
            log.append("Evaluate failed: \(error.localizedDescription)")
        }
    }

    private func short(_ data: Data) -> String {
        data.prefix(4).map { String(format: "%02x", $0) }.joined()
    }
}

#Preview {
    NavigationStack {
        PRFTestView(unlocker: PasskeyPRFUnlocker(relyingPartyID: "example.com"))
    }
}
