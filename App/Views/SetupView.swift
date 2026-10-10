import SwiftUI

struct SetupView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        VStack(spacing: 20) {
            Spacer()
            Image(systemName: "lock.shield")
                .font(.system(size: 64))
                .foregroundStyle(.tint)
            Text("Create your vault")
                .font(.title.bold())
            Text("Secrets are encrypted on this device before they're stored. Nobody else, including Apple, can read them.")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
            Spacer()

            if model.passkeysAvailable {
                Button {
                    Task { await model.setup(kind: .passkeyPRF) }
                } label: {
                    Label("Create with passkey", systemImage: "person.badge.key")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
            }

            Button {
                Task { await model.setup(kind: .devLocal) }
            } label: {
                Label("Create with device key (dev)", systemImage: "hammer")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)
            .controlSize(.large)

            if !model.passkeysAvailable {
                Text("Passkeys are off until AppConfig.relyingPartyID is set. The device key is for testing only.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
        }
        .padding(24)
        .disabled(model.busy)
        .overlay { if model.busy { ProgressView() } }
    }
}

#Preview {
    PreviewHost(.setup) { _ in SetupView() }
}
