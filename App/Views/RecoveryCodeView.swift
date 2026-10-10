import SwiftUI

struct RecoveryCodeView: View {
    let code: String
    let onDone: () -> Void
    @State private var confirmed = false

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 20) {
                Text("Write this down and keep it somewhere safe. It's the only way back into your vault if you lose your passkey or device.")
                    .foregroundStyle(.secondary)

                Text(code)
                    .font(.system(.title3, design: .monospaced).weight(.semibold))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(.quaternary, in: RoundedRectangle(cornerRadius: 12))

                Label("It's shown only once. We can't recover it for you.", systemImage: "exclamationmark.triangle")
                    .font(.footnote)
                    .foregroundStyle(.orange)

                Toggle("I've written down my recovery code", isOn: $confirmed)

                Spacer()

                Button("Done") { onDone() }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    .frame(maxWidth: .infinity)
                    .disabled(!confirmed)
            }
            .padding(24)
            .navigationTitle("Recovery code")
        }
    }
}

#Preview {
    RecoveryCodeView(code: "7Q2M-K9XA-4HTR-0B6C-PZ3W-N8DE-Y5GF-1JKV") {}
}
