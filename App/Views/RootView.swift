import SwiftUI

struct RootView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        ZStack {
            switch model.screen {
            case .loading:
                ProgressView()
            case .setup:
                SetupView()
            case .locked:
                UnlockView()
            case .unlocked:
                UnlockedTabsView()
            }
            if model.obscured {
                PrivacyCover()
            }
        }
        .sheet(isPresented: Binding(
            get: { model.recoveryCodeToShow != nil },
            set: { if !$0 { model.recoveryCodeToShow = nil } }
        )) {
            RecoveryCodeView(code: model.recoveryCodeToShow ?? "") {
                model.recoveryCodeToShow = nil
            }
            .interactiveDismissDisabled()
        }
        .alert("Something went wrong", isPresented: Binding(
            get: { model.errorMessage != nil },
            set: { if !$0 { model.errorMessage = nil } }
        )) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(model.errorMessage ?? "")
        }
        .task { await model.start() }
    }
}

struct PrivacyCover: View {
    var body: some View {
        ZStack {
            Rectangle().fill(.background)
            Image(systemName: "lock.fill")
                .font(.system(size: 48))
                .foregroundStyle(.secondary)
        }
        .ignoresSafeArea()
    }
}

#Preview("Setup") {
    PreviewHost(.setup) { _ in RootView() }
}

#Preview("Locked") {
    PreviewHost(.locked) { _ in RootView() }
}

#Preview("Unlocked") {
    PreviewHost(.unlocked) { _ in RootView() }
}
