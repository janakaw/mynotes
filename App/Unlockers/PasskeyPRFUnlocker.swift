import AuthenticationServices
import CryptoKit
import UIKit
import SecretShareCore

/// Unlocks the vault with a passkey and the WebAuthn PRF extension (iOS 18+).
/// The PRF output is computed inside the authenticator (Secure Enclave / iCloud Keychain)
/// for a given salt, never leaves the device, and is identical on every device the
/// passkey syncs to. It is used only as key material; no server verifies the assertion.
@MainActor
final class PasskeyPRFUnlocker: NSObject, Unlocker {
    nonisolated var kind: UnlockerKind { .passkeyPRF }

    private let relyingPartyID: String
    private var controller: ASAuthorizationController?
    private var continuation: CheckedContinuation<ASAuthorization, Error>?

    init(relyingPartyID: String) {
        self.relyingPartyID = relyingPartyID
        super.init()
    }

    private var provider: ASAuthorizationPlatformPublicKeyCredentialProvider {
        ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: relyingPartyID)
    }

    // MARK: Unlocker

    func enroll() async throws -> UnlockerEnrollment {
        let credentialID = try await registerPasskey(name: "SecretShare vault")
        let salt = Data(Self.randomBytes(32))
        // Second prompt: evaluate PRF on the new passkey to get the secret.
        let result = try await evaluatePRF(salts: [credentialID: salt])
        return UnlockerEnrollment(secret: result.secret, credentialID: credentialID,
                                  prfSalt: salt, label: "Passkey")
    }

    func secret(for candidates: [UnlockerEntry]) async throws -> (secret: [UInt8], credentialID: Data?) {
        var salts: [Data: Data] = [:]
        for entry in candidates {
            if let credentialID = entry.credentialID, let salt = entry.prfSalt {
                salts[credentialID] = salt
            }
        }
        guard !salts.isEmpty else { throw VaultError.noMatchingUnlocker }
        let result = try await evaluatePRF(salts: salts)
        return (result.secret, result.credentialID)
    }

    // MARK: Passkey operations (also used by the PRF test screen)

    /// Creates a passkey and checks it supports PRF. Returns its credential ID.
    func registerPasskey(name: String) async throws -> Data {
        let request = provider.createCredentialRegistrationRequest(
            challenge: Data(Self.randomBytes(32)),
            name: name,
            userID: Data(Self.randomBytes(16)))
        request.prf = .checkForSupport

        let authorization = try await perform(request)
        guard let registration = authorization.credential
                as? ASAuthorizationPlatformPublicKeyCredentialRegistration else {
            throw VaultError.unlockerFailed("Unexpected passkey registration response.")
        }
        if let prf = registration.prf, !prf.isSupported {
            throw VaultError.prfUnsupported
        }
        return registration.credentialID
    }

    /// Runs a passkey assertion with per-credential PRF salts.
    func evaluatePRF(salts: [Data: Data]) async throws -> (secret: [UInt8], credentialID: Data) {
        let request = provider.createCredentialAssertionRequest(challenge: Data(Self.randomBytes(32)))
        request.allowedCredentials = salts.keys.map {
            ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: $0)
        }
        var perCredential: [Data: ASAuthorizationPublicKeyCredentialPRFAssertionInput.InputValues] = [:]
        for (credentialID, salt) in salts {
            perCredential[credentialID] = .init(saltInput1: salt, saltInput2: nil)
        }
        request.prf = .perCredentialInputValues(perCredential)
        return try await performAssertion(request)
    }

    /// Discoverable assertion (user picks any passkey for this domain) with one salt.
    func evaluatePRFDiscoverable(salt: Data) async throws -> (secret: [UInt8], credentialID: Data) {
        let request = provider.createCredentialAssertionRequest(challenge: Data(Self.randomBytes(32)))
        request.prf = .inputValues(.init(saltInput1: salt, saltInput2: nil), perCredentialInputValues: nil)
        return try await performAssertion(request)
    }

    private func performAssertion(
        _ request: ASAuthorizationPlatformPublicKeyCredentialAssertionRequest
    ) async throws -> (secret: [UInt8], credentialID: Data) {
        let authorization = try await perform(request)
        guard let assertion = authorization.credential
                as? ASAuthorizationPlatformPublicKeyCredentialAssertion else {
            throw VaultError.unlockerFailed("Unexpected passkey assertion response.")
        }
        guard let prf = assertion.prf else { throw VaultError.prfUnsupported }
        let key: SymmetricKey = prf.first
        let secret = key.withUnsafeBytes { Array($0) }
        return (secret, assertion.credentialID)
    }

    // MARK: ASAuthorizationController plumbing

    private func perform(_ request: ASAuthorizationRequest) async throws -> ASAuthorization {
        guard continuation == nil else {
            throw VaultError.unlockerFailed("A passkey request is already in progress.")
        }
        return try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
            let controller = ASAuthorizationController(authorizationRequests: [request])
            controller.delegate = self
            controller.presentationContextProvider = self
            self.controller = controller
            controller.performRequests()
        }
    }

    private func finish(_ result: Result<ASAuthorization, Error>) {
        continuation?.resume(with: result)
        continuation = nil
        controller = nil
    }

    private static func randomBytes(_ count: Int) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: count)
        _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        return bytes
    }
}

extension PasskeyPRFUnlocker: ASAuthorizationControllerDelegate,
                              ASAuthorizationControllerPresentationContextProviding {
    nonisolated func authorizationController(controller: ASAuthorizationController,
                                             didCompleteWithAuthorization authorization: ASAuthorization) {
        MainActor.assumeIsolated {
            finish(.success(authorization))
        }
    }

    nonisolated func authorizationController(controller: ASAuthorizationController,
                                             didCompleteWithError error: Error) {
        let mapped: VaultError
        if let authError = error as? ASAuthorizationError, authError.code == .canceled {
            mapped = .cancelled
        } else {
            mapped = .unlockerFailed("Passkey error: \(error.localizedDescription). "
                + "Check the Associated Domains entitlement and apple-app-site-association file.")
        }
        MainActor.assumeIsolated {
            finish(.failure(mapped))
        }
    }

    nonisolated func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        MainActor.assumeIsolated {
            let windows = UIApplication.shared.connectedScenes
                .compactMap { $0 as? UIWindowScene }
                .flatMap(\.windows)
            return windows.first(where: \.isKeyWindow) ?? windows.first ?? ASPresentationAnchor()
        }
    }
}
