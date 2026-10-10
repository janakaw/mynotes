import Foundation
import Security
import SecretShareCore

/// DEVELOPMENT ONLY. A random 32-byte key in this device's Keychain
/// (ThisDeviceOnly, never synced). Lets the full app run in the Simulator
/// before passkeys are configured. Not a substitute for the passkey in production.
final class DevLocalUnlocker: Unlocker {
    let kind: UnlockerKind = .devLocal
    private static let service = "secretshare.dev-unlocker"

    func enroll() async throws -> UnlockerEnrollment {
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw VaultError.unlockerFailed("Couldn't generate a device key.")
        }
        let account = UUID().uuidString
        try Self.store(Data(bytes), account: account)
        return UnlockerEnrollment(secret: bytes, credentialID: Data(account.utf8),
                                  prfSalt: nil, label: "Device key (dev)")
    }

    func secret(for candidates: [UnlockerEntry]) async throws -> (secret: [UInt8], credentialID: Data?) {
        for entry in candidates {
            guard let credentialID = entry.credentialID,
                  let account = String(data: credentialID, encoding: .utf8),
                  let data = Self.load(account: account) else { continue }
            return (Array(data), credentialID)
        }
        throw VaultError.unlockerFailed("No device key for this vault on this device. Use your recovery code.")
    }

    static func deleteAllKeys() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
        ]
        SecItemDelete(query as CFDictionary)
    }

    private static func store(_ data: Data, account: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw VaultError.unlockerFailed("Keychain error \(status).")
        }
    }

    private static func load(account: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess else { return nil }
        return result as? Data
    }
}
