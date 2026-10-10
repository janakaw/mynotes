import Foundation
import Sodium
import CryptoKit

/// All cryptography used by the vault. Implemented with libsodium (+ CryptoKit for HKDF/SHA-256).
public protocol CryptoEngine: Sendable {
    func randomBytes(_ count: Int) -> [UInt8]
    /// XChaCha20-Poly1305. Returns nonce ‖ ciphertext ‖ tag.
    func seal(_ plaintext: [UInt8], key: [UInt8], ad: [UInt8]) throws -> [UInt8]
    /// Throws `CryptoError.authenticationFailed` if the key, AD or ciphertext is wrong.
    func open(_ sealed: [UInt8], key: [UInt8], ad: [UInt8]) throws -> [UInt8]
    func pad(_ bytes: [UInt8], blockSize: Int) throws -> [UInt8]
    func unpad(_ bytes: [UInt8], blockSize: Int) throws -> [UInt8]
    func hkdfSHA256(_ ikm: [UInt8], salt: [UInt8], info: String, length: Int) -> [UInt8]
    func sha256(_ bytes: [UInt8]) -> [UInt8]
    func boxKeyPair() throws -> (publicKey: [UInt8], secretKey: [UInt8])
    /// Anonymous sealed box (X25519 + XSalsa20-Poly1305) to a recipient public key.
    func sealToPublicKey(_ plaintext: [UInt8], publicKey: [UInt8]) throws -> [UInt8]
    func openSealed(_ sealed: [UInt8], publicKey: [UInt8], secretKey: [UInt8]) throws -> [UInt8]
    /// Ed25519 detached signature.
    func sign(_ message: [UInt8], secretKey: [UInt8]) throws -> [UInt8]
    func verify(_ message: [UInt8], signature: [UInt8], publicKey: [UInt8]) -> Bool
    func signKeyPair() throws -> (publicKey: [UInt8], secretKey: [UInt8])
    /// Best-effort zeroing of secret material.
    func wipe(_ bytes: inout [UInt8])
}

public final class SodiumCryptoEngine: CryptoEngine, @unchecked Sendable {
    private let sodium = Sodium()

    public init() {}

    public func randomBytes(_ count: Int) -> [UInt8] {
        guard let bytes = sodium.randomBytes.buf(length: count) else {
            fatalError("libsodium random generator failed")
        }
        return bytes
    }

    public func seal(_ plaintext: [UInt8], key: [UInt8], ad: [UInt8]) throws -> [UInt8] {
        let sealed: [UInt8]? = sodium.aead.xchacha20poly1305ietf.encrypt(
            message: plaintext, secretKey: key, additionalData: ad)
        guard let sealed else { throw CryptoError.failure("encrypt") }
        return sealed
    }

    public func open(_ sealed: [UInt8], key: [UInt8], ad: [UInt8]) throws -> [UInt8] {
        guard let plaintext = sodium.aead.xchacha20poly1305ietf.decrypt(
            nonceAndAuthenticatedCipherText: sealed, secretKey: key, additionalData: ad)
        else { throw CryptoError.authenticationFailed }
        return plaintext
    }

    public func pad(_ bytes: [UInt8], blockSize: Int) throws -> [UInt8] {
        var out = bytes
        guard sodium.utils.pad(bytes: &out, blockSize: blockSize) != nil else {
            throw CryptoError.failure("pad")
        }
        return out
    }

    public func unpad(_ bytes: [UInt8], blockSize: Int) throws -> [UInt8] {
        var out = bytes
        guard sodium.utils.unpad(bytes: &out, blockSize: blockSize) != nil else {
            throw CryptoError.failure("unpad")
        }
        return out
    }

    public func hkdfSHA256(_ ikm: [UInt8], salt: [UInt8], info: String, length: Int) -> [UInt8] {
        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm),
            salt: salt,
            info: Array(info.utf8),
            outputByteCount: length)
        return key.withUnsafeBytes { Array($0) }
    }

    public func sha256(_ bytes: [UInt8]) -> [UInt8] {
        Array(SHA256.hash(data: bytes))
    }

    public func boxKeyPair() throws -> (publicKey: [UInt8], secretKey: [UInt8]) {
        guard let pair = sodium.box.keyPair() else { throw CryptoError.failure("box keypair") }
        return (pair.publicKey, pair.secretKey)
    }

    public func sealToPublicKey(_ plaintext: [UInt8], publicKey: [UInt8]) throws -> [UInt8] {
        guard let sealed = sodium.box.seal(message: plaintext, recipientPublicKey: publicKey) else {
            throw CryptoError.failure("seal")
        }
        return sealed
    }

    public func openSealed(_ sealed: [UInt8], publicKey: [UInt8], secretKey: [UInt8]) throws -> [UInt8] {
        guard let plaintext = sodium.box.open(anonymousCipherText: sealed,
                                              recipientPublicKey: publicKey,
                                              recipientSecretKey: secretKey) else {
            throw CryptoError.authenticationFailed
        }
        return plaintext
    }

    public func sign(_ message: [UInt8], secretKey: [UInt8]) throws -> [UInt8] {
        guard let signature = sodium.sign.signature(message: message, secretKey: secretKey) else {
            throw CryptoError.failure("sign")
        }
        return signature
    }

    public func verify(_ message: [UInt8], signature: [UInt8], publicKey: [UInt8]) -> Bool {
        sodium.sign.verify(message: message, publicKey: publicKey, signature: signature)
    }

    public func signKeyPair() throws -> (publicKey: [UInt8], secretKey: [UInt8]) {
        guard let pair = sodium.sign.keyPair() else { throw CryptoError.failure("sign keypair") }
        return (pair.publicKey, pair.secretKey)
    }

    public func wipe(_ bytes: inout [UInt8]) {
        sodium.utils.zero(&bytes)
    }
}
