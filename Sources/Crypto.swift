import Foundation
import CryptoKit

public enum CryptoError: Error, LocalizedError {
    case encryptionFailed
    case decryptionFailed
    case invalidCiphertext
    
    public var errorDescription: String? {
        switch self {
        case .encryptionFailed:
            return "Encryption failed."
        case .decryptionFailed:
            return "Decryption failed. Please ensure the vault key is correct."
        case .invalidCiphertext:
            return "Invalid ciphertext format."
        }
    }
}

public struct Crypto {
    /// Encrypts plaintext string using AES-256-GCM and returns a Base64 combined representation (IV + ciphertext + Tag)
    public static func encrypt(_ plaintext: String, using key: SymmetricKey) throws -> String {
        guard let data = plaintext.data(using: .utf8) else {
            throw CryptoError.encryptionFailed
        }
        let sealedBox = try AES.GCM.seal(data, using: key)
        guard let combined = sealedBox.combined else {
            throw CryptoError.encryptionFailed
        }
        return combined.base64EncodedString()
    }
    
    /// Decrypts a Base64 combined representation (IV + ciphertext + Tag) using AES-256-GCM and returns plaintext string
    public static func decrypt(_ base64Ciphertext: String, using key: SymmetricKey) throws -> String {
        guard let data = Data(base64Encoded: base64Ciphertext) else {
            throw CryptoError.invalidCiphertext
        }
        let sealedBox = try AES.GCM.SealedBox(combined: data)
        let decryptedData = try AES.GCM.open(sealedBox, using: key)
        guard let plaintext = String(data: decryptedData, encoding: .utf8) else {
            throw CryptoError.decryptionFailed
        }
        return plaintext
    }
}
