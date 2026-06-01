import Foundation
import Security
import CryptoKit

public enum KeychainError: Error, LocalizedError {
    case creationFailed(OSStatus)
    case itemNotFound
    case accessControlError
    case conversionError
    case unhandledError(OSStatus)
    
    public var errorDescription: String? {
        switch self {
        case .creationFailed(let status):
            return "Failed to create keychain item: \(status)"
        case .itemNotFound:
            return "Vault key not found in Keychain."
        case .accessControlError:
            return "Failed to create access control for Keychain item."
        case .conversionError:
            return "Failed to convert Keychain data to key."
        case .unhandledError(let status):
            return "Keychain error: \(status)"
        }
    }
}

public struct Keychain {
    private static let service = "my.memory.vault"
    private static let account = "vault_key"
    
    /// Generates a new 256-bit vault key and stores it in the Keychain.
    public static func generateAndStoreVaultKey() throws -> SymmetricKey {
        let key = SymmetricKey(size: .bits256)
        let keyData = key.withUnsafeBytes { Data($0) }
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: keyData,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        
        // Delete existing item if any
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(deleteQuery as CFDictionary)
        
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.creationFailed(status)
        }
        
        return key
    }
    
    /// Retrieves the vault key from Keychain.
    public static func retrieveVaultKey() throws -> SymmetricKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        if status == errSecItemNotFound {
            // Key does not exist yet, generate and store a new one
            return try generateAndStoreVaultKey()
        }
        
        guard status == errSecSuccess else {
            throw KeychainError.unhandledError(status)
        }
        
        guard let data = item as? Data else {
            throw KeychainError.conversionError
        }
        
        return SymmetricKey(data: data)
    }
    
    /// Checks if a vault key has already been created in the Keychain
    public static func vaultKeyExists() -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess
    }
}
