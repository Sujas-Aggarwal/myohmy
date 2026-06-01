import Foundation
import Security
import CryptoKit

public struct Session {
    private static let sessionService = "my.memory.session"
    private static let sessionAccount = "session_key"
    
    private static var sessionDirectory: URL {
        let home = FileManager.default.homeDirectoryForCurrentUser
        return home.appendingPathComponent(".my")
    }
    
    private static var sessionFileURL: URL {
        return sessionDirectory.appendingPathComponent(".session")
    }
    
    struct SessionPayload: Codable {
        let encryptedVaultKey: String
        let expiresAt: TimeInterval
    }
    
    /// Retrieves or generates the ephemeral session encryption key stored in Keychain (silently, without Touch ID)
    private static func getOrCreateSessionKey() throws -> SymmetricKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: sessionService,
            kSecAttrAccount as String: sessionAccount,
            kSecReturnData as String: true
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        if status == errSecSuccess, let data = item as? Data {
            return SymmetricKey(data: data)
        }
        
        // Generate new key and store it
        let newKey = SymmetricKey(size: .bits256)
        let keyData = newKey.withUnsafeBytes { Data($0) }
        
        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: sessionService,
            kSecAttrAccount as String: sessionAccount,
            kSecValueData as String: keyData,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        
        // Delete existing item if any
        SecItemDelete(query as CFDictionary)
        
        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw KeychainError.creationFailed(addStatus)
        }
        
        return newKey
    }
    
    /// Caches the Vault Key for 5 minutes.
    public static func saveVaultKeyToSession(_ vaultKey: SymmetricKey) {
        do {
            // Ensure directory exists
            try FileManager.default.createDirectory(at: sessionDirectory, withIntermediateDirectories: true, attributes: nil)
            
            let sessionKey = try getOrCreateSessionKey()
            let vaultKeyData = vaultKey.withUnsafeBytes { Data($0) }
            
            // Encrypt Vault Key using Session Key
            let sealedBox = try AES.GCM.seal(vaultKeyData, using: sessionKey)
            guard let combined = sealedBox.combined else { return }
            let encryptedVaultKeyBase64 = combined.base64EncodedString()
            
            let expiration = Date().addingTimeInterval(300).timeIntervalSince1970 // 5 minutes
            let payload = SessionPayload(encryptedVaultKey: encryptedVaultKeyBase64, expiresAt: expiration)
            
            let jsonData = try JSONEncoder().encode(payload)
            try jsonData.write(to: sessionFileURL, options: .atomic)
        } catch {
            // Silently ignore or write to stderr if logging is needed (we want to remain clean)
        }
    }
    
    /// Tries to retrieve the Vault Key from the 5-minute session cache without triggering Touch ID.
    /// Returns nil if the session has expired or is invalid.
    public static func getVaultKeyFromSession() -> SymmetricKey? {
        do {
            guard FileManager.default.fileExists(atPath: sessionFileURL.path) else {
                return nil
            }
            
            let data = try Data(contentsOf: sessionFileURL)
            let payload = try JSONDecoder().decode(SessionPayload.self, from: data)
            
            // Check expiration
            guard Date().timeIntervalSince1970 < payload.expiresAt else {
                clearSession()
                return nil
            }
            
            let sessionKey = try getOrCreateSessionKey()
            guard let combinedData = Data(base64Encoded: payload.encryptedVaultKey) else {
                clearSession()
                return nil
            }
            
            let sealedBox = try AES.GCM.SealedBox(combined: combinedData)
            let decryptedData = try AES.GCM.open(sealedBox, using: sessionKey)
            
            return SymmetricKey(data: decryptedData)
        } catch {
            clearSession()
            return nil
        }
    }
    
    /// Clears the session file.
    public static func clearSession() {
        try? FileManager.default.removeItem(at: sessionFileURL)
    }
}
