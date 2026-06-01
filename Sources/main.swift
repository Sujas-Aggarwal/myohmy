import Foundation
import ArgumentParser
import CryptoKit
import LocalAuthentication

// Helper to extract tags from text
func extractTags(from text: String) -> [String] {
    let pattern = "#[a-zA-Z0-9_\\-]+"
    guard let regex = try? NSRegularExpression(pattern: pattern, options: []) else { return [] }
    let matches = regex.matches(in: text, options: [], range: NSRange(text.startIndex..., in: text))
    return matches.map { match in
        let range = Range(match.range, in: text)!
        return String(text[range]).lowercased()
    }
}

struct CLI {
    static func printUsage() {
        let usage = """
        My - Personal Memory Database (v1.0.0)
        
        Usage:
          my add <key>=<value> [<key2>=<value2> ...] [--secret]
          my add "<note content>" [--secret]
          my <key>
          my #<tag>
          my find <query> [--all] [--limit=<limit>]
          my delete <key_or_id>
          my recent
          my keys
          my tags
          my stats
        """
        print(usage)
    }
}

// Intercept natural lookup or route to ArgumentParser
let args = Array(CommandLine.arguments.dropFirst())

if args.isEmpty {
    CLI.printUsage()
} else {
    let firstArg = args[0]
    let subcommands = ["add", "delete", "find", "recent", "keys", "tags", "stats"]
    
    if subcommands.contains(firstArg) {
        MyCLI.main()
    } else {
        // Natural lookup
        let query = args.joined(separator: " ")
        handleNaturalLookup(query: query)
    }
}

// Swift ArgumentParser setup
struct MyCLI: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "my",
        abstract: "Secure, local-first extension of your memory.",
        subcommands: [Add.self, Delete.self, Find.self, Recent.self, Keys.self, Tags.self, Stats.self]
    )
}

// Authentication Helper
struct AuthHelper {
    /// Attempts to retrieve the Vault Key. Triggers Touch ID if not cached in the 5-minute session.
    static func getVaultKey() throws -> SymmetricKey {
        if let cachedKey = Session.getVaultKeyFromSession() {
            return cachedKey
        }
        
        let context = LAContext()
        var error: NSError?
        
        // Check if biometrics/passcode evaluation is available
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            // Headless / CI runner fallback: retrieve key directly from standard Keychain
            let key = try Keychain.retrieveVaultKey()
            Session.saveVaultKeyToSession(key)
            return key
        }
        
        let semaphore = DispatchSemaphore(value: 0)
        var authSuccess = false
        
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Authorize access to your personal memory vault") { success, _ in
            authSuccess = success
            semaphore.signal()
        }
        
        _ = semaphore.wait(timeout: .distantFuture)
        
        guard authSuccess else {
            throw NSError(domain: "Auth", code: 4, userInfo: [NSLocalizedDescriptionKey: "Authentication failed."])
        }
        
        // Once biometrics/passcode authorized, fetch Vault Key from standard Keychain
        let key = try Keychain.retrieveVaultKey()
        // Save to 5-minute session cache
        Session.saveVaultKeyToSession(key)
        return key
    }
    
    /// Checks if we currently have an active 5-minute session
    static func isSessionAuthenticated() -> Bool {
        return Session.getVaultKeyFromSession() != nil
    }
}

// MARK: - Subcommands

extension MyCLI {
    
    struct Add: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Add key-value pairs or notes.")
        
        @Argument(help: "Key-value pairs (key=value) or notes.")
        var inputs: [String]
        
        @Flag(name: .shortAndLong, help: "Encrypt entries securely using AES-256-GCM and Touch ID protection.")
        var secret: Bool = false
        
        func run() throws {
            let db = try Database()
            var vaultKey: SymmetricKey?
            
            if secret {
                // Trigger/verify authentication
                vaultKey = try AuthHelper.getVaultKey()
            }
            
            for input in inputs {
                if let eqIndex = input.firstIndex(of: "=") {
                    let key = String(input[..<eqIndex]).trimmingCharacters(in: .whitespacesAndNewlines)
                    let value = String(input[input.index(after: eqIndex)...]).trimmingCharacters(in: .whitespacesAndNewlines)
                    
                    if secret, let keyObj = vaultKey {
                        let encryptedValue = try Crypto.encrypt(value, using: keyObj)
                        try db.addOrUpdateKV(key: key, value: encryptedValue, encrypted: true)
                        print("Added secret: \(key)")
                    } else {
                        try db.addOrUpdateKV(key: key, value: value, encrypted: false)
                        print("Added: \(key) = \(value)")
                    }
                } else {
                    let note = input.trimmingCharacters(in: .whitespacesAndNewlines)
                    if secret, let keyObj = vaultKey {
                        let encryptedNote = try Crypto.encrypt(note, using: keyObj)
                        try db.addNote(content: encryptedNote, encrypted: true)
                        print("Added secret note.")
                    } else {
                        try db.addNote(content: note, encrypted: false)
                        print("Added note.")
                    }
                }
            }
        }
    }
    
    struct Delete: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Delete a key-value pair, note, or recent entries.")
        
        @Argument(help: "The key name, entry ID, or 'recent' to delete.")
        var target: String
        
        @Option(name: .shortAndLong, help: "Number of recent entries to delete (only applies if target is 'recent').")
        var limit: Int = 1
        
        func run() throws {
            let db = try Database()
            
            if target == "recent" {
                let recent = try db.getRecentEntries(limit: limit)
                if recent.isEmpty {
                    print("No recent entries found to delete.")
                    return
                }
                for entry in recent {
                    if entry.encrypted {
                        _ = try AuthHelper.getVaultKey() // Require Touch ID if any are encrypted
                    }
                    if try db.deleteEntryByID(entry.id) {
                        if entry.type == "kv", let key = entry.key {
                            print("Deleted recent key '\(key)'.")
                        } else {
                            print("Deleted recent note #\(entry.id).")
                        }
                    }
                }
            } else if let id = Int64(target) {
                if let entry = try db.getEntryByID(id) {
                    if entry.encrypted {
                        _ = try AuthHelper.getVaultKey() // Require Touch ID
                    }
                    if try db.deleteEntryByID(id) {
                        print("Deleted entry \(id).")
                    } else {
                        print("Failed to delete entry \(id).")
                    }
                } else {
                    print("Entry ID \(id) not found.")
                }
            } else {
                if let entry = try db.getEntryByKey(target) {
                    if entry.encrypted {
                        _ = try AuthHelper.getVaultKey() // Require Touch ID
                    }
                    if try db.deleteEntryByKey(target) {
                        print("Deleted key '\(target)'.")
                    } else {
                        print("Failed to delete key '\(target)'.")
                    }
                } else {
                    print("Key '\(target)' not found.")
                }
            }
        }
    }
    
    struct Find: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Search memory database.")
        
        @Argument(help: "Search query.")
        var query: String
        
        @Flag(name: .shortAndLong, help: "Decrypt and search secret entries as well.")
        var all: Bool = false
        
        @Option(name: .shortAndLong, help: "Limit the number of returned matches.")
        var limit: Int?
        
        func run() throws {
            let db = try Database()
            var vaultKey: SymmetricKey?
            
            if all {
                vaultKey = try AuthHelper.getVaultKey()
            }
            
            let results = try performRankedSearch(query: query, db: db, vaultKey: vaultKey)
            
            let finalResults = limit != nil ? Array(results.prefix(limit!)) : results
            
            if finalResults.isEmpty {
                print("No matches found.")
            } else {
                for entry in finalResults {
                    printEntry(entry, vaultKey: vaultKey)
                }
            }
        }
    }
    
    struct Recent: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "List recent entries.")
        
        func run() throws {
            let db = try Database()
            let recent = try db.getRecentEntries(limit: 10)
            
            if recent.isEmpty {
                print("No entries found.")
                return
            }
            
            let vaultKey = Session.getVaultKeyFromSession()
            
            print("--- Recent Entries ---")
            for entry in recent {
                printEntry(entry, vaultKey: vaultKey)
            }
        }
    }
    
    struct Keys: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "List all keys.")
        
        func run() throws {
            let db = try Database()
            let keys = try db.listAllKeys()
            
            if keys.isEmpty {
                print("No keys found.")
            } else {
                for key in keys {
                    print(key)
                }
            }
        }
    }
    
    struct Tags: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "List all unique tags.")
        
        func run() throws {
            let db = try Database()
            let entries = try db.getAllEntries()
            var vaultKey: SymmetricKey?
            
            if AuthHelper.isSessionAuthenticated() {
                vaultKey = Session.getVaultKeyFromSession()
            }
            
            var tagsSet = Set<String>()
            for entry in entries {
                var content = entry.value
                if entry.encrypted {
                    if let keyObj = vaultKey, let decrypted = try? Crypto.decrypt(entry.value, using: keyObj) {
                        content = decrypted
                    } else {
                        continue // Skip encrypted if we can't decrypt
                    }
                }
                
                let extracted = extractTags(from: content) + (entry.key.map { extractTags(from: $0) } ?? [])
                for t in extracted {
                    tagsSet.insert(t)
                }
            }
            
            if tagsSet.isEmpty {
                print("No tags found.")
            } else {
                for tag in tagsSet.sorted() {
                    print(tag)
                }
            }
        }
    }
    
    struct Stats: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Display database statistics.")
        
        func run() throws {
            let db = try Database()
            let entries = try db.getAllEntries()
            
            let total = entries.count
            let keysCount = entries.filter { $0.type == "kv" }.count
            let notesCount = entries.filter { $0.type == "note" }.count
            let publicCount = entries.filter { !$0.encrypted }.count
            let secretCount = entries.filter { $0.encrypted }.count
            
            let dbSize = db.getDatabaseSize()
            let dbSizeStr = formatBytes(dbSize)
            
            var oldestStr = "N/A"
            var newestStr = "N/A"
            
            let formatter = DateFormatter()
            formatter.dateFormat = "yyyy-MM-dd"
            
            if let oldest = entries.map({ $0.createdAt }).min() {
                oldestStr = formatter.string(from: Date(timeIntervalSince1970: TimeInterval(oldest)))
            }
            if let newest = entries.map({ $0.updatedAt }).max() {
                newestStr = formatter.string(from: Date(timeIntervalSince1970: TimeInterval(newest)))
            }
            
            // Count tags (include secrets only if already authenticated)
            let vaultKey = Session.getVaultKeyFromSession()
            var tagsSet = Set<String>()
            for entry in entries {
                var content = entry.value
                if entry.encrypted {
                    if let keyObj = vaultKey, let decrypted = try? Crypto.decrypt(entry.value, using: keyObj) {
                        content = decrypted
                    } else {
                        continue
                    }
                }
                let extracted = extractTags(from: content) + (entry.key.map { extractTags(from: $0) } ?? [])
                for t in extracted {
                    tagsSet.insert(t)
                }
            }
            
            let statsOutput = """
            Total Entries: \(total)
            Keys: \(keysCount)
            Notes: \(notesCount)

            Public Entries: \(publicCount)
            Secret Entries: \(secretCount)

            Tags: \(tagsSet.count)

            Database Size: \(dbSizeStr)

            Oldest Entry: \(oldestStr)
            Newest Entry: \(newestStr)
            """
            print(statsOutput)
        }
        
        private func formatBytes(_ bytes: Int64) -> String {
            let kb = Double(bytes) / 1024.0
            if kb < 1024.0 {
                return String(format: "%.1f KB", kb)
            }
            let mb = kb / 1024.0
            return String(format: "%.1f MB", mb)
        }
    }
}

// MARK: - Natural Lookup & Search Engine

func handleNaturalLookup(query: String) {
    do {
        let db = try Database()
        let vaultKey = Session.getVaultKeyFromSession()
        
        // 1. Is it a tag lookup (starts with #)?
        if query.hasPrefix("#") {
            let results = try performRankedSearch(query: query, db: db, vaultKey: vaultKey)
            if results.isEmpty {
                print("No entries matching tag '\(query)'.")
            } else {
                for entry in results {
                    printEntry(entry, vaultKey: vaultKey)
                }
            }
            return
        }
        
        // 2. Is it an exact key lookup?
        if let entry = try db.getEntryByKey(query) {
            if entry.encrypted {
                let key = try AuthHelper.getVaultKey()
                if let decrypted = try? Crypto.decrypt(entry.value, using: key) {
                    print(decrypted)
                } else {
                    print("Error: Decryption failed.")
                }
            } else {
                print(entry.value)
            }
            return
        }
        
        // 3. Fallback to automatic note search
        let results = try performRankedSearch(query: query, db: db, vaultKey: vaultKey)
        if results.isEmpty {
            print("No entry or note matches '\(query)'.")
        } else {
            // Print the most relevant match or a list of matches
            if results.count == 1 {
                printDecryptedValue(results[0], vaultKey: vaultKey)
            } else {
                for entry in results {
                    printEntry(entry, vaultKey: vaultKey)
                }
            }
        }
    } catch {
        print("Error: \(error.localizedDescription)")
    }
}

/// Performs a ranked search over candidate entries (including decrypted secrets if vaultKey is provided)
func performRankedSearch(query: String, db: Database, vaultKey: SymmetricKey?) throws -> [Entry] {
    let allEntries = try db.getAllEntries()
    let q = query.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
    let qWords = q.split(separator: " ").map { String($0) }
    
    struct RankedEntry {
        let entry: Entry
        let score: Int
    }
    
    var rankedCandidates = [RankedEntry]()
    
    for entry in allEntries {
        // Skip encrypted entries if we don't have the vault key to decrypt them
        var entryValue = entry.value
        if entry.encrypted {
            guard let keyObj = vaultKey,
                  let decrypted = try? Crypto.decrypt(entry.value, using: keyObj) else {
                continue
            }
            entryValue = decrypted
        }
        
        var score = 0
        let entryKeyLower = entry.key?.lowercased()
        let entryValueLower = entryValue.lowercased()
        
        // 1. Exact key match
        if let k = entryKeyLower, k == q {
            score += 1000
        }
        
        // 2. Prefix key match
        if let k = entryKeyLower, k.hasPrefix(q) {
            score += 500
        }
        
        // 3. Exact phrase match in value
        if entryValueLower.contains(q) {
            score += 200
        } else if let k = entryKeyLower, k.contains(q) {
            score += 150
        }
        
        // 4. Individual word matching (FTS-like fallback)
        var wordMatches = 0
        for word in qWords {
            if entryValueLower.contains(word) {
                wordMatches += 1
            }
            if let k = entryKeyLower, k.contains(word) {
                wordMatches += 1
            }
        }
        
        if wordMatches > 0 {
            score += wordMatches * 20
        }
        
        if score > 0 {
            rankedCandidates.append(RankedEntry(entry: entry, score: score))
        }
    }
    
    // Sort by score DESC, and then by updated_at DESC
    let sorted = rankedCandidates.sorted {
        if $0.score == $1.score {
            return $0.entry.updatedAt > $1.entry.updatedAt
        }
        return $0.score > $1.score
    }
    
    return sorted.map { $0.entry }
}

// MARK: - Display Utilities

func printEntry(_ entry: Entry, vaultKey: SymmetricKey?) {
    let typeIndicator = entry.type == "kv" ? "[\(entry.key ?? "")]" : "[Note #\(entry.id)]"
    let lockIndicator = entry.encrypted ? "🔒 " : ""
    
    var displayValue = entry.value
    if entry.encrypted {
        if let key = vaultKey, let decrypted = try? Crypto.decrypt(entry.value, using: key) {
            displayValue = decrypted
        } else {
            displayValue = "<encrypted>"
        }
    }
    
    print("\(lockIndicator)\(typeIndicator) \(displayValue)")
}

func printDecryptedValue(_ entry: Entry, vaultKey: SymmetricKey?) {
    if entry.encrypted {
        guard let key = vaultKey, let decrypted = try? Crypto.decrypt(entry.value, using: key) else {
            print("🔒 <encrypted - authorization required>")
            return
        }
        print(decrypted)
    } else {
        print(entry.value)
    }
}
