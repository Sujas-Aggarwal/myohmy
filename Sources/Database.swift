import Foundation
import SQLite3

internal let SQLITE_TRANSIENT = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

public struct Entry: Identifiable {
    public let id: Int64
    public let type: String      // "kv" or "note"
    public let key: String?      // Key for KV pairs, nil for notes
    public let value: String     // Unencrypted value/note content or ciphertext
    public let encrypted: Bool
    public let createdAt: Int64  // Unix timestamp
    public let updatedAt: Int64  // Unix timestamp
}

public class Database {
    private var db: OpaquePointer?
    
    private static var dbDirectory: URL {
        let home = FileManager.default.homeDirectoryForCurrentUser
        return home.appendingPathComponent(".my")
    }
    
    private static var dbFileURL: URL {
        return dbDirectory.appendingPathComponent("database.sqlite")
    }
    
    public init() throws {
        // Ensure directory exists
        try FileManager.default.createDirectory(at: Database.dbDirectory, withIntermediateDirectories: true, attributes: nil)
        
        let path = Database.dbFileURL.path
        if sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nil) != SQLITE_OK {
            let errorMsg = db.map { String(cString: sqlite3_errmsg($0)) } ?? "Unknown error"
            throw NSError(domain: "SQLite", code: 1, userInfo: [NSLocalizedDescriptionKey: "Failed to open SQLite database: \(errorMsg)"])
        }
        
        try setupSchema()
    }
    
    deinit {
        if db != nil {
            sqlite3_close(db)
        }
    }
    
    private func execute(_ sql: String) throws {
        var errorMsg: UnsafeMutablePointer<Int8>?
        if sqlite3_exec(db, sql, nil, nil, &errorMsg) != SQLITE_OK {
            let msg = errorMsg.map { String(cString: $0) } ?? "Unknown error"
            sqlite3_free(errorMsg)
            throw NSError(domain: "SQLiteExec", code: 2, userInfo: [NSLocalizedDescriptionKey: "SQL execution error: \(msg)"])
        }
    }
    private func setupSchema() throws {
        // Create base entries table
        try execute("""
        CREATE TABLE IF NOT EXISTS entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,          -- 'kv' or 'note'
            key TEXT UNIQUE,             -- Key for KV pair (must be unique if set), NULL for note
            value TEXT NOT NULL,         -- Value or note content (plain or ciphertext)
            encrypted INTEGER NOT NULL,  -- 1 if encrypted, 0 if public
            created_at INTEGER NOT NULL, -- Unix timestamp
            updated_at INTEGER NOT NULL  -- Unix timestamp
        );
        """)
        
        // Create FTS5 table for public entries only (encrypted = 0)
        try execute("""
        CREATE VIRTUAL TABLE IF NOT EXISTS entries_fts USING fts5(
            key,
            value,
            content='entries',
            content_rowid='id'
        );
        """)
        
        // Create triggers to automatically keep FTS index in sync with public entries
        try execute("""
        CREATE TRIGGER IF NOT EXISTS entries_ai AFTER INSERT ON entries FOR EACH ROW WHEN NEW.encrypted = 0 BEGIN
            INSERT INTO entries_fts(rowid, key, value) VALUES (NEW.id, NEW.key, NEW.value);
        END;
        """)
        
        try execute("""
        CREATE TRIGGER IF NOT EXISTS entries_ad AFTER DELETE ON entries FOR EACH ROW WHEN OLD.encrypted = 0 BEGIN
            DELETE FROM entries_fts WHERE rowid = OLD.id;
        END;
        """)
        
        try execute("""
        CREATE TRIGGER IF NOT EXISTS entries_au AFTER UPDATE ON entries FOR EACH ROW BEGIN
            DELETE FROM entries_fts WHERE rowid = OLD.id;
            INSERT INTO entries_fts(rowid, key, value) SELECT NEW.id, NEW.key, NEW.value WHERE NEW.encrypted = 0;
        END;
        """)
    }
    
    /// Insert or update a Key-Value pair
    public func addOrUpdateKV(key: String, value: String, encrypted: Bool) throws {
        let now = Int64(Date().timeIntervalSince1970)
        let encryptedVal = encrypted ? 1 : 0
        
        let sql = """
        INSERT INTO entries (type, key, value, encrypted, created_at, updated_at)
        VALUES ('kv', ?, ?, ?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET
            value = excluded.value,
            encrypted = excluded.encrypted,
            updated_at = excluded.updated_at;
        """
        
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw getLastError()
        }
        
        defer { sqlite3_finalize(stmt) }
        
        sqlite3_bind_text(stmt, 1, key, -1, SQLITE_TRANSIENT)
        sqlite3_bind_text(stmt, 2, value, -1, SQLITE_TRANSIENT)
        sqlite3_bind_int(stmt, 3, Int32(encryptedVal))
        sqlite3_bind_int64(stmt, 4, now)
        sqlite3_bind_int64(stmt, 5, now)
        
        guard sqlite3_step(stmt) == SQLITE_DONE else {
            throw getLastError()
        }
    }
    
    /// Add a note entry
    public func addNote(content: String, encrypted: Bool) throws {
        let now = Int64(Date().timeIntervalSince1970)
        let encryptedVal = encrypted ? 1 : 0
        
        let sql = """
        INSERT INTO entries (type, key, value, encrypted, created_at, updated_at)
        VALUES ('note', NULL, ?, ?, ?, ?);
        """
        
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw getLastError()
        }
        
        defer { sqlite3_finalize(stmt) }
        
        sqlite3_bind_text(stmt, 1, content, -1, SQLITE_TRANSIENT)
        sqlite3_bind_int(stmt, 2, Int32(encryptedVal))
        sqlite3_bind_int64(stmt, 3, now)
        sqlite3_bind_int64(stmt, 4, now)
        
        guard sqlite3_step(stmt) == SQLITE_DONE else {
            throw getLastError()
        }
    }
    
    /// Retrieve exact entry by key (case-sensitive or exact lookup)
    public func getEntryByKey(_ key: String) throws -> Entry? {
        let sql = "SELECT id, type, key, value, encrypted, created_at, updated_at FROM entries WHERE key = ? LIMIT 1;"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw getLastError()
        }
        defer { sqlite3_finalize(stmt) }
        
        sqlite3_bind_text(stmt, 1, key, -1, SQLITE_TRANSIENT)
        
        if sqlite3_step(stmt) == SQLITE_ROW {
            return entryFromStatement(stmt!)
        }
        return nil
    }
    
    /// Retrieve entry by ID
    public func getEntryByID(_ id: Int64) throws -> Entry? {
        let sql = "SELECT id, type, key, value, encrypted, created_at, updated_at FROM entries WHERE id = ? LIMIT 1;"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw getLastError()
        }
        defer { sqlite3_finalize(stmt) }
        
        sqlite3_bind_int64(stmt, 1, id)
        
        if sqlite3_step(stmt) == SQLITE_ROW {
            return entryFromStatement(stmt!)
        }
        return nil
    }
    
    /// Delete entry by key
    public func deleteEntryByKey(_ key: String) throws -> Bool {
        let sql = "DELETE FROM entries WHERE key = ?;"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw getLastError()
        }
        defer { sqlite3_finalize(stmt) }
        
        sqlite3_bind_text(stmt, 1, key, -1, SQLITE_TRANSIENT)
        
        guard sqlite3_step(stmt) == SQLITE_DONE else {
            throw getLastError()
        }
        
        return sqlite3_changes(db) > 0
    }
    
    /// Delete entry by ID
    public func deleteEntryByID(_ id: Int64) throws -> Bool {
        let sql = "DELETE FROM entries WHERE id = ?;"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw getLastError()
        }
        defer { sqlite3_finalize(stmt) }
        
        sqlite3_bind_int64(stmt, 1, id)
        
        guard sqlite3_step(stmt) == SQLITE_DONE else {
            throw getLastError()
        }
        
        return sqlite3_changes(db) > 0
    }
    
    /// Fetch all entries (used for stats or decrypted in-memory searching)
    public func getAllEntries() throws -> [Entry] {
        let sql = "SELECT id, type, key, value, encrypted, created_at, updated_at FROM entries;"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw getLastError()
        }
        defer { sqlite3_finalize(stmt) }
        
        var results = [Entry]()
        while sqlite3_step(stmt) == SQLITE_ROW {
            results.append(entryFromStatement(stmt!))
        }
        return results
    }
    
    /// List all keys in alphabetical order
    public func listAllKeys() throws -> [String] {
        let sql = "SELECT key FROM entries WHERE key IS NOT NULL ORDER BY key ASC;"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw getLastError()
        }
        defer { sqlite3_finalize(stmt) }
        
        var keys = [String]()
        while sqlite3_step(stmt) == SQLITE_ROW {
            if let keyCStr = sqlite3_column_text(stmt, 0) {
                keys.append(String(cString: keyCStr))
            }
        }
        return keys
    }
    
    /// List recent entries (ordered by updated_at DESC)
    public func getRecentEntries(limit: Int) throws -> [Entry] {
        let sql = "SELECT id, type, key, value, encrypted, created_at, updated_at FROM entries ORDER BY updated_at DESC LIMIT ?;"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw getLastError()
        }
        defer { sqlite3_finalize(stmt) }
        
        sqlite3_bind_int(stmt, 1, Int32(limit))
        
        var results = [Entry]()
        while sqlite3_step(stmt) == SQLITE_ROW {
            results.append(entryFromStatement(stmt!))
        }
        return results
    }
    
    /// Public search using FTS5 (only processes encrypted=0 entries)
    public func publicFTSSearch(_ query: String) throws -> [Entry] {
        // Query must be escaped for FTS5 double quotes to prevent syntax issues
        let escapedQuery = query.replacingOccurrences(of: "\"", with: "\"\"")
        let sql = """
        SELECT e.id, e.type, e.key, e.value, e.encrypted, e.created_at, e.updated_at
        FROM entries e
        JOIN entries_fts f ON e.id = f.rowid
        WHERE entries_fts MATCH ?
        ORDER BY rank;
        """
        
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw getLastError()
        }
        defer { sqlite3_finalize(stmt) }
        
        sqlite3_bind_text(stmt, 1, "\"\(escapedQuery)\"*", -1, SQLITE_TRANSIENT) // Add prefix matching
        
        var results = [Entry]()
        while sqlite3_step(stmt) == SQLITE_ROW {
            results.append(entryFromStatement(stmt!))
        }
        return results
    }
    
    /// Gets database size in bytes
    public func getDatabaseSize() -> Int64 {
        let path = Database.dbFileURL.path
        if let attrs = try? FileManager.default.attributesOfItem(atPath: path),
           let size = attrs[.size] as? Int64 {
            return size
        }
        return 0
    }
    
    // Helpers
    private func getLastError() -> Error {
        let errorMsg = db.map { String(cString: sqlite3_errmsg($0)) } ?? "Unknown error"
        return NSError(domain: "SQLite", code: 3, userInfo: [NSLocalizedDescriptionKey: errorMsg])
    }
    
    private func entryFromStatement(_ stmt: OpaquePointer) -> Entry {
        let id = sqlite3_column_int64(stmt, 0)
        
        let typeCStr = sqlite3_column_text(stmt, 1)
        let type = typeCStr.map { String(cString: $0) } ?? ""
        
        let keyCStr = sqlite3_column_text(stmt, 2)
        let key = keyCStr.map { String(cString: $0) }
        
        let valCStr = sqlite3_column_text(stmt, 3)
        let value = valCStr.map { String(cString: $0) } ?? ""
        
        let encrypted = sqlite3_column_int(stmt, 4) != 0
        let createdAt = sqlite3_column_int64(stmt, 5)
        let updatedAt = sqlite3_column_int64(stmt, 6)
        
        return Entry(id: id, type: type, key: key, value: value, encrypted: encrypted, createdAt: createdAt, updatedAt: updatedAt)
    }
}
