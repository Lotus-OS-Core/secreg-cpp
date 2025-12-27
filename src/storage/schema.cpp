/**
 * @file schema.cpp
 * @brief Database schema implementation for SecReg-Linux
 * @author SecReg Security Team
 * @version 1.0.0
 */

#include "schema.h"
#include "constants.h"
#include "utils.h"
#include <iostream>
#include <sstream>

namespace secreg {

// SchemaManager implementation

SchemaManager::SchemaManager(const std::string& dbPath)
    : dbPath_(dbPath) {}

SchemaManager::~SchemaManager() {
    if (db_) {
        sqlite3_close(db_);
    }
}

void SchemaManager::initialize() {
    int rc = sqlite3_open(dbPath_.c_str(), &db_);
    if (rc != SQLITE_OK) {
        throw StorageException("Failed to open database: " + 
                               std::string(sqlite3_errmsg(db_)),
                               ErrorCode::StorageDatabaseError);
    }
    
    // Enable WAL mode for better concurrency
    executeSql("PRAGMA journal_mode=WAL");
    executeSql("PRAGMA synchronous=NORMAL");
    executeSql("PRAGMA cache_size=-64000"); // 64MB cache
    executeSql("PRAGMA foreign_keys=ON");
    
    if (!tableExists("metadata")) {
        createTables();
    } else {
        uint32_t currentVersion = getVersion();
        if (currentVersion < DbConstants::SCHEMA_VERSION) {
            migrate(currentVersion);
        }
    }
}

uint32_t SchemaManager::getVersion() const {
    sqlite3_stmt* stmt;
    std::string sql = "SELECT value FROM metadata WHERE key = 'schema_version'";
    
    int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        return 0;
    }
    
    uint32_t version = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        version = static_cast<uint32_t>(sqlite3_column_int(stmt, 0));
    }
    
    sqlite3_finalize(stmt);
    return version;
}

bool SchemaManager::migrate(uint32_t targetVersion) {
    // Future migrations would go here
    return true;
}

void SchemaManager::createTables() {
    createEntriesTable();
    createAuditTable();
    createAclTable();
    createMetadataTable();
    createIndexes();
    
    // Set schema version
    executeSql("INSERT INTO metadata (key, value) VALUES ('schema_version', '" + 
               std::to_string(DbConstants::SCHEMA_VERSION) + "')");
    executeSql("INSERT INTO metadata (key, value) VALUES ('created_at', '" + 
               std::to_string(getCurrentTimestampSeconds()) + "')");
}

void SchemaManager::createEntriesTable() {
    std::string sql = R"(
        CREATE TABLE IF NOT EXISTS entries (
            key TEXT PRIMARY KEY,
            value BLOB NOT NULL,
            type TEXT NOT NULL DEFAULT 'string',
            created_at INTEGER NOT NULL,
            modified_at INTEGER NOT NULL,
            created_by TEXT NOT NULL,
            modified_by TEXT NOT NULL,
            version INTEGER NOT NULL DEFAULT 1,
            is_encrypted INTEGER NOT NULL DEFAULT 0,
            metadata TEXT
        ) WITHOUT ROWID
    )";
    executeSql(sql);
}

void SchemaManager::createAuditTable() {
    std::string sql = R"(
        CREATE TABLE IF NOT EXISTS audit (
            id TEXT PRIMARY KEY,
            timestamp INTEGER NOT NULL,
            actor_user_id INTEGER NOT NULL,
            actor_user_name TEXT NOT NULL,
            actor_group_id INTEGER NOT NULL,
            actor_process_id INTEGER NOT NULL,
            actor_session_id INTEGER NOT NULL,
            actor_tty TEXT,
            actor_remote_address TEXT,
            actor_auth_method TEXT NOT NULL,
            actor_mfa_used INTEGER NOT NULL DEFAULT 0,
            action TEXT NOT NULL,
            target_key TEXT NOT NULL,
            success INTEGER NOT NULL,
            error_message TEXT,
            source_socket_path TEXT,
            source_network_address TEXT,
            source_client_version TEXT,
            request_hash TEXT,
            previous_value_hash TEXT,
            new_value_hash TEXT,
            chain_hash TEXT NOT NULL
        )
    )";
    executeSql(sql);
    
    // Create index for efficient querying
    executeSql("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit(timestamp DESC)");
    executeSql("CREATE INDEX IF NOT EXISTS idx_audit_user ON audit(actor_user_name)");
    executeSql("CREATE INDEX IF NOT EXISTS idx_audit_key ON audit(target_key)");
}

void SchemaManager::createAclTable() {
    std::string sql = R"(
        CREATE TABLE IF NOT EXISTS acl (
            key TEXT PRIMARY KEY,
            owner TEXT NOT NULL DEFAULT 'root',
            owner_group TEXT NOT NULL DEFAULT 'wheel',
            permissions TEXT NOT NULL,
            inheritance TEXT
        ) WITHOUT ROWID
    )";
    executeSql(sql);
}

void SchemaManager::createMetadataTable() {
    std::string sql = R"(
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        ) WITHOUT ROWID
    )";
    executeSql(sql);
}

void SchemaManager::createIndexes() {
    executeSql("CREATE INDEX IF NOT EXISTS idx_entries_key ON entries(key)");
    executeSql("CREATE INDEX IF NOT EXISTS idx_entries_modified ON entries(modified_at DESC)");
}

bool SchemaManager::tableExists(const std::string& tableName) {
    std::string sql = "SELECT name FROM sqlite_master WHERE type='table' AND name=?";
    sqlite3_stmt* stmt;
    
    int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, tableName.c_str(), -1, SQLITE_TRANSIENT);
    
    bool exists = (sqlite3_step(stmt) == SQLITE_ROW);
    
    sqlite3_finalize(stmt);
    return exists;
}

void SchemaManager::executeSql(const std::string& sql) {
    char* errMsg = nullptr;
    
    int rc = sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        std::string error = errMsg;
        sqlite3_free(errMsg);
        throw StorageException("SQL error: " + error,
                               ErrorCode::StorageDatabaseError);
    }
}

// EntryMapper implementation

EntryMapper::EntryMapper(sqlite3* db) : db_(db) {}

void EntryMapper::insert(const RegistryEntry& entry) {
    std::string sql = R"(
        INSERT OR REPLACE INTO entries 
        (key, value, type, created_at, modified_at, created_by, modified_by, 
         version, is_encrypted, metadata)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";
    
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        throw StorageException("Failed to prepare statement",
                               ErrorCode::StorageDatabaseError);
    }
    
    bindEntry(stmt, entry);
    
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw StorageException("Failed to insert entry",
                               ErrorCode::StorageDatabaseError);
    }
    
    sqlite3_finalize(stmt);
}

void EntryMapper::update(const RegistryEntry& entry) {
    std::string sql = R"(
        UPDATE entries SET
            value = ?,
            type = ?,
            modified_at = ?,
            modified_by = ?,
            version = ?,
            is_encrypted = ?,
            metadata = ?
        WHERE key = ?
    )";
    
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        throw StorageException("Failed to prepare statement",
                               ErrorCode::StorageDatabaseError);
    }
    
    sqlite3_bind_blob(stmt, 1, entry.value.asBinary().data(), 
                      entry.value.asBinary().size(), SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, valueTypeToString(entry.value_type).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, entry.modified_at);
    sqlite3_bind_text(stmt, 4, entry.modified_by.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 5, entry.version);
    sqlite3_bind_int(stmt, 6, entry.is_encrypted ? 1 : 0);
    
    // Serialize metadata
    std::string metadataJson = serializeMetadata(entry.metadata);
    sqlite3_bind_text(stmt, 7, metadataJson.c_str(), -1, SQLITE_TRANSIENT);
    
    sqlite3_bind_text(stmt, 8, entry.key.c_str(), -1, SQLITE_TRANSIENT);
    
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw StorageException("Failed to update entry",
                               ErrorCode::StorageDatabaseError);
    }
    
    sqlite3_finalize(stmt);
}

void EntryMapper::remove(const std::string& key) {
    std::string sql = "DELETE FROM entries WHERE key = ?";
    
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        throw StorageException("Failed to prepare statement",
                               ErrorCode::StorageDatabaseError);
    }
    
    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);
    
    rc = sqlite3_step(stmt);
    
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        throw StorageException("Failed to delete entry",
                               ErrorCode::StorageDatabaseError);
    }
}

std::optional<RegistryEntry> EntryMapper::findByKey(const std::string& key) {
    std::string sql = "SELECT * FROM entries WHERE key = ?";
    
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        return std::nullopt;
    }
    
    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);
    
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        RegistryEntry entry = extractEntry(stmt);
        sqlite3_finalize(stmt);
        return entry;
    }
    
    sqlite3_finalize(stmt);
    return std::nullopt;
}

std::vector<RegistryEntry> EntryMapper::findByPrefix(const std::string& prefix,
                                                      bool recursive) {
    std::vector<RegistryEntry> results;
    
    std::string sql;
    if (recursive) {
        sql = "SELECT * FROM entries WHERE key LIKE ? || '%' OR key = ?";
    } else {
        sql = "SELECT * FROM entries WHERE key = ? OR key LIKE ? || '/%'";
    }
    
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        return results;
    }
    
    sqlite3_bind_text(stmt, 1, prefix.c_str(), -1, SQLITE_TRANSIENT);
    if (recursive) {
        sqlite3_bind_text(stmt, 2, prefix.c_str(), -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_text(stmt, 2, prefix.c_str(), -1, SQLITE_TRANSIENT);
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        results.push_back(extractEntry(stmt));
    }
    
    sqlite3_finalize(stmt);
    return results;
}

void EntryMapper::bindEntry(sqlite3_stmt* stmt, const RegistryEntry& entry) {
    sqlite3_bind_text(stmt, 1, entry.key.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 2, entry.value.asBinary().data(),
                      entry.value.asBinary().size(), SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, valueTypeToString(entry.value_type).c_str(), 
                      -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 4, entry.created_at);
    sqlite3_bind_int64(stmt, 5, entry.modified_at);
    sqlite3_bind_text(stmt, 6, entry.created_by.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, entry.modified_by.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 8, entry.version);
    sqlite3_bind_int(stmt, 9, entry.is_encrypted ? 1 : 0);
    
    std::string metadataJson = serializeMetadata(entry.metadata);
    sqlite3_bind_text(stmt, 10, metadataJson.c_str(), -1, SQLITE_TRANSIENT);
}

RegistryEntry EntryMapper::extractEntry(sqlite3_stmt* stmt) {
    RegistryEntry entry;
    
    entry.key = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
    
    int blobSize = sqlite3_column_bytes(stmt, 1);
    const void* blobData = sqlite3_column_blob(stmt, 1);
    entry.value = RegistryValue::deserialize(
        std::vector<uint8_t>(static_cast<const uint8_t*>(blobData), 
                             static_cast<const uint8_t*>(blobData) + blobSize)
    );
    
    entry.value_type = stringToValueType(
        reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2)));
    
    entry.created_at = sqlite3_column_int64(stmt, 3);
    entry.modified_at = sqlite3_column_int64(stmt, 4);
    entry.created_by = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
    entry.modified_by = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
    entry.version = sqlite3_column_int64(stmt, 7);
    entry.is_encrypted = sqlite3_column_int(stmt, 8) != 0;
    
    return entry;
}

// Transaction implementation

Transaction::Transaction(sqlite3* db) : db_(db) {
    executeSql("BEGIN TRANSACTION");
}

Transaction::~Transaction() {
    if (active_ && !committed_) {
        rollback();
    }
}

void Transaction::commit() {
    executeSql("COMMIT");
    active_ = false;
    committed_ = true;
}

void Transaction::rollback() {
    executeSql("ROLLBACK");
    active_ = false;
}

} // namespace secreg
