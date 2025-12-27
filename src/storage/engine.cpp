/**
 * @file engine.cpp
 * @brief Storage engine implementation for SecReg-Linux
 * @author SecReg Security Team
 * @version 1.0.0
 */

#include "engine.h"
#include "schema.h"
#include "constants.h"
#include "utils.h"
#include <iostream>
#include <fstream>
#include <filesystem>

namespace secreg {

// StorageEngine implementation

StorageEngine::StorageEngine(const StorageConfig& config,
                             std::shared_ptr<CryptoManager> cryptoManager)
    : config_(config), cryptoManager_(cryptoManager) {
    initialize();
}

StorageEngine::~StorageEngine() {
    closeDatabase();
}

void StorageEngine::initialize() {
    std::unique_lock lock(mutex_);
    
    // Ensure directories exist
    ensureDirectory(config_.dbPath);
    
    // Open database
    openDatabase();
    
    // Initialize schema
    schemaManager_ = std::make_unique<SchemaManager>(
        config_.dbPath + "/" + DbConstants::DB_FILENAME);
    schemaManager_->initialize();
    
    // Create mappers
    entryMapper_ = std::make_unique<EntryMapper>(db_);
    
    initialized_ = true;
}

void StorageEngine::openDatabase() {
    std::string dbPath = config_.dbPath + "/" + DbConstants::DB_FILENAME;
    
    int rc = sqlite3_open(dbPath.c_str(), &db_);
    if (rc != SQLITE_OK) {
        throw StorageException("Failed to open database: " +
                               std::string(sqlite3_errmsg(db_)),
                               ErrorCode::StorageDatabaseError);
    }
    
    // Configure connection
    sqlite3_busy_timeout(db_, 5000); // 5 second timeout
    sqlite3_exec(db_, "PRAGMA journal_mode=WAL", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA synchronous=NORMAL", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, ("PRAGMA cache_size=-" + std::to_string(config_.cacheSize / 1024)).c_str(),
                 nullptr, nullptr, nullptr);
}

void StorageEngine::closeDatabase() {
    std::unique_lock lock(mutex_);
    
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
    
    initialized_ = false;
}

void StorageEngine::set(const RegistryEntry& entry, bool encrypt) {
    std::unique_lock lock(mutex_);
    
    RegistryEntry finalEntry = entry;
    finalEntry.modified_at = getCurrentTimestampSeconds();
    
    if (encrypt && config_.enableEncryption) {
        auto encrypted = encryptEntry(finalEntry);
        finalEntry.value = RegistryValue(encrypted);
        finalEntry.is_encrypted = true;
    }
    
    entryMapper_->insert(finalEntry);
    
    lock.unlock();
    notifyChange(entry.key, finalEntry);
}

std::optional<RegistryEntry> StorageEngine::get(const std::string& key, bool decrypt) {
    std::shared_lock lock(mutex_);
    
    auto entryOpt = entryMapper_->findByKey(key);
    if (!entryOpt.has_value()) {
        return std::nullopt;
    }
    
    RegistryEntry entry = entryOpt.value();
    
    if (decrypt && entry.is_encrypted) {
        entry = decryptEntry(entry.value.asBinary());
    }
    
    return entry;
}

bool StorageEngine::remove(const std::string& key) {
    std::unique_lock lock(mutex_);
    
    auto entryOpt = entryMapper_->findByKey(key);
    if (!entryOpt.has_value()) {
        return false;
    }
    
    entryMapper_->remove(key);
    
    lock.unlock();
    notifyDelete(key);
    
    return true;
}

void StorageEngine::setBatch(const std::vector<RegistryEntry>& entries, bool encrypt) {
    std::unique_lock lock(mutex_);
    
    for (const auto& entry : entries) {
        RegistryEntry finalEntry = entry;
        finalEntry.modified_at = getCurrentTimestampSeconds();
        
        if (encrypt && config_.enableEncryption) {
            auto encrypted = encryptEntry(finalEntry);
            finalEntry.value = RegistryValue(encrypted);
            finalEntry.is_encrypted = true;
        }
        
        entryMapper_->insert(finalEntry);
    }
}

std::vector<std::optional<RegistryEntry>> StorageEngine::getBatch(
    const std::vector<std::string>& keys, bool decrypt) {
    std::shared_lock lock(mutex_);
    
    std::vector<std::optional<RegistryEntry>> results;
    results.reserve(keys.size());
    
    for (const auto& key : keys) {
        auto entryOpt = entryMapper_->findByKey(key);
        
        if (entryOpt.has_value() && decrypt && entryOpt.value().is_encrypted) {
            results.push_back(decryptEntry(entryOpt.value().value.asBinary()));
        } else {
            results.push_back(entryOpt);
        }
    }
    
    return results;
}

bool StorageEngine::removeBatch(const std::vector<std::string>& keys) {
    std::unique_lock lock(mutex_);
    
    for (const auto& key : keys) {
        entryMapper_->remove(key);
    }
    
    lock.unlock();
    
    for (const auto& key : keys) {
        notifyDelete(key);
    }
    
    return true;
}

std::vector<std::string> StorageEngine::listKeys(const std::string& prefix, 
                                                   bool recursive) {
    std::shared_lock lock(mutex_);
    return entryMapper_->findByPrefix(prefix, recursive)
        .transform([](const RegistryEntry& e) { return e.key; });
}

std::vector<RegistryEntry> StorageEngine::listEntries(const std::string& prefix,
                                                        bool recursive) {
    std::shared_lock lock(mutex_);
    return entryMapper_->findByPrefix(prefix, recursive);
}

std::vector<RegistryEntry> StorageEngine::search(const std::string& pattern) {
    std::shared_lock lock(mutex_);
    
    std::vector<RegistryEntry> results;
    auto allEntries = entryMapper_->findByPrefix("/", true);
    
    for (const auto& entry : allEntries) {
        if (entry.key.find(pattern) != std::string::npos) {
            results.push_back(entry);
        }
    }
    
    return results;
}

std::vector<RegistryEntry> StorageEngine::searchByTag(const std::string& tag) {
    std::shared_lock lock(mutex_);
    
    std::vector<RegistryEntry> results;
    auto allEntries = entryMapper_->findByPrefix("/", true);
    
    for (const auto& entry : allEntries) {
        for (const auto& entryTag : entry.metadata.tags) {
            if (entryTag == tag) {
                results.push_back(entry);
                break;
            }
        }
    }
    
    return results;
}

StorageEngine::Transaction StorageEngine::beginTransaction() {
    return Transaction(*this);
}

void StorageEngine::backup(const std::string& outputPath, bool encrypted) {
    std::shared_lock lock(mutex_);
    
    // Use SQLite backup API
    sqlite3* backupDb;
    int rc = sqlite3_open(outputPath.c_str(), &backupDb);
    if (rc != SQLITE_OK) {
        throw StorageException("Failed to create backup",
                               ErrorCode::StorageDatabaseError);
    }
    
    sqlite3_backup* backup = sqlite3_backup_init(backupDb, "main", db_, "main");
    if (backup) {
        sqlite3_backup_step(backup, -1);
        sqlite3_backup_finish(backup);
    }
    
    if (sqlite3_errcode(backupDb) != SQLITE_OK) {
        sqlite3_close(backupDb);
        throw StorageException("Backup failed",
                               ErrorCode::StorageDatabaseError);
    }
    
    sqlite3_close(backupDb);
    
    // Encrypt backup if requested
    if (encrypted) {
        std::vector<uint8_t> backupData = hexDecode(readFile(outputPath));
        std::vector<uint8_t> encryptedData = cryptoManager_->encrypt(backupData);
        writeFile(outputPath, hexEncode(encryptedData));
    }
}

void StorageEngine::restore(const std::string& inputPath, bool encrypted) {
    std::unique_lock lock(mutex_);
    
    // Decrypt if encrypted
    if (encrypted) {
        std::vector<uint8_t> encryptedData = hexDecode(readFile(inputPath));
        std::vector<uint8_t> backupData = cryptoManager_->decrypt(encryptedData);
        
        // Write decrypted data to temp file
        std::string tempPath = config_.dbPath + "/temp_backup.db";
        writeFile(tempPath, std::string(backupData.begin(), backupData.end()));
        
        // Restore from temp file
        sqlite3* restoreDb;
        int rc = sqlite3_open(tempPath.c_str(), &restoreDb);
        if (rc != SQLITE_OK) {
            std::filesystem::remove(tempPath);
            throw StorageException("Failed to open backup for restore",
                                   ErrorCode::StorageDatabaseError);
        }
        
        sqlite3_backup* backup = sqlite3_backup_init(db_, "main", restoreDb, "main");
        if (backup) {
            sqlite3_backup_step(backup, -1);
            sqlite3_backup_finish(backup);
        }
        
        sqlite3_close(restoreDb);
        std::filesystem::remove(tempPath);
    } else {
        // Direct restore
        sqlite3* restoreDb;
        int rc = sqlite3_open(inputPath.c_str(), &restoreDb);
        if (rc != SQLITE_OK) {
            throw StorageException("Failed to open backup for restore",
                                   ErrorCode::StorageDatabaseError);
        }
        
        sqlite3_backup* backup = sqlite3_backup_init(db_, "main", restoreDb, "main");
        if (backup) {
            sqlite3_backup_step(backup, -1);
            sqlite3_backup_finish(backup);
        }
        
        sqlite3_close(restoreDb);
    }
}

bool StorageEngine::healthCheck() {
    std::shared_lock lock(mutex_);
    
    if (!db_ || !initialized_) {
        return false;
    }
    
    int rc = sqlite3_exec(db_, "PRAGMA integrity_check", nullptr, nullptr, nullptr);
    return rc == SQLITE_OK;
}

void StorageEngine::vacuum() {
    std::unique_lock lock(mutex_);
    sqlite3_exec(db_, "VACUUM", nullptr, nullptr, nullptr);
}

void StorageEngine::compact() {
    vacuum();
}

size_t StorageEngine::getSize() const {
    std::shared_lock lock(mutex_);
    
    size_t totalSize = 0;
    for (const auto& entry : std::filesystem::directory_iterator(config_.dbPath)) {
        totalSize += entry.file_size();
    }
    
    return totalSize;
}

uint32_t StorageEngine::getKeyCount() const {
    std::shared_lock lock(mutex_);
    
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db_, "SELECT COUNT(*) FROM entries", -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        return 0;
    }
    
    uint32_t count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }
    
    sqlite3_finalize(stmt);
    return count;
}

void StorageEngine::setOnChangeCallback(
    std::function<void(const std::string&, const RegistryEntry&)> callback) {
    std::unique_lock lock(mutex_);
    onChangeCallback_ = callback;
}

void StorageEngine::setOnDeleteCallback(
    std::function<void(const std::string&)> callback) {
    std::unique_lock lock(mutex_);
    onDeleteCallback_ = callback;
}

std::vector<uint8_t> StorageEngine::encryptEntry(const RegistryEntry& entry) {
    std::string json = serializeEntry(entry);
    return cryptoManager_->encryptField(json, entry.key);
}

RegistryEntry StorageEngine::decryptEntry(const std::vector<uint8_t>& encrypted) {
    std::string json = cryptoManager_->decryptField(encrypted, "");
    return deserializeEntry(std::vector<uint8_t>(json.begin(), json.end()));
}

void StorageEngine::notifyChange(const std::string& key, const RegistryEntry& entry) {
    if (onChangeCallback_) {
        onChangeCallback_(key, entry);
    }
}

void StorageEngine::notifyDelete(const std::string& key) {
    if (onDeleteCallback_) {
        onDeleteCallback_(key);
    }
}

// StorageEngine::Transaction implementation

StorageEngine::Transaction::Transaction(StorageEngine& engine) 
    : engine_(engine) {
    engine.mutex_.lock();
}

StorageEngine::Transaction::~Transaction() {
    if (active_ && !committed_) {
        rollback();
    }
    engine_.mutex_.unlock();
}

void StorageEngine::Transaction::commit() {
    if (!active_) {
        throw StorageException("Transaction not active",
                               ErrorCode::InvalidState);
    }
    
    for (const auto& entry : pendingEntries_) {
        engine_.entryMapper_->insert(entry);
    }
    
    for (const auto& key : pendingDeletes_) {
        engine_.entryMapper_->remove(key);
    }
    
    committed_ = true;
    active_ = false;
}

void StorageEngine::Transaction::rollback() {
    active_ = false;
    pendingEntries_.clear();
    pendingDeletes_.clear();
}

void StorageEngine::Transaction::set(const RegistryEntry& entry, bool encrypt) {
    if (!active_) {
        throw StorageException("Transaction not active",
                               ErrorCode::InvalidState);
    }
    
    RegistryEntry finalEntry = entry;
    finalEntry.modified_at = getCurrentTimestampSeconds();
    
    if (encrypt && engine_.config_.enableEncryption) {
        auto encrypted = engine_.encryptEntry(finalEntry);
        finalEntry.value = RegistryValue(encrypted);
        finalEntry.is_encrypted = true;
    }
    
    pendingEntries_.push_back(finalEntry);
}

bool StorageEngine::Transaction::remove(const std::string& key) {
    if (!active_) {
        throw StorageException("Transaction not active",
                               ErrorCode::InvalidState);
    }
    
    pendingDeletes_.push_back(key);
    return true;
}

// StorageConnectionPool implementation

StorageConnectionPool::StorageConnectionPool(
    const StorageConfig& config,
    std::shared_ptr<CryptoManager> cryptoManager,
    size_t poolSize)
    : config_(config), cryptoManager_(cryptoManager), poolSize_(poolSize) {}

StorageConnectionPool::~StorageConnectionPool() {
    std::unique_lock lock(mutex_);
    pool_.clear();
}

std::unique_ptr<StorageEngine> StorageConnectionPool::acquire() {
    std::unique_lock lock(mutex_);
    
    if (!pool_.empty()) {
        auto engine = std::move(pool_.back());
        pool_.pop_back();
        activeCount_++;
        return engine;
    }
    
    if (activeCount_ >= poolSize_) {
        throw StorageException("Connection pool exhausted",
                               ErrorCode::StorageDatabaseError);
    }
    
    activeCount_++;
    return std::make_unique<StorageEngine>(config_, cryptoManager_);
}

void StorageConnectionPool::release(std::unique_ptr<StorageEngine> engine) {
    std::unique_lock lock(mutex_);
    pool_.push_back(std::move(engine));
    activeCount_--;
}

size_t StorageConnectionPool::getActiveCount() const {
    return activeCount_.load();
}

size_t StorageConnectionPool::getAvailableCount() const {
    std::shared_lock lock(mutex_);
    return pool_.size();
}

} // namespace secreg
