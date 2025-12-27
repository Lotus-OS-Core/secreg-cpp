/**
 * @file engine.h
 * @brief Storage engine for SecReg-Linux
 * @author SecReg Security Team
 * @version 1.0.0
 */

#ifndef SECREG_ENGINE_H
#define SECREG_ENGINE_H

#include "types.h"
#include "errors.h"
#include "crypto_manager.h"
#include <string>
#include <memory>
#include <shared_mutex>
#include <thread>
#include <atomic>
#include <functional>

namespace secreg {

/**
 * @brief Storage engine configuration
 */
struct StorageConfig {
    std::string dbPath = PathConstants::DEFAULT_DB_PATH;
    std::string logPath = PathConstants::DEFAULT_LOG_PATH;
    bool enableEncryption = true;
    bool enableWalMode = true;
    size_t cacheSize = 64 * 1024 * 1024; // 64MB
    uint32_t maxConnections = 10;
};

/**
 * @brief Main storage engine
 */
class StorageEngine {
public:
    explicit StorageEngine(const StorageConfig& config, 
                          std::shared_ptr<CryptoManager> cryptoManager);
    ~StorageEngine();
    
    // CRUD operations
    void set(const RegistryEntry& entry, bool encrypt = false);
    std::optional<RegistryEntry> get(const std::string& key, bool decrypt = false);
    bool remove(const std::string& key);
    
    // Batch operations
    void setBatch(const std::vector<RegistryEntry>& entries, bool encrypt = false);
    std::vector<std::optional<RegistryEntry>> getBatch(
        const std::vector<std::string>& keys, bool decrypt = false);
    bool removeBatch(const std::vector<std::string>& keys);
    
    // Query operations
    std::vector<std::string> listKeys(const std::string& prefix, bool recursive = false);
    std::vector<RegistryEntry> listEntries(const std::string& prefix, bool recursive = false);
    
    // Search operations
    std::vector<RegistryEntry> search(const std::string& pattern);
    std::vector<RegistryEntry> searchByTag(const std::string& tag);
    
    // Transaction support
    class Transaction {
    public:
        explicit Transaction(StorageEngine& engine);
        ~Transaction();
        
        void commit();
        void rollback();
        
        void set(const RegistryEntry& entry, bool encrypt = false);
        bool remove(const std::string& key);
        
    private:
        StorageEngine& engine_;
        bool active_ = true;
        bool committed_ = false;
        std::vector<RegistryEntry> pendingEntries_;
        std::vector<std::string> pendingDeletes_;
    };
    
    Transaction beginTransaction();
    
    // Backup and restore
    void backup(const std::string& outputPath, bool encrypted = true);
    void restore(const std::string& inputPath, bool encrypted = true);
    
    // Status and maintenance
    bool healthCheck();
    void vacuum();
    void compact();
    size_t getSize() const;
    uint32_t getKeyCount() const;
    
    // Event callbacks
    void setOnChangeCallback(std::function<void(const std::string&, const RegistryEntry&)> callback);
    void setOnDeleteCallback(std::function<void(const std::string&)> callback);
    
private:
    StorageConfig config_;
    std::shared_ptr<CryptoManager> cryptoManager_;
    sqlite3* db_ = nullptr;
    std::unique_ptr<SchemaManager> schemaManager_;
    std::unique_ptr<EntryMapper> entryMapper_;
    
    mutable std::shared_mutex mutex_;
    std::atomic<bool> initialized_{false};
    
    std::function<void(const std::string&, const RegistryEntry&)> onChangeCallback_;
    std::function<void(const std::string&)> onDeleteCallback_;
    
    void initialize();
    void openDatabase();
    void closeDatabase();
    
    std::vector<uint8_t> serializeEntry(const RegistryEntry& entry);
    RegistryEntry deserializeEntry(const std::vector<uint8_t>& data);
    
    std::vector<uint8_t> encryptEntry(const RegistryEntry& entry);
    RegistryEntry decryptEntry(const std::vector<uint8_t>& encrypted);
    
    void notifyChange(const std::string& key, const RegistryEntry& entry);
    void notifyDelete(const std::string& key);
};

/**
 * @brief Connection pool for storage engine
 */
class StorageConnectionPool {
public:
    explicit StorageConnectionPool(const StorageConfig& config,
                                   std::shared_ptr<CryptoManager> cryptoManager,
                                   size_t poolSize);
    ~StorageConnectionPool();
    
    std::unique_ptr<StorageEngine> acquire();
    void release(std::unique_ptr<StorageEngine> engine);
    
    size_t getActiveCount() const;
    size_t getAvailableCount() const;

private:
    StorageConfig config_;
    std::shared_ptr<CryptoManager> cryptoManager_;
    size_t poolSize_;
    mutable std::mutex mutex_;
    std::vector<std::unique_ptr<StorageEngine>> pool_;
    std::atomic<size_t> activeCount_{0};
};

} // namespace secreg

#endif // SECREG_ENGINE_H
