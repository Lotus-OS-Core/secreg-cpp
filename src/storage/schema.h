/**
 * @file schema.h
 * @brief Database schema for SecReg-Linux
 * @author SecReg Security Team
 * @version 1.0.0
 */

#ifndef SECREG_SCHEMA_H
#define SECREG_SCHEMA_H

#include "types.h"
#include "errors.h"
#include <string>
#include <vector>
#include <optional>
#include <sqlite3.h>

namespace secreg {

/**
 * @brief Database schema manager
 */
class SchemaManager {
public:
    explicit SchemaManager(const std::string& dbPath);
    ~SchemaManager();
    
    void initialize();
    uint32_t getVersion() const;
    bool migrate(uint32_t targetVersion);
    
private:
    std::string dbPath_;
    sqlite3* db_ = nullptr;
    
    void createTables();
    void createEntriesTable();
    void createAuditTable();
    void createAclTable();
    void createMetadataTable();
    void createIndexes();
    
    bool tableExists(const std::string& tableName);
    void executeSql(const std::string& sql);
};

/**
 * @brief Entry mapper for database operations
 */
class EntryMapper {
public:
    explicit EntryMapper(sqlite3* db);
    
    void insert(const RegistryEntry& entry);
    void update(const RegistryEntry& entry);
    void remove(const std::string& key);
    std::optional<RegistryEntry> findByKey(const std::string& key);
    std::vector<RegistryEntry> findByPrefix(const std::string& prefix, 
                                             bool recursive);
    
private:
    sqlite3* db_;
    
    void bindEntry(sqlite3_stmt* stmt, const RegistryEntry& entry);
    RegistryEntry extractEntry(sqlite3_stmt* stmt);
};

/**
 * @brief Audit mapper for database operations
 */
class AuditMapper {
public:
    explicit AuditMapper(sqlite3* db);
    
    void insert(const AuditRecord& record);
    std::vector<AuditRecord> query(const std::string& conditions,
                                     const std::string& orderBy,
                                     size_t limit,
                                     size_t offset);
    size_t count(const std::string& conditions);
    bool verifyChain();
    
private:
    sqlite3* db_;
    
    void bindRecord(sqlite3_stmt* stmt, const AuditRecord& record);
    AuditRecord extractRecord(sqlite3_stmt* stmt);
};

/**
 * @brief ACL mapper for database operations
 */
class AclMapper {
public:
    explicit AclMapper(sqlite3* db);
    
    void insert(const std::string& key, const AccessControlEntry& acl);
    void update(const std::string& key, const AccessControlEntry& acl);
    void remove(const std::string& key);
    std::optional<AccessControlEntry> findByKey(const std::string& key);
    std::vector<std::pair<std::string, AccessControlEntry>> findByUser(
        const std::string& userName);
    
private:
    sqlite3* db_;
};

/**
 * @brief Transaction support
 */
class Transaction {
public:
    explicit Transaction(sqlite3* db);
    ~Transaction();
    
    void commit();
    void rollback();
    
    Transaction(const Transaction&) = delete;
    Transaction& operator=(const Transaction&) = delete;
    Transaction(Transaction&&) = delete;
    Transaction& operator=(Transaction&&) = delete;

private:
    sqlite3* db_;
    bool active_ = true;
    bool committed_ = false;
};

} // namespace secreg

#endif // SECREG_SCHEMA_H
