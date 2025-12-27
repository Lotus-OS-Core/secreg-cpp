/**
 * @file audit.h
 * @brief Audit logging for SecReg-Linux
 * @author SecReg Security Team
 * @version 1.0.0
 */

#ifndef SECREG_AUDIT_H
#define SECREG_AUDIT_H

#include "types.h"
#include "errors.h"
#include <string>
#include <memory>
#include <vector>
#include <functional>
#include <queue>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>

namespace secreg {

/**
 * @brief Audit log configuration
 */
struct AuditConfig {
    std::string logPath = PathConstants::DEFAULT_LOG_PATH;
    uint64_t retentionDays = AuditConstants::DEFAULT_RETENTION_DAYS;
    size_t maxLogSize = AuditConstants::MAX_AUDIT_LOG_SIZE;
    bool enableChainVerification = true;
    bool asyncWrite = true;
    uint32_t batchSize = 100;
    uint64_t flushInterval = 1000; // milliseconds
};

/**
 * @brief Audit chain entry
 */
struct AuditChainEntry {
    uint64_t index;
    AuditRecord record;
    std::string previousHash;
    std::string currentHash;
    uint64_t timestamp;
};

/**
 * @brief Audit logger
 */
class AuditLogger {
public:
    explicit AuditLogger(const AuditConfig& config);
    ~AuditLogger();
    
    // Logging
    void log(const AuditRecord& record);
    void logAuthSuccess(const ActorInfo& actor, const std::string& target);
    void logAuthFailure(const ActorInfo& actor, const std::string& target,
                        const std::string& reason);
    void logAccess(const ActorInfo& actor, const std::string& target,
                   Action action, bool success, const std::string& reason);
    void logChange(const ActorInfo& actor, const std::string& target,
                   const std::string& oldValue, const std::string& newValue);
    void logError(const std::string& category, int code, 
                  const std::string& message);
    
    // Querying
    std::vector<AuditRecord> query(const std::string& conditions,
                                    size_t limit = 100,
                                    size_t offset = 0);
    std::vector<AuditRecord> queryByUser(const std::string& userName,
                                          uint64_t startTime,
                                          uint64_t endTime,
                                          size_t limit = 100);
    std::vector<AuditRecord> queryByKey(const std::string& keyPath,
                                         uint64_t startTime,
                                         uint64_t endTime,
                                         size_t limit = 100);
    std::vector<AuditRecord> queryByAction(Action action,
                                            uint64_t startTime,
                                            uint64_t endTime,
                                            size_t limit = 100);
    
    // Verification
    bool verifyChain();
    bool verifyEntry(uint64_t index);
    std::vector<uint64_t> findTamperedEntries();
    
    // Export
    std::vector<uint8_t> exportChain();
    std::vector<uint8_t> exportToJson();
    
    // Maintenance
    void truncate(uint64_t beforeTimestamp);
    void compact();
    void flush();
    
    // Statistics
    size_t getEntryCount() const;
    size_t getLogSize() const;
    uint64_t getFirstTimestamp() const;
    uint64_t getLastTimestamp() const;

private:
    AuditConfig config_;
    std::string chainHash_;
    uint64_t entryCounter_ = 0;
    
    std::deque<AuditChainEntry> entries_;
    std::deque<AuditRecord> pendingWrites_;
    
    std::thread writerThread_;
    std::atomic<bool> running_{false};
    std::atomic<bool> dirty_{false};
    
    mutable std::mutex mutex_;
    mutable std::shared_mutex chainMutex_;
    
    std::function<void(const std::string&)> syslogCallback_;
    
    void writerLoop();
    void writeEntry(const AuditChainEntry& entry);
    void computeChainHash(const AuditRecord& record, std::string& hash);
    void writeToSyslog(const AuditRecord& record);
    
    std::string computeHash(const std::string& data);
    std::string computeHash(const std::vector<uint8_t>& data);
};

/**
 * @brief Audit query builder
 */
class AuditQuery {
public:
    AuditQuery();
    
    AuditQuery& forUser(const std::string& userName);
    AuditQuery& forKey(const std::string& keyPath);
    AuditQuery& forAction(Action action);
    AuditQuery& forTimeRange(uint64_t start, uint64_t end);
    AuditQuery& forSuccess(bool success);
    AuditQuery& limit(size_t limit);
    AuditQuery& offset(size_t offset);
    AuditQuery& orderBy(const std::string& field, bool ascending = false);
    
    std::vector<AuditRecord> execute(AuditLogger& logger);
    size_t count(AuditLogger& logger);

private:
    std::string userName_;
    std::string keyPath_;
    Action action_ = Action::Read;
    bool hasAction_ = false;
    uint64_t startTime_ = 0;
    uint64_t endTime_ = UINT64_MAX;
    bool hasTimeRange_ = false;
    bool success_ = true;
    bool hasSuccess_ = false;
    size_t limit_ = 100;
    size_t offset_ = 0;
    std::string orderBy_ = "timestamp";
    bool ascending_ = false;
};

/**
 * @brief Audit event types for filtering
 */
enum class AuditEventType {
    Authentication,
    Authorization,
    ConfigurationChange,
    DataAccess,
    SystemEvent,
    SecurityEvent
};

/**
 * @brief Audit event converter
 */
struct AuditEventConverter {
    static AuditEventType toEventType(const Action& action);
    static std::string toString(AuditEventType type);
};

} // namespace secreg

#endif // SECREG_AUDIT_H
