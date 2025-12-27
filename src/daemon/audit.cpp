/**
 * @file audit.cpp
 * @brief Audit logging implementation for SecReg-Linux
 * @author SecReg Security Team
 * @version 1.0.0
 */

#include "audit.h"
#include "constants.h"
#include "utils.h"
#include <openssl/sha.h>
#include <fstream>
#include <iostream>
#include <syslog.h>

namespace secreg {

// AuditLogger implementation

AuditLogger::AuditLogger(const AuditConfig& config)
    : config_(config) {
    // Initialize chain hash
    chainHash_ = computeHash("secreg-audit-chain-v1");
    
    // Ensure log directory exists
    ensureDirectory(config_.logPath);
    
    // Start writer thread if async mode enabled
    if (config_.asyncWrite) {
        running_ = true;
        writerThread_ = std::thread(&AuditLogger::writerLoop, this);
    }
}

AuditLogger::~AuditLogger() {
    if (config_.asyncWrite) {
        running_ = false;
        dirty_ = true;
        if (writerThread_.joinable()) {
            writerThread_.join();
        }
    }
    
    flush();
}

void AuditLogger::log(const AuditRecord& record) {
    AuditChainEntry entry;
    entry.index = entryCounter_++;
    entry.record = record;
    entry.previousHash = chainHash_;
    entry.timestamp = getCurrentTimestamp();
    
    // Compute chain hash
    std::string recordJson = serializeAuditRecord(record);
    std::string combined = chainHash_ + recordJson + 
                          std::to_string(entry.timestamp);
    entry.currentHash = computeHash(combined);
    chainHash_ = entry.currentHash;
    
    {
        std::unique_lock lock(mutex_);
        entries_.push_back(entry);
    }
    
    if (!config_.asyncWrite) {
        writeEntry(entry);
    } else {
        dirty_ = true;
    }
    
    writeToSyslog(record);
}

void AuditLogger::logAuthSuccess(const ActorInfo& actor, const std::string& target) {
    AuditRecord record;
    record.id = generateUuid();
    record.timestamp = getCurrentTimestamp();
    record.actor = actor;
    record.action = Action::Read; // Auth is a read operation
    record.target_key = target;
    record.success = true;
    record.source_info.client_version = AppConstants::APP_VERSION;
    
    log(record);
}

void AuditLogger::logAuthFailure(const ActorInfo& actor, const std::string& target,
                                  const std::string& reason) {
    AuditRecord record;
    record.id = generateUuid();
    record.timestamp = getCurrentTimestamp();
    record.actor = actor;
    record.action = Action::Read;
    record.target_key = target;
    record.success = false;
    record.error_message = reason;
    record.source_info.client_version = AppConstants::APP_VERSION;
    
    log(record);
}

void AuditLogger::logAccess(const ActorInfo& actor, const std::string& target,
                             Action action, bool success, 
                             const std::string& reason) {
    AuditRecord record;
    record.id = generateUuid();
    record.timestamp = getCurrentTimestamp();
    record.actor = actor;
    record.action = action;
    record.target_key = target;
    record.success = success;
    if (!success) {
        record.error_message = reason;
    }
    record.source_info.client_version = AppConstants::APP_VERSION;
    
    log(record);
}

void AuditLogger::logChange(const ActorInfo& actor, const std::string& target,
                             const std::string& oldValue, 
                             const std::string& newValue) {
    AuditRecord record;
    record.id = generateUuid();
    record.timestamp = getCurrentTimestamp();
    record.actor = actor;
    record.action = Action::Write;
    record.target_key = target;
    record.success = true;
    record.previous_value_hash = computeHash(oldValue);
    record.new_value_hash = computeHash(newValue);
    record.source_info.client_version = AppConstants::APP_VERSION;
    
    log(record);
}

void AuditLogger::logError(const std::string& category, int code,
                           const std::string& message) {
    AuditRecord record;
    record.id = generateUuid();
    record.timestamp = getCurrentTimestamp();
    record.target_key = "system/error";
    record.success = false;
    record.error_message = "[" + category + "] " + 
                          std::to_string(code) + ": " + message;
    record.source_info.client_version = AppConstants::APP_VERSION;
    
    log(record);
}

std::vector<AuditRecord> AuditLogger::query(const std::string& conditions,
                                              size_t limit, size_t offset) {
    std::shared_lock lock(mutex_);
    
    std::vector<AuditRecord> results;
    size_t skipped = 0;
    
    for (const auto& entry : entries_) {
        if (skipped < offset) {
            skipped++;
            continue;
        }
        
        if (results.size() >= limit) {
            break;
        }
        
        results.push_back(entry.record);
    }
    
    return results;
}

std::vector<AuditRecord> AuditLogger::queryByUser(const std::string& userName,
                                                    uint64_t startTime,
                                                    uint64_t endTime,
                                                    size_t limit) {
    std::shared_lock lock(mutex_);
    
    std::vector<AuditRecord> results;
    
    for (const auto& entry : entries_) {
        if (results.size() >= limit) {
            break;
        }
        
        if (entry.record.timestamp < startTime || 
            entry.record.timestamp > endTime) {
            continue;
        }
        
        if (entry.record.actor.user_name != userName) {
            continue;
        }
        
        results.push_back(entry.record);
    }
    
    return results;
}

std::vector<AuditRecord> AuditLogger::queryByKey(const std::string& keyPath,
                                                   uint64_t startTime,
                                                   uint64_t endTime,
                                                   size_t limit) {
    std::shared_lock lock(mutex_);
    
    std::vector<AuditRecord> results;
    
    for (const auto& entry : entries_) {
        if (results.size() >= limit) {
            break;
        }
        
        if (entry.record.timestamp < startTime || 
            entry.record.timestamp > endTime) {
            continue;
        }
        
        if (entry.record.target_key.find(keyPath) != 0) {
            continue;
        }
        
        results.push_back(entry.record);
    }
    
    return results;
}

std::vector<AuditRecord> AuditLogger::queryByAction(Action action,
                                                     uint64_t startTime,
                                                     uint64_t endTime,
                                                     size_t limit) {
    std::shared_lock lock(mutex_);
    
    std::vector<AuditRecord> results;
    
    for (const auto& entry : entries_) {
        if (results.size() >= limit) {
            break;
        }
        
        if (entry.record.timestamp < startTime || 
            entry.record.timestamp > endTime) {
            continue;
        }
        
        if (entry.record.action != action) {
            continue;
        }
        
        results.push_back(entry.record);
    }
    
    return results;
}

bool AuditLogger::verifyChain() {
    std::shared_lock lock(mutex_);
    
    std::string expectedHash = computeHash("secreg-audit-chain-v1");
    std::string currentHash = expectedHash;
    
    for (const auto& entry : entries_) {
        if (entry.previousHash != currentHash) {
            return false;
        }
        
        std::string recordJson = serializeAuditRecord(entry.record);
        std::string combined = currentHash + recordJson + 
                              std::to_string(entry.timestamp);
        currentHash = computeHash(combined);
    }
    
    return currentHash == chainHash_;
}

bool AuditLogger::verifyEntry(uint64_t index) {
    std::shared_lock lock(mutex_);
    
    if (index >= entries_.size()) {
        return false;
    }
    
    const auto& entry = entries_[index];
    
    std::string recordJson = serializeAuditRecord(entry.record);
    std::string combined = entry.previousHash + recordJson + 
                          std::to_string(entry.timestamp);
    std::string computedHash = computeHash(combined);
    
    return computedHash == entry.currentHash;
}

std::vector<uint64_t> AuditLogger::findTamperedEntries() {
    std::shared_lock lock(mutex_);
    
    std::vector<uint64_t> tampered;
    std::string expectedHash = computeHash("secreg-audit-chain-v1");
    std::string currentHash = expectedHash;
    
    for (size_t i = 0; i < entries_.size(); ++i) {
        const auto& entry = entries_[i];
        
        if (entry.previousHash != currentHash) {
            tampered.push_back(i);
        }
        
        std::string recordJson = serializeAuditRecord(entry.record);
        std::string combined = currentHash + recordJson + 
                              std::to_string(entry.timestamp);
        currentHash = computeHash(combined);
    }
    
    if (currentHash != chainHash_) {
        // Last entry is tampered
    }
    
    return tampered;
}

std::vector<uint8_t> AuditLogger::exportChain() {
    std::shared_lock lock(mutex_);
    
    std::vector<uint8_t> data;
    
    // Write header
    uint32_t version = 1;
    data.insert(data.end(), 
                reinterpret_cast<const uint8_t*>(&version),
                reinterpret_cast<const uint8_t*>(&version) + sizeof(version));
    
    // Write entry count
    uint64_t count = entries_.size();
    data.insert(data.end(),
                reinterpret_cast<const uint8_t*>(&count),
                reinterpret_cast<const uint8_t*>(&count) + sizeof(count));
    
    // Write chain hash
    uint32_t hashLen = chainHash_.size();
    data.insert(data.end(),
                reinterpret_cast<const uint8_t*>(&hashLen),
                reinterpret_cast<const uint8_t*>(&hashLen) + sizeof(hashLen));
    data.insert(data.end(), chainHash_.begin(), chainHash_.end());
    
    // Write entries
    for (const auto& entry : entries_) {
        // Write index
        data.insert(data.end(),
                    reinterpret_cast<const uint8_t*>(&entry.index),
                    reinterpret_cast<const uint8_t*>(&entry.index) + sizeof(entry.index));
        
        // Write timestamp
        data.insert(data.end(),
                    reinterpret_cast<const uint8_t*>(&entry.timestamp),
                    reinterpret_cast<const uint8_t*>(&entry.timestamp) + sizeof(entry.timestamp));
        
        // Write hashes
        uint32_t prevLen = entry.previousHash.size();
        data.insert(data.end(),
                    reinterpret_cast<const uint8_t*>(&prevLen),
                    reinterpret_cast<const uint8_t*>(&prevLen) + sizeof(prevLen));
        data.insert(data.end(), entry.previousHash.begin(), entry.previousHash.end());
        
        uint32_t currLen = entry.currentHash.size();
        data.insert(data.end(),
                    reinterpret_cast<const uint8_t*>(&currLen),
                    reinterpret_cast<const uint8_t*>(&currLen) + sizeof(currLen));
        data.insert(data.end(), entry.currentHash.begin(), entry.currentHash.end());
        
        // Write record
        std::string recordJson = serializeAuditRecord(entry.record);
        uint32_t recordLen = recordJson.size();
        data.insert(data.end(),
                    reinterpret_cast<const uint8_t*>(&recordLen),
                    reinterpret_cast<const uint8_t*>(&recordLen) + sizeof(recordLen));
        data.insert(data.end(), recordJson.begin(), recordJson.end());
    }
    
    return data;
}

std::vector<uint8_t> AuditLogger::exportToJson() {
    std::shared_lock lock(mutex_);
    
    std::string json = "[\n";
    
    for (size_t i = 0; i < entries_.size(); ++i) {
        if (i > 0) {
            json += ",\n";
        }
        json += auditRecordToJson(entries_[i].record);
    }
    
    json += "\n]";
    
    return std::vector<uint8_t>(json.begin(), json.end());
}

void AuditLogger::truncate(uint64_t beforeTimestamp) {
    std::unique_lock lock(mutex_);
    
    // Remove entries before timestamp
    while (!entries_.empty() && entries_.front().timestamp < beforeTimestamp) {
        entries_.pop_front();
    }
}

void AuditLogger::compact() {
    std::unique_lock lock(mutex_);
    
    // Remove old entries beyond retention
    uint64_t cutoff = getCurrentTimestampSeconds() - 
                      config_.retentionDays * 86400;
    truncate(cutoff * 1000);
}

void AuditLogger::flush() {
    std::unique_lock lock(mutex_);
    
    while (!entries_.empty()) {
        writeEntry(entries_.front());
        entries_.pop_front();
    }
}

size_t AuditLogger::getEntryCount() const {
    std::shared_lock lock(mutex_);
    return entries_.size();
}

size_t AuditLogger::getLogSize() const {
    std::shared_lock lock(mutex_);
    
    size_t size = sizeof(uint32_t); // version
    size += sizeof(uint64_t); // entry count
    size += sizeof(uint32_t) + chainHash_.size(); // chain hash
    
    for (const auto& entry : entries_) {
        size += sizeof(uint64_t); // index
        size += sizeof(uint64_t); // timestamp
        size += sizeof(uint32_t) + entry.previousHash.size(); // prev hash
        size += sizeof(uint32_t) + entry.currentHash.size(); // curr hash
        size += sizeof(uint32_t); // record length
        size += serializeAuditRecord(entry.record).size(); // record
    }
    
    return size;
}

uint64_t AuditLogger::getFirstTimestamp() const {
    std::shared_lock lock(mutex_);
    
    if (entries_.empty()) {
        return 0;
    }
    
    return entries_.front().timestamp;
}

uint64_t AuditLogger::getLastTimestamp() const {
    std::shared_lock lock(mutex_);
    
    if (entries_.empty()) {
        return 0;
    }
    
    return entries_.back().timestamp;
}

void AuditLogger::writerLoop() {
    while (running_) {
        std::this_thread::sleep_for(
            std::chrono::milliseconds(config_.flushInterval));
        
        if (!running_) break;
        
        if (dirty_) {
            std::unique_lock lock(mutex_);
            
            while (entries_.size() > config_.batchSize && !entries_.empty()) {
                writeEntry(entries_.front());
                entries_.pop_front();
            }
            
            dirty_ = false;
        }
    }
}

void AuditLogger::writeEntry(const AuditChainEntry& entry) {
    std::string logPath = config_.logPath + "/" + 
                          std::to_string(entry.timestamp / 86400000) + ".log";
    
    std::ofstream file(logPath, std::ios::app);
    if (file.is_open()) {
        std::string recordJson = serializeAuditRecord(entry.record);
        file << recordJson << "\n";
        file.close();
    }
}

void AuditLogger::computeChainHash(const AuditRecord& record, std::string& hash) {
    std::string recordJson = serializeAuditRecord(record);
    hash = computeHash(chainHash_ + recordJson);
}

void AuditLogger::writeToSyslog(const AuditRecord& record) {
    int priority = record.success ? LOG_NOTICE : LOG_WARNING;
    
    std::string message = "SECREG: user=" + record.actor.user_name +
                         " action=" + actionToString(record.action) +
                         " target=" + record.target_key +
                         " success=" + (record.success ? "yes" : "no");
    
    if (record.error_message.has_value()) {
        message += " reason=" + record.error_message.value();
    }
    
    syslog(priority, "%s", message.c_str());
}

std::string AuditLogger::computeHash(const std::string& data) {
    std::vector<uint8_t> hash = sha256HashBytes(
        std::vector<uint8_t>(data.begin(), data.end()));
    return hexEncode(hash);
}

std::string AuditLogger::computeHash(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> hash = sha256HashBytes(data);
    return hexEncode(hash);
}

// AuditQuery implementation

AuditQuery::AuditQuery() = default;

AuditQuery& AuditQuery::forUser(const std::string& userName) {
    userName_ = userName;
    return *this;
}

AuditQuery& AuditQuery::forKey(const std::string& keyPath) {
    keyPath_ = keyPath;
    return *this;
}

AuditQuery& AuditQuery::forAction(Action action) {
    action_ = action;
    hasAction_ = true;
    return *this;
}

AuditQuery& AuditQuery::forTimeRange(uint64_t start, uint64_t end) {
    startTime_ = start;
    endTime_ = end;
    hasTimeRange_ = true;
    return *this;
}

AuditQuery& AuditQuery::forSuccess(bool success) {
    success_ = success;
    hasSuccess_ = true;
    return *this;
}

AuditQuery& AuditQuery::limit(size_t limit) {
    limit_ = limit;
    return *this;
}

AuditQuery& AuditQuery::offset(size_t offset) {
    offset_ = offset;
    return *this;
}

AuditQuery& AuditQuery::orderBy(const std::string& field, bool ascending) {
    orderBy_ = field;
    ascending_ = ascending;
    return *this;
}

std::vector<AuditRecord> AuditQuery::execute(AuditLogger& logger) {
    std::vector<AuditRecord> results;
    
    if (hasAction_) {
        results = logger.queryByAction(action_, startTime_, endTime_, limit_);
    } else if (!keyPath_.empty()) {
        results = logger.queryByKey(keyPath_, startTime_, endTime_, limit_);
    } else if (!userName_.empty()) {
        results = logger.queryByUser(userName_, startTime_, endTime_, limit_);
    } else {
        results = logger.query("", limit_, offset_);
    }
    
    // Apply success filter
    if (hasSuccess_) {
        std::vector<AuditRecord> filtered;
        for (const auto& record : results) {
            if (record.success == success_) {
                filtered.push_back(record);
            }
        }
        results = filtered;
    }
    
    return results;
}

size_t AuditQuery::count(AuditLogger& logger) {
    return execute(logger).size();
}

// AuditEventConverter implementation

AuditEventType AuditEventConverter::toEventType(const Action& action) {
    switch (action) {
        case Action::Read:
            return AuditEventType::DataAccess;
        case Action::Write:
            return AuditEventType::ConfigurationChange;
        case Action::Delete:
            return AuditEventType::ConfigurationChange;
        case Action::Grant:
            return AuditEventType::SecurityEvent;
        case Action::Admin:
            return AuditEventType::SystemEvent;
        default:
            return AuditEventType::SystemEvent;
    }
}

std::string AuditEventConverter::toString(AuditEventType type) {
    switch (type) {
        case AuditEventType::Authentication:
            return "authentication";
        case AuditEventType::Authorization:
            return "authorization";
        case AuditEventType::ConfigurationChange:
            return "configuration_change";
        case AuditEventType::DataAccess:
            return "data_access";
        case AuditEventType::SystemEvent:
            return "system_event";
        case AuditEventType::SecurityEvent:
            return "security_event";
        default:
            return "unknown";
    }
}

} // namespace secreg
