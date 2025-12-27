/**
 * @file daemon.h
 * @brief Main daemon interface for SecReg-Linux
 * @author SecReg Security Team
 * @version 1.0.0
 */

#ifndef SECREG_DAEMON_H
#define SECREG_DAEMON_H

#include "types.h"
#include "errors.h"
#include "storage/engine.h"
#include "crypto/crypto_manager.h"
#include <string>
#include <memory>
#include <functional>
#include <atomic>
#include <thread>

namespace secreg {

/**
 * @brief Daemon configuration
 */
struct DaemonConfig {
    std::string dbPath = PathConstants::DEFAULT_DB_PATH;
    std::string socketPath = PathConstants::DEFAULT_SOCKET_PATH;
    std::string logPath = PathConstants::DEFAULT_LOG_PATH;
    std::string configPath = PathConstants::DEFAULT_CONFIG_PATH;
    uint64_t sessionTimeout = CryptoConstants::DEFAULT_SESSION_TIMEOUT;
    uint32_t maxSessions = SessionConstants::MAX_SESSIONS_PER_USER;
    bool enableRemoteAccess = false;
    uint16_t remotePort = NetworkConstants::DEFAULT_PORT;
    bool requireMfa = false;
    bool dropPrivileges = SecurityConstants::DROP_PRIVILEGES;
    std::string runAsUser = SecurityConstants::DEFAULT_USER;
    std::string runAsGroup = SecurityConstants::DEFAULT_GROUP;
};

/**
 * @brief Main registry daemon
 */
class RegistryDaemon {
public:
    explicit RegistryDaemon(const DaemonConfig& config);
    ~RegistryDaemon();
    
    // Lifecycle
    bool initialize(const std::string& password);
    bool start();
    bool stop();
    bool restart();
    
    // Status
    bool isRunning() const;
    bool isInitialized() const;
    std::string getStatus() const;
    
    // Configuration
    void reloadConfig();
    DaemonConfig getConfig() const;
    
    // Operations (for internal use)
    class OperationContext;
    
    std::optional<RegistryEntry> getValue(const std::string& key, 
                                          bool decrypt,
                                          OperationContext& ctx);
    void setValue(const RegistryEntry& entry, 
                  bool encrypt,
                  OperationContext& ctx);
    bool deleteValue(const std::string& key, OperationContext& ctx);
    std::vector<std::string> listKeys(const std::string& prefix,
                                       bool recursive,
                                       OperationContext& ctx);
    
    // Event callbacks
    void setOnStartCallback(std::function<void()> callback);
    void setOnStopCallback(std::function<void()> callback);
    void setOnConnectionCallback(std::function<void(const std::string&)> callback);

private:
    DaemonConfig config_;
    std::shared_ptr<CryptoManager> cryptoManager_;
    std::unique_ptr<StorageEngine> storage_;
    
    std::atomic<bool> running_{false};
    std::atomic<bool> initialized_{false};
    std::thread serverThread_;
    std::thread cleanupThread_;
    
    std::function<void()> onStartCallback_;
    std::function<void()> onStopCallback_;
    std::function<void(const std::string&)> onConnectionCallback_;
    
    void runServer();
    void runCleanup();
    void setupSignalHandlers();
    void cleanup();
};

/**
 * @brief Operation context for daemon operations
 */
class RegistryDaemon::OperationContext {
public:
    std::string sessionId;
    std::string userName;
    uint32_t userId;
    std::optional<std::string> remoteAddress;
    bool isAdmin = false;
};

} // namespace secreg

#endif // SECREG_DAEMON_H
