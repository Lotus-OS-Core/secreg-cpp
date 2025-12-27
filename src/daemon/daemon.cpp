/**
 * @file daemon.cpp
 * @brief Main daemon implementation for SecReg-Linux
 * @author SecReg Security Team
 * @version 1.0.0
 */

#include "daemon.h"
#include "server.h"
#include "auth.h"
#include "acl.h"
#include "audit.h"
#include "constants.h"
#include "utils.h"
#include <iostream>
#include <csignal>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

namespace secreg {

static std::atomic<bool> g_running{true};
static std::function<void(int)> g_signalHandler;

static void signalHandler(int sig) {
    g_running = false;
    if (g_signalHandler) {
        g_signalHandler(sig);
    }
}

// RegistryDaemon implementation

RegistryDaemon::RegistryDaemon(const DaemonConfig& config)
    : config_(config) {
    // Ensure directories exist
    ensureDirectory(PathConstants::DB_DIR);
    ensureDirectory(PathConstants::LOG_DIR);
    ensureDirectory(PathConstants::SOCKET_DIR);
    
    // Set directory permissions
    chmod(PathConstants::DB_DIR, 0700);
    chmod(PathConstants::LOG_DIR, 0700);
    chmod(PathConstants::SOCKET_DIR, 0700);
}

RegistryDaemon::~RegistryDaemon() {
    stop();
}

bool RegistryDaemon::initialize(const std::string& password) {
    if (initialized_) {
        throw GeneralException("Daemon already initialized",
                               ErrorCode::InvalidState);
    }
    
    // Create crypto manager
    auto keyProvider = std::make_shared<SoftwareKeyProvider>(
        PathConstants::MASTER_KEY_PATH);
    keyProvider->initialize(password);
    
    cryptoManager_ = std::make_shared<CryptoManager>(keyProvider);
    
    // Create storage engine
    StorageConfig storageConfig;
    storageConfig.dbPath = config_.dbPath;
    storageConfig.logPath = config_.logPath;
    storage_ = std::make_unique<StorageEngine>(storageConfig, cryptoManager_);
    
    initialized_ = true;
    
    return true;
}

bool RegistryDaemon::start() {
    if (!initialized_) {
        throw GeneralException("Daemon not initialized",
                               ErrorCode::InvalidState);
    }
    
    if (running_) {
        return true;
    }
    
    // Setup signal handlers
    g_signalHandler = [this](int sig) {
        std::cout << "Received signal " << sig << ", stopping..." << std::endl;
        stop();
    };
    
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    signal(SIGHUP, signalHandler);
    
    // Start cleanup thread
    cleanupThread_ = std::thread(&RegistryDaemon::runCleanup, this);
    
    // Start server thread
    running_ = true;
    serverThread_ = std::thread(&RegistryDaemon::runServer, this);
    
    if (onStartCallback_) {
        onStartCallback_();
    }
    
    return true;
}

bool RegistryDaemon::stop() {
    if (!running_) {
        return true;
    }
    
    running_ = false;
    
    // Stop server
    stopServer();
    
    // Wait for threads
    if (serverThread_.joinable()) {
        serverThread_.join();
    }
    
    if (cleanupThread_.joinable()) {
        cleanupThread_.join();
    }
    
    if (onStopCallback_) {
        onStopCallback_();
    }
    
    return true;
}

bool RegistryDaemon::restart() {
    stop();
    return start();
}

bool RegistryDaemon::isRunning() const {
    return running_;
}

bool RegistryDaemon::isInitialized() const {
    return initialized_;
}

std::string RegistryDaemon::getStatus() const {
    std::ostringstream status;
    status << "Status: " << (running_ ? "Running" : "Stopped") << "\n";
    status << "Initialized: " << (initialized_ ? "Yes" : "No") << "\n";
    status << "Socket: " << config_.socketPath << "\n";
    status << "Database: " << config_.dbPath << "\n";
    
    if (storage_) {
        status << "Keys: " << storage_->getKeyCount() << "\n";
        status << "Size: " << formatFileSize(storage_->getSize()) << "\n";
    }
    
    return status.str();
}

void RegistryDaemon::reloadConfig() {
    // Reload configuration from file
    // For now, just log it
    std::cout << "Configuration reloaded" << std::endl;
}

DaemonConfig RegistryDaemon::getConfig() const {
    return config_;
}

std::optional<RegistryEntry> RegistryDaemon::getValue(const std::string& key,
                                                        bool decrypt,
                                                        OperationContext& ctx) {
    return storage_->get(key, decrypt);
}

void RegistryDaemon::setValue(const RegistryEntry& entry,
                               bool encrypt,
                               OperationContext& ctx) {
    storage_->set(entry, encrypt);
}

bool RegistryDaemon::deleteValue(const std::string& key, OperationContext& ctx) {
    return storage_->remove(key);
}

std::vector<std::string> RegistryDaemon::listKeys(const std::string& prefix,
                                                    bool recursive,
                                                    OperationContext& ctx) {
    return storage_->listKeys(prefix, recursive);
}

void RegistryDaemon::setOnStartCallback(std::function<void()> callback) {
    onStartCallback_ = callback;
}

void RegistryDaemon::setOnStopCallback(std::function<void()> callback) {
    onStopCallback_ = callback;
}

void RegistryDaemon::setOnConnectionCallback(
    std::function<void(const std::string&)> callback) {
    onConnectionCallback_ = callback;
}

void RegistryDaemon::runServer() {
    runServerThread(config_.socketPath);
}

void RegistryDaemon::runCleanup() {
    while (running_) {
        std::this_thread::sleep_for(std::chrono::seconds(
            SessionConstants::SESSION_CLEANUP_INTERVAL));
        
        if (!running_) break;
        
        // Cleanup expired sessions
        cleanupSessions();
        
        // Compact database
        if (storage_) {
            storage_->compact();
        }
    }
}

void RegistryDaemon::cleanup() {
    // Final cleanup
    if (cryptoManager_) {
        cryptoManager_->~CryptoManager();
    }
}

} // namespace secreg
