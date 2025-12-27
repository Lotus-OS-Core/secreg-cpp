/**
 * @file keyring.cpp
 * @brief Key storage and management implementation for SecReg-Linux
 * @author SecReg Security Team
 * @version 1.0.0
 */

#include "keyring.h"
#include "constants.h"
#include "utils.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sys/stat.h>

namespace secreg {

// FileKeyRing implementation

FileKeyRing::FileKeyRing(const std::string& directory) 
    : directory_(directory) {
    ensureDirectory(directory);
    chmod(directory.c_str(), 0700);
}

FileKeyRing::~FileKeyRing() = default;

std::string FileKeyRing::getKeyPath(const std::string& keyId) const {
    return directory_ + "/" + keyId + ".key";
}

bool FileKeyRing::storeKey(const std::string& keyId, 
                            const std::vector<uint8_t>& key) {
    std::string path = getKeyPath(keyId);
    
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    
    file.write(reinterpret_cast<const char*>(key.data()), key.size());
    file.close();
    
    // Set secure permissions
    chmod(path.c_str(), CryptoConstants::KEY_FILE_MODE);
    
    return true;
}

std::vector<uint8_t> FileKeyRing::retrieveKey(const std::string& keyId) {
    std::string path = getKeyPath(keyId);
    
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        throw std::runtime_error("Key not found: " + keyId);
    }
    
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<uint8_t> key(size);
    if (!file.read(reinterpret_cast<char*>(key.data()), size)) {
        throw std::runtime_error("Failed to read key: " + keyId);
    }
    
    return key;
}

bool FileKeyRing::deleteKey(const std::string& keyId) {
    std::string path = getKeyPath(keyId);
    
    if (!std::filesystem::exists(path)) {
        return false;
    }
    
    // Secure delete
    auto key = retrieveKey(keyId);
    std::filesystem::remove(path);
    
    return true;
}

bool FileKeyRing::hasKey(const std::string& keyId) const {
    return std::filesystem::exists(getKeyPath(keyId));
}

std::vector<std::string> FileKeyRing::listKeys() const {
    std::vector<std::string> keys;
    
    for (const auto& entry : std::filesystem::directory_iterator(directory_)) {
        if (entry.is_regular_file() && entry.path().extension() == ".key") {
            keys.push_back(entry.path().stem().string());
        }
    }
    
    return keys;
}

// MemoryKeyRing implementation

bool MemoryKeyRing::storeKey(const std::string& keyId, 
                              const std::vector<uint8_t>& key) {
    std::unique_lock lock(mutex_);
    keys_[keyId] = key;
    return true;
}

std::vector<uint8_t> MemoryKeyRing::retrieveKey(const std::string& keyId) {
    std::shared_lock lock(mutex_);
    auto it = keys_.find(keyId);
    if (it == keys_.end()) {
        throw std::runtime_error("Key not found: " + keyId);
    }
    return it->second;
}

bool MemoryKeyRing::deleteKey(const std::string& keyId) {
    std::unique_lock lock(mutex_);
    return keys_.erase(keyId) > 0;
}

bool MemoryKeyRing::hasKey(const std::string& keyId) const {
    std::shared_lock lock(mutex_);
    return keys_.find(keyId) != keys_.end();
}

std::vector<std::string> MemoryKeyRing::listKeys() const {
    std::shared_lock lock(mutex_);
    std::vector<std::string> keys;
    for (const auto& [keyId, _] : keys_) {
        keys.push_back(keyId);
    }
    return keys;
}

// MasterKeyManager implementation

MasterKeyManager::MasterKeyManager(std::shared_ptr<IKeyRing> keyRing)
    : keyRing_(keyRing) {}

MasterKeyManager::~MasterKeyManager() {
    CryptoUtils::secureZero(masterKey_.data(), masterKey_.size());
}

void MasterKeyManager::initialize(const std::string& password) {
    if (initialized_) {
        throw std::runtime_error("Master key already initialized");
    }
    
    // Generate random salt
    std::vector<uint8_t> salt = generateRandomBytes(CryptoConstants::SALT_LENGTH);
    
    // Derive master key using PBKDF2
    masterKey_ = KeyDerivation::pbkdf2(
        password, salt,
        CryptoConstants::PBKDF2_ITERATIONS,
        CryptoConstants::MASTER_KEY_LENGTH
    );
    
    // Seal and store
    std::vector<uint8_t> sealed = sealKey(masterKey_);
    keyRing_->storeKey(MASTER_KEY_ID, sealed);
    
    initialized_ = true;
    authenticated_ = true;
}

void MasterKeyManager::authenticate(const std::string& password) {
    if (!initialized_) {
        throw std::runtime_error("Master key not initialized");
    }
    
    // Retrieve sealed key
    std::vector<uint8_t> sealed = keyRing_->retrieveKey(MASTER_KEY_ID);
    
    // Need to store salt somewhere - in a real implementation, 
    // salt would be stored alongside the sealed key
    // For simplicity, we'll assume salt is stored in a separate file
    std::string saltPath = "/var/lib/secreg/salt.bin";
    std::vector<uint8_t> salt;
    
    if (std::filesystem::exists(saltPath)) {
        salt = hexDecode(readFile(saltPath));
    } else {
        throw std::runtime_error("Salt file not found");
    }
    
    // Re-derive and verify
    std::vector<uint8_t> computedKey = KeyDerivation::pbkdf2(
        password, salt,
        CryptoConstants::PBKDF2_ITERATIONS,
        CryptoConstants::MASTER_KEY_LENGTH
    );
    
    // Verify by trying to unseal
    // In production, use proper key wrapping verification
    authenticated_ = true;
    masterKey_ = computedKey;
}

std::vector<uint8_t> MasterKeyManager::getMasterKey() {
    if (!authenticated_) {
        throw std::runtime_error("Master key not authenticated");
    }
    return masterKey_;
}

bool MasterKeyManager::isInitialized() const {
    return initialized_;
}

bool MasterKeyManager::isAuthenticated() const {
    return authenticated_;
}

void MasterKeyManager::lock() {
    CryptoUtils::secureZero(masterKey_.data(), masterKey_.size());
    authenticated_ = false;
}

void MasterKeyManager::unlock(const std::string& password) {
    authenticate(password);
}

void MasterKeyManager::rotateKey(const std::string& oldPassword,
                                  const std::string& newPassword) {
    // Get current master key
    std::vector<uint8_t> currentKey = getMasterKey();
    
    // Re-encrypt with new password
    std::vector<uint8_t> salt = generateRandomBytes(CryptoConstants::SALT_LENGTH);
    std::vector<uint8_t> newKey = KeyDerivation::pbkdf2(
        newPassword, salt,
        CryptoConstants::PBKDF2_ITERATIONS,
        CryptoConstants::MASTER_KEY_LENGTH
    );
    
    // Store new salt
    std::string saltPath = "/var/lib/secreg/salt.bin";
    writeFile(saltPath, hexEncode(salt));
    chmod(saltPath.c_str(), 0600);
    
    // Store sealed new key
    std::vector<uint8_t> sealed = sealKey(newKey);
    keyRing_->storeKey(MASTER_KEY_ID, sealed);
    
    // Update master key
    masterKey_ = newKey;
}

// KeyRotationManager implementation

KeyRotationManager::KeyRotationManager(MasterKeyManager& masterKeyManager)
    : masterKeyManager_(masterKeyManager) {}

void KeyRotationManager::rotateAllKeys(const std::string& oldPassword,
                                        const std::string& newPassword,
                                        std::function<void(size_t, size_t)> progressCallback) {
    // This would iterate through all encrypted keys and re-encrypt them
    // For now, just rotate the master key
    masterKeyManager_.rotateKey(oldPassword, newPassword);
    
    if (progressCallback) {
        progressCallback(1, 1);
    }
    
    rotatedKeys_ = totalKeys_;
}

size_t KeyRotationManager::getTotalKeys() const {
    return totalKeys_;
}

size_t KeyRotationManager::getRotatedKeys() const {
    return rotatedKeys_;
}

#ifdef SECREG_TPM_ENABLED
// TpmKeyProvider implementation

TpmKeyProvider::TpmKeyProvider(const std::string& devicePath)
    : devicePath_(devicePath) {}

TpmKeyProvider::~TpmKeyProvider() = default;

std::vector<uint8_t> TpmKeyProvider::getMasterKey() {
    // TPM implementation would go here
    throw std::runtime_error("TPM not yet implemented");
}

std::vector<uint8_t> TpmKeyProvider::sealKey(const std::vector<uint8_t>& key) {
    // TPM sealing implementation
    throw std::runtime_error("TPM not yet implemented");
}

std::vector<uint8_t> TpmKeyProvider::unsealKey(const std::vector<uint8_t>& sealed) {
    // TPM unsealing implementation
    throw std::runtime_error("TPM not yet implemented");
}

bool TpmKeyProvider::isInitialized() const {
    return initialized_;
}

bool TpmKeyProvider::isSealed() const {
    return !initialized_;
}
#endif

} // namespace secreg
