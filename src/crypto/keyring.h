/**
 * @file keyring.h
 * @brief Key storage and management for SecReg-Linux
 * @author SecReg Security Team
 * @version 1.0.0
 */

#ifndef SECREG_KEYRING_H
#define SECREG_KEYRING_H

#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace secreg {

/**
 * @brief Key ring interface for secure key storage
 */
class IKeyRing {
public:
    virtual ~IKeyRing() = default;
    virtual bool storeKey(const std::string& keyId, 
                          const std::vector<uint8_t>& key) = 0;
    virtual std::vector<uint8_t> retrieveKey(const std::string& keyId) = 0;
    virtual bool deleteKey(const std::string& keyId) = 0;
    virtual bool hasKey(const std::string& keyId) const = 0;
    virtual std::vector<std::string> listKeys() const = 0;
};

/**
 * @brief File-based key ring
 */
class FileKeyRing : public IKeyRing {
public:
    explicit FileKeyRing(const std::string& directory);
    ~FileKeyRing() override;
    
    bool storeKey(const std::string& keyId, 
                  const std::vector<uint8_t>& key) override;
    std::vector<uint8_t> retrieveKey(const std::string& keyId) override;
    bool deleteKey(const std::string& keyId) override;
    bool hasKey(const std::string& keyId) const override;
    std::vector<std::string> listKeys() const override;

private:
    std::string directory_;
    
    std::string getKeyPath(const std::string& keyId) const;
};

/**
 * @brief In-memory key ring (for testing)
 */
class MemoryKeyRing : public IKeyRing {
public:
    bool storeKey(const std::string& keyId, 
                  const std::vector<uint8_t>& key) override;
    std::vector<uint8_t> retrieveKey(const std::string& keyId) override;
    bool deleteKey(const std::string& keyId) override;
    bool hasKey(const std::string& keyId) const override;
    std::vector<std::string> listKeys() const override;

private:
    std::map<std::string, std::vector<uint8_t>> keys_;
    mutable std::shared_mutex mutex_;
};

/**
 * @brief Master key manager
 */
class MasterKeyManager {
public:
    explicit MasterKeyManager(std::shared_ptr<IKeyRing> keyRing);
    ~MasterKeyManager();
    
    void initialize(const std::string& password);
    void authenticate(const std::string& password);
    std::vector<uint8_t> getMasterKey();
    
    bool isInitialized() const;
    bool isAuthenticated() const;
    
    void lock();
    void unlock(const std::string& password);
    
    void rotateKey(const std::string& oldPassword, 
                   const std::string& newPassword);

private:
    std::shared_ptr<IKeyRing> keyRing_;
    std::vector<uint8_t> masterKey_;
    bool initialized_ = false;
    bool authenticated_ = false;
    
    static constexpr const char* MASTER_KEY_ID = "master";
};

/**
 * @brief Key rotation manager
 */
class KeyRotationManager {
public:
    explicit KeyRotationManager(MasterKeyManager& masterKeyManager);
    
    void rotateAllKeys(const std::string& oldPassword,
                       const std::string& newPassword,
                       std::function<void(size_t, size_t)> progressCallback);
    
    size_t getTotalKeys() const;
    size_t getRotatedKeys() const;

private:
    MasterKeyManager& masterKeyManager_;
    size_t totalKeys_ = 0;
    size_t rotatedKeys_ = 0;
};

/**
 * @brief Hardware security module (HSM) key provider
 */
#ifdef SECREG_TPM_ENABLED
class TpmKeyProvider : public IKeyProvider {
public:
    explicit TpmKeyProvider(const std::string& devicePath = "/dev/tpm0");
    ~TpmKeyProvider() override;
    
    std::vector<uint8_t> getMasterKey() override;
    std::vector<uint8_t> sealKey(const std::vector<uint8_t>& key) override;
    std::vector<uint8_t> unsealKey(const std::vector<uint8_t>& sealed) override;
    bool isInitialized() const override;
    bool isSealed() const override;

private:
    std::string devicePath_;
    bool initialized_ = false;
    // TPM2 context handles would go here
};
#endif

} // namespace secreg

#endif // SECREG_KEYRING_H
