/**
 * @file crypto_manager.h
 * @brief Cryptographic manager for SecReg-Linux
 * @author SecReg Security Team
 * @version 1.0.0
 */

#ifndef SECREG_CRYPTO_MANAGER_H
#define SECREG_CRYPTO_MANAGER_H

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include "errors.h"

namespace secreg {

/**
 * @brief Key provider interface for different key storage backends
 */
class IKeyProvider {
public:
    virtual ~IKeyProvider() = default;
    virtual std::vector<uint8_t> getMasterKey() = 0;
    virtual std::vector<uint8_t> sealKey(const std::vector<uint8_t>& key) = 0;
    virtual std::vector<uint8_t> unsealKey(const std::vector<uint8_t>& sealed) = 0;
    virtual bool isInitialized() const = 0;
    virtual bool isSealed() const = 0;
};

/**
 * @brief Software-based key provider (password-based key derivation)
 */
class SoftwareKeyProvider : public IKeyProvider {
public:
    explicit SoftwareKeyProvider(const std::string& keyPath);
    ~SoftwareKeyProvider() override;
    
    void initialize(const std::string& password);
    void authenticate(const std::string& password);
    
    std::vector<uint8_t> getMasterKey() override;
    std::vector<uint8_t> sealKey(const std::vector<uint8_t>& key) override;
    std::vector<uint8_t> unsealKey(const std::vector<uint8_t>& sealed) override;
    bool isInitialized() const override;
    bool isSealed() const override;

private:
    std::string keyPath_;
    std::vector<uint8_t> masterKey_;
    bool initialized_ = false;
    bool authenticated_ = false;
    
    void deriveKeyFromPassword(const std::string& password, 
                                const std::vector<uint8_t>& salt,
                                std::vector<uint8_t>& key);
    void loadSealedKey();
    void saveSealedKey();
};

/**
 * @brief Main cryptographic manager
 */
class CryptoManager {
public:
    explicit CryptoManager(std::shared_ptr<IKeyProvider> keyProvider);
    ~CryptoManager();
    
    // Encryption/decryption
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext,
                                  const std::vector<uint8_t>& associatedData = {});
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext,
                                  const std::vector<uint8_t>& associatedData = {});
    
    // Field-level encryption for registry values
    std::vector<uint8_t> encryptField(const std::string& plaintext, 
                                       const std::string& keyPath);
    std::string decryptField(const std::vector<uint8_t>& encrypted,
                              const std::string& keyPath);
    
    // Key derivation
    std::vector<uint8_t> deriveKey(const std::string& purpose,
                                    const std::vector<uint8_t>& salt);
    std::vector<uint8_t> deriveKey(const std::string& purpose,
                                    const std::string& keyPath);
    
    // HMAC
    std::vector<uint8_t> hmac(const std::vector<uint8_t>& data,
                               const std::vector<uint8_t>& key);
    bool verifyHmac(const std::vector<uint8_t>& data,
                    const std::vector<uint8_t>& key,
                    const std::vector<uint8_t>& expectedMac);
    
    // Hashing
    std::vector<uint8_t> sha256(const std::vector<uint8_t>& data);
    std::vector<uint8_t> sha512(const std::vector<uint8_t>& data);
    
    // Random bytes
    std::vector<uint8_t> randomBytes(size_t length);
    std::string randomString(size_t length);
    
    // Master key access (for internal use)
    std::vector<uint8_t> getMasterKey();
    
    // Re-encryption (for key rotation)
    void reEncrypt(const std::string& oldPassword, 
                   const std::string& newPassword);
    
    // Status
    bool isReady() const;
    std::string getAlgorithm() const;

private:
    std::shared_ptr<IKeyProvider> keyProvider_;
    std::vector<uint8_t> cachedKey_;
    std::vector<uint8_t> fieldEncryptionKey_;
    std::vector<uint8_t> hmacKey_;
    uint64_t nonceCounter_ = 0;
    const size_t KEY_SIZE = 32;
    const size_t NONCE_SIZE = 24;
    
    void initializeKeys();
    std::vector<uint8_t> generateNonce();
};

/**
 * @brief Crypto utilities
 */
struct CryptoUtils {
    static bool constantTimeCompare(const std::vector<uint8_t>& a, 
                                     const std::vector<uint8_t>& b);
    static void secureZero(void* ptr, size_t size);
    static std::vector<uint8_t> xorBuffers(const std::vector<uint8_t>& a,
                                            const std::vector<uint8_t>& b);
};

} // namespace secreg

#endif // SECREG_CRYPTO_MANAGER_H
