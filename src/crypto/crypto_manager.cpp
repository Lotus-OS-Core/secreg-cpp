/**
 * @file crypto_manager.cpp
 * @brief Cryptographic manager implementation for SecReg-Linux
 * @author SecReg Security Team
 * @version 1.0.0
 */

#include "crypto_manager.h"
#include "constants.h"
#include "utils.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <fstream>
#include <iostream>

namespace secreg {

// SoftwareKeyProvider implementation

SoftwareKeyProvider::SoftwareKeyProvider(const std::string& keyPath)
    : keyPath_(keyPath) {}

SoftwareKeyProvider::~SoftwareKeyProvider() {
    CryptoUtils::secureZero(masterKey_.data(), masterKey_.size());
}

void SoftwareKeyProvider::initialize(const std::string& password) {
    if (initialized_) {
        throw CryptoException("Key provider already initialized", 
                              ErrorCode::CryptoKeyNotInitialized);
    }
    
    // Generate random salt
    std::vector<uint8_t> salt = CryptoUtils::generateRandomBytes(
        CryptoConstants::SALT_LENGTH);
    
    // Derive master key
    deriveKeyFromPassword(password, salt, masterKey_);
    
    // Save sealed key
    saveSealedKey();
    
    initialized_ = true;
    authenticated_ = true;
}

void SoftwareKeyProvider::authenticate(const std::string& password) {
    if (!initialized_) {
        throw CryptoException("Key provider not initialized", 
                              ErrorCode::CryptoKeyNotInitialized);
    }
    
    loadSealedKey();
    
    // Re-derive and compare
    std::vector<uint8_t> computedKey(masterKey_.size());
    deriveKeyFromPassword(password, saltBuffer_, computedKey);
    
    if (!CryptoUtils::constantTimeCompare(masterKey_, computedKey)) {
        CryptoUtils::secureZero(computedKey.data(), computedKey.size());
        throw CryptoException("Invalid password", 
                              ErrorCode::AuthInvalidCredentials);
    }
    
    authenticated_ = true;
    CryptoUtils::secureZero(computedKey.data(), computedKey.size());
}

std::vector<uint8_t> SoftwareKeyProvider::getMasterKey() {
    if (!authenticated_) {
        throw CryptoException("Key provider not authenticated", 
                              ErrorCode::CryptoKeyNotInitialized);
    }
    return masterKey_;
}

std::vector<uint8_t> SoftwareKeyProvider::sealKey(const std::vector<uint8_t>& key) {
    // Simple key wrapping (in production, use proper key wrapping algorithm)
    std::vector<uint8_t> wrapped = masterKey_;
    std::vector<uint8_t> result;
    
    result.push_back(0x01); // Version
    result.push_back(0x01); // Algorithm version
    
    // Encrypt key with master key
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw CryptoException("Failed to create cipher context",
                              ErrorCode::CryptoEncryptionFailed);
    }
    
    std::vector<uint8_t> iv = CryptoUtils::generateRandomBytes(16);
    result.insert(result.end(), iv.begin(), iv.end());
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, 
                           masterKey_.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Failed to initialize encryption",
                              ErrorCode::CryptoEncryptionFailed);
    }
    
    std::vector<uint8_t> ciphertext(key.size() + 16);
    int len;
    
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, 
                          key.data(), key.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Failed to encrypt",
                              ErrorCode::CryptoEncryptionFailed);
    }
    
    int ciphertextLen = len;
    
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Failed to finalize encryption",
                              ErrorCode::CryptoEncryptionFailed);
    }
    
    ciphertextLen += len;
    ciphertext.resize(ciphertextLen);
    
    std::vector<uint8_t> tag(16);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Failed to get authentication tag",
                              ErrorCode::CryptoEncryptionFailed);
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    result.insert(result.end(), tag.begin(), tag.end());
    
    return result;
}

std::vector<uint8_t> SoftwareKeyProvider::unsealKey(const std::vector<uint8_t>& sealed) {
    if (sealed.size() < 2 + 16 + 16) {
        throw CryptoException("Invalid sealed key format",
                              ErrorCode::CryptoDecryptionFailed);
    }
    
    size_t offset = 2;
    std::vector<uint8_t> iv(sealed.begin() + offset, 
                            sealed.begin() + offset + 16);
    offset += 16;
    
    size_t ciphertextLen = sealed.size() - offset - 16;
    std::vector<uint8_t> ciphertext(sealed.begin() + offset,
                                     sealed.begin() + offset + ciphertextLen);
    offset += ciphertextLen;
    
    std::vector<uint8_t> tag(sealed.begin() + offset,
                             sealed.begin() + offset + 16);
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw CryptoException("Failed to create cipher context",
                              ErrorCode::CryptoDecryptionFailed);
    }
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                           masterKey_.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Failed to initialize decryption",
                              ErrorCode::CryptoDecryptionFailed);
    }
    
    std::vector<uint8_t> plaintext(ciphertextLen);
    int len;
    
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                          ciphertext.data(), ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Failed to decrypt",
                              ErrorCode::CryptoDecryptionFailed);
    }
    
    int plaintextLen = len;
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Failed to set authentication tag",
                              ErrorCode::CryptoTagVerificationFailed);
    }
    
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Authentication tag verification failed",
                              ErrorCode::CryptoTagVerificationFailed);
    }
    
    plaintextLen += len;
    plaintext.resize(plaintextLen);
    
    EVP_CIPHER_CTX_free(ctx);
    
    return plaintext;
}

bool SoftwareKeyProvider::isInitialized() const {
    return initialized_;
}

bool SoftwareKeyProvider::isSealed() const {
    return !authenticated_;
}

void SoftwareKeyProvider::deriveKeyFromPassword(const std::string& password,
                                                 const std::vector<uint8_t>& salt,
                                                 std::vector<uint8_t>& key) {
    key.resize(CryptoConstants::MASTER_KEY_LENGTH);
    
    PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                       salt.data(), salt.size(),
                       CryptoConstants::PBKDF2_ITERATIONS,
                       EVP_sha256(),
                       CryptoConstants::MASTER_KEY_LENGTH,
                       key.data());
}

void SoftwareKeyProvider::saveSealedKey() {
    std::vector<uint8_t> sealed = sealKey(masterKey_);
    
    std::ofstream file(keyPath_, std::ios::binary);
    if (!file.is_open()) {
        throw CryptoException("Failed to save sealed key",
                              ErrorCode::CryptoKeyDerivationFailed);
    }
    
    file.write(reinterpret_cast<const char*>(sealed.data()), sealed.size());
    file.close();
    
    // Set secure permissions
    chmod(keyPath_.c_str(), CryptoConstants::KEY_FILE_MODE);
}

void SoftwareKeyProvider::loadSealedKey() {
    std::ifstream file(keyPath_, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        throw CryptoException("Failed to load sealed key",
                              ErrorCode::CryptoKeyDerivationFailed);
    }
    
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<uint8_t> sealed(size);
    if (!file.read(reinterpret_cast<char*>(sealed.data()), size)) {
        throw CryptoException("Failed to read sealed key",
                              ErrorCode::CryptoKeyDerivationFailed);
    }
    
    masterKey_ = unsealKey(sealed);
}

// CryptoManager implementation

CryptoManager::CryptoManager(std::shared_ptr<IKeyProvider> keyProvider)
    : keyProvider_(keyProvider) {
    initializeKeys();
}

CryptoManager::~CryptoManager() {
    CryptoUtils::secureZero(fieldEncryptionKey_.data(), 
                           fieldEncryptionKey_.size());
    CryptoUtils::secureZero(hmacKey_.data(), hmacKey_.size());
    CryptoUtils::secureZero(cachedKey_.data(), cachedKey_.size());
}

void CryptoManager::initializeKeys() {
    std::vector<uint8_t> masterKey = keyProvider_->getMasterKey();
    
    // Derive field encryption key
    fieldEncryptionKey_ = deriveKey("field-encryption", masterKey);
    
    // Derive HMAC key
    hmacKey_ = deriveKey("hmac", masterKey);
    
    cachedKey_ = masterKey;
}

std::vector<uint8_t> CryptoManager::encrypt(const std::vector<uint8_t>& plaintext,
                                             const std::vector<uint8_t>& associatedData) {
    std::vector<uint8_t> nonce = generateNonce();
    std::vector<uint8_t> ciphertext;
    ciphertext.resize(plaintext.size() + POLY1305_TAG_LENGTH);
    std::vector<uint8_t> tag(POLY1305_TAG_LENGTH);
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw CryptoException("Failed to create cipher context",
                              ErrorCode::CryptoEncryptionFailed);
    }
    
    int len;
    int ciphertextLen;
    
    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr,
                           fieldEncryptionKey_.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Failed to initialize encryption",
                              ErrorCode::CryptoEncryptionFailed);
    }
    
    if (!associatedData.empty()) {
        if (EVP_EncryptUpdate(ctx, nullptr, &len, 
                              associatedData.data(), 
                              associatedData.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw CryptoException("Failed to set AAD",
                                  ErrorCode::CryptoEncryptionFailed);
        }
    }
    
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                          plaintext.data(), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Failed to encrypt",
                              ErrorCode::CryptoEncryptionFailed);
    }
    
    ciphertextLen = len;
    
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Failed to finalize encryption",
                              ErrorCode::CryptoEncryptionFailed);
    }
    
    ciphertextLen += len;
    ciphertext.resize(ciphertextLen);
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CHACHAPOLY_GET_TAG, 
                            POLY1305_TAG_LENGTH, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Failed to get tag",
                              ErrorCode::CryptoEncryptionFailed);
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    // Combine nonce, ciphertext, and tag
    std::vector<uint8_t> result;
    result.reserve(NONCE_SIZE + ciphertext.size() + POLY1305_TAG_LENGTH);
    result.insert(result.end(), nonce.begin(), nonce.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    result.insert(result.end(), tag.begin(), tag.end());
    
    return result;
}

std::vector<uint8_t> CryptoManager::decrypt(const std::vector<uint8_t>& ciphertext,
                                             const std::vector<uint8_t>& associatedData) {
    if (ciphertext.size() < NONCE_SIZE + POLY1305_TAG_LENGTH) {
        throw CryptoException("Invalid ciphertext format",
                              ErrorCode::CryptoDecryptionFailed);
    }
    
    std::vector<uint8_t> nonce(ciphertext.begin(), 
                               ciphertext.begin() + NONCE_SIZE);
    std::vector<uint8_t> tag(ciphertext.end() - POLY1305_TAG_LENGTH, 
                             ciphertext.end());
    std::vector<uint8_t> encrypted(ciphertext.begin() + NONCE_SIZE,
                                    ciphertext.end() - POLY1305_TAG_LENGTH);
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw CryptoException("Failed to create cipher context",
                              ErrorCode::CryptoDecryptionFailed);
    }
    
    int len;
    int plaintextLen;
    
    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr,
                           fieldEncryptionKey_.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Failed to initialize decryption",
                              ErrorCode::CryptoDecryptionFailed);
    }
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CHACHAPOLY_SET_TAG, 
                            POLY1305_TAG_LENGTH, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Failed to set tag",
                              ErrorCode::CryptoDecryptionFailed);
    }
    
    if (!associatedData.empty()) {
        if (EVP_DecryptUpdate(ctx, nullptr, &len,
                              associatedData.data(),
                              associatedData.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw CryptoException("Failed to set AAD",
                                  ErrorCode::CryptoDecryptionFailed);
        }
    }
    
    std::vector<uint8_t> plaintext(encrypted.size());
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                          encrypted.data(), encrypted.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Failed to decrypt",
                              ErrorCode::CryptoDecryptionFailed);
    }
    
    plaintextLen = len;
    
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    
    if (ret != 1) {
        throw CryptoException("Authentication tag verification failed",
                              ErrorCode::CryptoTagVerificationFailed);
    }
    
    plaintextLen += len;
    plaintext.resize(plaintextLen);
    
    return plaintext;
}

std::vector<uint8_t> CryptoManager::encryptField(const std::string& plaintext,
                                                  const std::string& keyPath) {
    std::vector<uint8_t> associatedData(keyPath.begin(), keyPath.end());
    std::vector<uint8_t> data(plaintext.begin(), plaintext.end());
    return encrypt(data, associatedData);
}

std::string CryptoManager::decryptField(const std::vector<uint8_t>& encrypted,
                                         const std::string& keyPath) {
    std::vector<uint8_t> associatedData(keyPath.begin(), keyPath.end());
    std::vector<uint8_t> decrypted = decrypt(encrypted, associatedData);
    return std::string(decrypted.begin(), decrypted.end());
}

std::vector<uint8_t> CryptoManager::deriveKey(const std::string& purpose,
                                               const std::vector<uint8_t>& salt) {
    std::vector<uint8_t> key(KEY_SIZE);
    
    HKDF(key.data(), KEY_SIZE,
         EVP_sha256(),
         cachedKey_.data(), cachedKey_.size(),
         nullptr, 0,
         reinterpret_cast<const uint8_t*>(purpose.data()), purpose.length(),
         salt.data(), salt.size());
    
    return key;
}

std::vector<uint8_t> CryptoManager::deriveKey(const std::string& purpose,
                                               const std::string& keyPath) {
    std::vector<uint8_t> salt(keyPath.begin(), keyPath.end());
    return deriveKey(purpose, salt);
}

std::vector<uint8_t> CryptoManager::hmac(const std::vector<uint8_t>& data,
                                          const std::vector<uint8_t>& key) {
    std::vector<uint8_t> mac(EVP_MAX_MD_SIZE);
    unsigned int macLen;
    
    HMAC(EVP_sha256(),
         key.data(), key.size(),
         data.data(), data.size(),
         mac.data(), &macLen);
    
    mac.resize(macLen);
    return mac;
}

bool CryptoManager::verifyHmac(const std::vector<uint8_t>& data,
                                const std::vector<uint8_t>& key,
                                const std::vector<uint8_t>& expectedMac) {
    std::vector<uint8_t> computedMac = hmac(data, key);
    return CryptoUtils::constantTimeCompare(computedMac, expectedMac);
}

std::vector<uint8_t> CryptoManager::sha256(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), hash.data());
    return hash;
}

std::vector<uint8_t> CryptoManager::sha512(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> hash(SHA512_DIGEST_LENGTH);
    SHA512(data.data(), data.size(), hash.data());
    return hash;
}

std::vector<uint8_t> CryptoManager::randomBytes(size_t length) {
    std::vector<uint8_t> result(length);
    if (RAND_bytes(result.data(), length) != 1) {
        throw CryptoException("Failed to generate random bytes",
                              ErrorCode::CryptoKeyDerivationFailed);
    }
    return result;
}

std::string CryptoManager::randomString(size_t length) {
    static const char charset[] = 
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789";
    
    std::vector<uint8_t> random = randomBytes(length);
    std::string result;
    result.reserve(length);
    
    for (size_t i = 0; i < length; ++i) {
        result += charset[random[i] % (sizeof(charset) - 1)];
    }
    
    return result;
}

std::vector<uint8_t> CryptoManager::getMasterKey() {
    return cachedKey_;
}

void CryptoManager::reEncrypt(const std::string& oldPassword,
                               const std::string& newPassword) {
    // This would require re-deriving all field encryption keys
    // and re-encrypting all data - complex operation
    throw std::runtime_error("Key rotation not yet implemented");
}

bool CryptoManager::isReady() const {
    return !fieldEncryptionKey_.empty() && !hmacKey_.empty();
}

std::string CryptoManager::getAlgorithm() const {
    return "XChaCha20-Poly1305";
}

std::vector<uint8_t> CryptoManager::generateNonce() {
    std::vector<uint8_t> nonce(NONCE_SIZE);
    
    // Use counter for first 8 bytes for uniqueness
    uint64_t counter = nonceCounter_++;
    std::memcpy(nonce.data(), &counter, sizeof(counter));
    
    // Fill rest with random bytes
    std::vector<uint8_t> random = randomBytes(NONCE_SIZE - sizeof(counter));
    std::memcpy(nonce.data() + sizeof(counter), random.data(), 
                NONCE_SIZE - sizeof(counter));
    
    return nonce;
}

// CryptoUtils implementation

bool CryptoUtils::constantTimeCompare(const std::vector<uint8_t>& a,
                                       const std::vector<uint8_t>& b) {
    if (a.size() != b.size()) {
        return false;
    }
    
    uint8_t result = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        result |= a[i] ^ b[i];
    }
    
    return result == 0;
}

void CryptoUtils::secureZero(void* ptr, size_t size) {
    volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
    while (size--) {
        *p++ = 0;
    }
}

std::vector<uint8_t> CryptoUtils::xorBuffers(const std::vector<uint8_t>& a,
                                              const std::vector<uint8_t>& b) {
    if (a.size() != b.size()) {
        throw std::invalid_argument("Buffer sizes must match");
    }
    
    std::vector<uint8_t> result(a.size());
    for (size_t i = 0; i < a.size(); ++i) {
        result[i] = a[i] ^ b[i];
    }
    
    return result;
}

} // namespace secreg
