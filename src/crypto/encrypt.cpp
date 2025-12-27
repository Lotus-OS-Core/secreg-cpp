/**
 * @file encrypt.cpp
 * @brief Encryption utilities implementation for SecReg-Linux
 * @author SecReg Security Team
 * @version 1.0.0
 */

#include "encrypt.h"
#include "constants.h"
#include "utils.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <regex>
#include <iostream>

namespace secreg {

// XChaCha20Poly1305Encryptor implementation

XChaCha20Poly1305Encryptor::XChaCha20Poly1305Encryptor(const std::vector<uint8_t>& key) {
    if (key.size() != 32) {
        throw std::invalid_argument("XChaCha20-Poly1305 requires 32-byte key");
    }
    key_ = key;
}

std::vector<uint8_t> XChaCha20Poly1305Encryptor::encrypt(
    const std::vector<uint8_t>& plaintext) {
    
    std::vector<uint8_t> nonce = generateNonce();
    std::vector<uint8_t> ciphertext;
    ciphertext.resize(plaintext.size() + 16);
    std::vector<uint8_t> tag(16);
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context");
    }
    
    int len;
    int ciphertextLen;
    
    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr,
                           key_.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize encryption");
    }
    
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                          plaintext.data(), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to encrypt");
    }
    
    ciphertextLen = len;
    
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize encryption");
    }
    
    ciphertextLen += len;
    ciphertext.resize(ciphertextLen);
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CHACHAPOLY_GET_TAG, 16, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to get authentication tag");
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    // Combine nonce, ciphertext, and tag
    std::vector<uint8_t> result;
    result.reserve(24 + ciphertext.size() + 16);
    result.insert(result.end(), nonce.begin(), nonce.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    result.insert(result.end(), tag.begin(), tag.end());
    
    return result;
}

std::vector<uint8_t> XChaCha20Poly1305Encryptor::decrypt(
    const std::vector<uint8_t>& ciphertext) {
    
    if (ciphertext.size() < 24 + 16) {
        throw std::runtime_error("Invalid ciphertext format");
    }
    
    std::vector<uint8_t> nonce(ciphertext.begin(), ciphertext.begin() + 24);
    std::vector<uint8_t> tag(ciphertext.end() - 16, ciphertext.end());
    std::vector<uint8_t> encrypted(ciphertext.begin() + 24,
                                    ciphertext.end() - 16);
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context");
    }
    
    int len;
    int plaintextLen;
    
    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr,
                           key_.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize decryption");
    }
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CHACHAPOLY_SET_TAG, 16, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to set authentication tag");
    }
    
    std::vector<uint8_t> plaintext(encrypted.size());
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                          encrypted.data(), encrypted.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to decrypt");
    }
    
    plaintextLen = len;
    
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    
    if (ret != 1) {
        throw std::runtime_error("Authentication tag verification failed");
    }
    
    plaintextLen += len;
    plaintext.resize(plaintextLen);
    
    return plaintext;
}

std::string XChaCha20Poly1305Encryptor::getAlgorithmName() const {
    return "XChaCha20-Poly1305";
}

size_t XChaCha20Poly1305Encryptor::getKeySize() const {
    return 32;
}

size_t XChaCha20Poly1305Encryptor::getNonceSize() const {
    return 24;
}

std::vector<uint8_t> XChaCha20Poly1305Encryptor::generateNonce() {
    std::vector<uint8_t> nonce(24);
    
    // Use counter for first 8 bytes
    uint64_t counter = nonce_counter_++;
    std::memcpy(nonce.data(), &counter, sizeof(counter));
    
    // Fill rest with random bytes
    std::vector<uint8_t> random = generateRandomBytes(16);
    std::memcpy(nonce.data() + sizeof(counter), random.data(), 16);
    
    return nonce;
}

// AES256GCMEncryptor implementation

AES256GCMEncryptor::AES256GCMEncryptor(const std::vector<uint8_t>& key) {
    if (key.size() != 32) {
        throw std::invalid_argument("AES-256-GCM requires 32-byte key");
    }
    key_ = key;
}

std::vector<uint8_t> AES256GCMEncryptor::encrypt(
    const std::vector<uint8_t>& plaintext) {
    
    std::vector<uint8_t> iv = generateRandomBytes(IV_SIZE);
    std::vector<uint8_t> ciphertext;
    ciphertext.resize(plaintext.size() + TAG_SIZE);
    std::vector<uint8_t> tag(TAG_SIZE);
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context");
    }
    
    int len;
    int ciphertextLen;
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                           key_.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize encryption");
    }
    
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                          plaintext.data(), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to encrypt");
    }
    
    ciphertextLen = len;
    
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize encryption");
    }
    
    ciphertextLen += len;
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to get authentication tag");
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    // Combine IV, ciphertext, and tag
    std::vector<uint8_t> result;
    result.reserve(IV_SIZE + ciphertextLen + TAG_SIZE);
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.begin() + ciphertextLen);
    result.insert(result.end(), tag.begin(), tag.end());
    
    return result;
}

std::vector<uint8_t> AES256GCMEncryptor::decrypt(
    const std::vector<uint8_t>& ciphertext) {
    
    if (ciphertext.size() < IV_SIZE + TAG_SIZE) {
        throw std::runtime_error("Invalid ciphertext format");
    }
    
    std::vector<uint8_t> iv(ciphertext.begin(), ciphertext.begin() + IV_SIZE);
    std::vector<uint8_t> tag(ciphertext.end() - TAG_SIZE, ciphertext.end());
    std::vector<uint8_t> encrypted(ciphertext.begin() + IV_SIZE,
                                    ciphertext.end() - TAG_SIZE);
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context");
    }
    
    int len;
    int plaintextLen;
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                           key_.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize decryption");
    }
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to set authentication tag");
    }
    
    std::vector<uint8_t> plaintext(encrypted.size());
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                          encrypted.data(), encrypted.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to decrypt");
    }
    
    plaintextLen = len;
    
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    
    if (ret != 1) {
        throw std::runtime_error("Authentication tag verification failed");
    }
    
    plaintextLen += len;
    plaintext.resize(plaintextLen);
    
    return plaintext;
}

std::string AES256GCMEncryptor::getAlgorithmName() const {
    return "AES-256-GCM";
}

size_t AES256GCMEncryptor::getKeySize() const {
    return 32;
}

size_t AES256GCMEncryptor::getNonceSize() const {
    return IV_SIZE;
}

// EncryptorFactory implementation

std::unique_ptr<IEncryptor> EncryptorFactory::createXChaCha20(
    const std::vector<uint8_t>& key) {
    return std::make_unique<XChaCha20Poly1305Encryptor>(key);
}

std::unique_ptr<IEncryptor> EncryptorFactory::createAES256GCM(
    const std::vector<uint8_t>& key) {
    return std::make_unique<AES256GCMEncryptor>(key);
}

std::unique_ptr<IEncryptor> EncryptorFactory::create(const std::string& algorithm,
                                                      const std::vector<uint8_t>& key) {
    if (algorithm == "XChaCha20-Poly1305" || algorithm == "xchacha20") {
        return createXChaCha20(key);
    } else if (algorithm == "AES-256-GCM" || algorithm == "aes256") {
        return createAES256GCM(key);
    } else {
        throw std::invalid_argument("Unknown encryption algorithm: " + algorithm);
    }
}

// KeyDerivation implementation

std::vector<uint8_t> KeyDerivation::pbkdf2(const std::string& password,
                                            const std::vector<uint8_t>& salt,
                                            uint32_t iterations,
                                            size_t keyLength) {
    std::vector<uint8_t> key(keyLength);
    
    PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                       salt.data(), salt.size(),
                       iterations,
                       EVP_sha256(),
                       keyLength,
                       key.data());
    
    return key;
}

std::vector<uint8_t> KeyDerivation::hkdf(const std::vector<uint8_t>& ikm,
                                          const std::vector<uint8_t>& salt,
                                          const std::vector<uint8_t>& info,
                                          size_t keyLength) {
    std::vector<uint8_t> key(keyLength);
    
    HKDF(key.data(), keyLength,
         EVP_sha256(),
         ikm.data(), ikm.size(),
         salt.data(), salt.size(),
         info.data(), info.size());
    
    return key;
}

std::vector<uint8_t> KeyDerivation::scrypt(const std::string& password,
                                            const std::vector<uint8_t>& salt,
                                            uint64_t N,
                                            uint32_t r,
                                            uint32_t p,
                                            size_t keyLength) {
    std::vector<uint8_t> key(keyLength);
    
    // OpenSSL 1.1.1+ supports EVP_PBE_scrypt
    // For older versions, we'd need to use a different approach
    if (EVP_PBE_scrypt(password.c_str(), password.length(),
                       salt.data(), salt.size(),
                       N, r, p, 0,
                       key.data(), keyLength) != 1) {
        throw std::runtime_error("Scrypt key derivation failed");
    }
    
    return key;
}

// PasswordUtils implementation

bool PasswordUtils::validatePassword(const std::string& password) {
    if (password.length() < SecurityConstants::MIN_PASSWORD_LENGTH) {
        return false;
    }
    
    if (password.length() > SecurityConstants::MAX_PASSWORD_LENGTH) {
        return false;
    }
    
    bool hasUpper = false, hasLower = false, hasDigit = false, hasSpecial = false;
    
    for (char c : password) {
        if (std::isupper(c)) hasUpper = true;
        else if (std::islower(c)) hasLower = true;
        else if (std::isdigit(c)) hasDigit = true;
        else if (std::ispunct(c)) hasSpecial = true;
    }
    
    if (SecurityConstants::REQUIRE_UPPERCASE && !hasUpper) return false;
    if (SecurityConstants::REQUIRE_LOWERCASE && !hasLower) return false;
    if (SecurityConstants::REQUIRE_DIGIT && !hasDigit) return false;
    if (SecurityConstants::REQUIRE_SPECIAL && !hasSpecial) return false;
    
    // Check for common weak passwords
    static const std::vector<std::string> commonPasswords = {
        "password", "123456", "qwerty", "admin", "letmein"
    };
    
    std::string lower = toLower(password);
    for (const auto& common : commonPasswords) {
        if (lower == common || lower.find(common) != std::string::npos) {
            return false;
        }
    }
    
    return true;
}

std::string PasswordUtils::generatePassword(size_t length) {
    static const char uppercase[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    static const char lowercase[] = "abcdefghijklmnopqrstuvwxyz";
    static const char digits[] = "0123456789";
    static const char special[] = "!@#$%^&*()_+-=[]{}|;:,.<>?";
    
    std::string password;
    std::vector<uint8_t> random = generateRandomBytes(length * 2);
    
    // Ensure at least one of each required character type
    password += uppercase[random[0] % sizeof(uppercase)];
    password += lowercase[random[1] % sizeof(lowercase)];
    password += digits[random[2] % sizeof(digits)];
    password += special[random[3] % sizeof(special)];
    
    // Fill the rest
    static const char all[] = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789"
        "!@#$%^&*()_+-=[]{}|;:,.<>?";
    
    for (size_t i = 4; i < length; ++i) {
        password += all[random[i + 4] % (sizeof(all) - 1)];
    }
    
    // Shuffle
    std::shuffle(password.begin(), password.end(),
                 std::default_random_engine(random[0]));
    
    return password;
}

uint32_t PasswordUtils::estimateEntropy(const std::string& password) {
    uint32_t poolSize = 0;
    
    for (char c : password) {
        if (std::isupper(c)) { poolSize += 26; break; }
    }
    for (char c : password) {
        if (std::islower(c)) { poolSize += 26; break; }
    }
    for (char c : password) {
        if (std::isdigit(c)) { poolSize += 10; break; }
    }
    for (char c : password) {
        if (std::ispunct(c)) { poolSize += 32; break; }
    }
    
    if (poolSize == 0) return 0;
    
    // Entropy = log2(poolSize^length) = length * log2(poolSize)
    double entropy = password.length() * std::log2(poolSize);
    
    // Reduce for patterns
    std::regex repeated(R"(.)\1{2,}");
    if (std::regex_search(password, repeated)) {
        entropy *= 0.8;
    }
    
    return static_cast<uint32_t>(entropy);
}

std::string PasswordUtils::getPasswordStrengthFeedback(const std::string& password) {
    std::vector<std::string> feedback;
    
    if (password.length() < 8) {
        feedback.push_back("Password is too short");
    }
    if (password.length() < 12) {
        feedback.push_back("Consider using a longer password");
    }
    
    bool hasUpper = false, hasLower = false, hasDigit = false, hasSpecial = false;
    for (char c : password) {
        if (std::isupper(c)) hasUpper = true;
        else if (std::islower(c)) hasLower = true;
        else if (std::isdigit(c)) hasDigit = true;
        else if (std::ispunct(c)) hasSpecial = true;
    }
    
    if (!hasUpper) feedback.push_back("Add uppercase letters");
    if (!hasLower) feedback.push_back("Add lowercase letters");
    if (!hasDigit) feedback.push_back("Add numbers");
    if (!hasSpecial) feedback.push_back("Add special characters");
    
    uint32_t entropy = estimateEntropy(password);
    if (entropy < 40) {
        feedback.push_back("Password is very weak");
    } else if (entropy < 60) {
        feedback.push_back("Password is weak");
    } else if (entropy < 80) {
        feedback.push_back("Password is moderate");
    } else {
        feedback.push_back("Password is strong");
    }
    
    return join(feedback, "; ");
}

} // namespace secreg
