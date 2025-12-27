/**
 * @file encrypt.h
 * @brief Encryption utilities for SecReg-Linux
 * @author SecReg Security Team
 * @version 1.0.0
 */

#ifndef SECREG_ENCRYPT_H
#define SECREG_ENCRYPT_H

#include <string>
#include <vector>
#include <cstdint>

namespace secreg {

/**
 * @brief Encryption interface
 */
class IEncryptor {
public:
    virtual ~IEncryptor() = default;
    virtual std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext) = 0;
    virtual std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext) = 0;
    virtual std::string getAlgorithmName() const = 0;
    virtual size_t getKeySize() const = 0;
    virtual size_t getNonceSize() const = 0;
};

/**
 * @brief XChaCha20-Poly1305 encryptor
 */
class XChaCha20Poly1305Encryptor : public IEncryptor {
public:
    explicit XChaCha20Poly1305Encryptor(const std::vector<uint8_t>& key);
    
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext) override;
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext) override;
    std::string getAlgorithmName() const override;
    size_t getKeySize() const override;
    size_t getNonceSize() const override;

private:
    std::vector<uint8_t> key_;
    uint64_t nonce_counter_ = 0;
    
    std::vector<uint8_t> generateNonce();
};

/**
 * @brief AES-256-GCM encryptor
 */
class AES256GCMEncryptor : public IEncryptor {
public:
    explicit AES256GCMEncryptor(const std::vector<uint8_t>& key);
    
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext) override;
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext) override;
    std::string getAlgorithmName() const override;
    size_t getKeySize() const override;
    size_t getNonceSize() const override;

private:
    std::vector<uint8_t> key_;
    
    static constexpr size_t IV_SIZE = 12;
    static constexpr size_t TAG_SIZE = 16;
};

/**
 * @brief Encryptor factory
 */
class EncryptorFactory {
public:
    static std::unique_ptr<IEncryptor> createXChaCha20(const std::vector<uint8_t>& key);
    static std::unique_ptr<IEncryptor> createAES256GCM(const std::vector<uint8_t>& key);
    static std::unique_ptr<IEncryptor> create(const std::string& algorithm, 
                                               const std::vector<uint8_t>& key);
};

/**
 * @brief Key derivation utilities
 */
struct KeyDerivation {
    static std::vector<uint8_t> pbkdf2(const std::string& password,
                                        const std::vector<uint8_t>& salt,
                                        uint32_t iterations,
                                        size_t keyLength);
    
    static std::vector<uint8_t> hkdf(const std::vector<uint8_t>& ikm,
                                      const std::vector<uint8_t>& salt,
                                      const std::vector<uint8_t>& info,
                                      size_t keyLength);
    
    static std::vector<uint8_t> scrypt(const std::string& password,
                                        const std::vector<uint8_t>& salt,
                                        uint64_t N,
                                        uint32_t r,
                                        uint32_t p,
                                        size_t keyLength);
};

/**
 * @brief Password utilities
 */
struct PasswordUtils {
    static bool validatePassword(const std::string& password);
    static std::string generatePassword(size_t length = 16);
    static uint32_t estimateEntropy(const std::string& password);
    static std::string getPasswordStrengthFeedback(const std::string& password);
};

} // namespace secreg

#endif // SECREG_ENCRYPT_H
