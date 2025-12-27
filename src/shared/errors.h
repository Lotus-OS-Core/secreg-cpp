/**
 * @file errors.h
 * @brief Error handling for SecReg-Linux
 * @author SecReg Security Team
 * @version 1.0.0
 */

#ifndef SECREG_ERRORS_H
#define SECREG_ERRORS_H

#include <stdexcept>
#include <string>
#include <optional>

namespace secreg {

/**
 * @brief Base exception class for all SecReg errors
 */
class SecRegException : public std::runtime_error {
public:
    explicit SecRegException(const std::string& message) 
        : std::runtime_error(message) {}
    
    virtual ~SecRegException() = default;
    virtual int getErrorCode() const = 0;
    virtual std::string getErrorCategory() const = 0;
};

/**
 * @brief Error codes enumeration
 */
enum class ErrorCode {
    // Success (not an error)
    Success = 0,
    
    // General errors (1-99)
    InvalidArgument = 1,
    OutOfMemory = 2,
    InvalidState = 3,
    NotImplemented = 4,
    FileNotFound = 5,
    PermissionDenied = 6,
    
    // Authentication errors (100-199)
    AuthFailed = 100,
    AuthInvalidCredentials = 101,
    AuthUserNotFound = 102,
    AuthSessionExpired = 103,
    AuthSessionNotFound = 104,
    AuthMfaRequired = 105,
    AuthRateLimited = 106,
    AuthAccountLocked = 107,
    
    // Authorization errors (200-299)
    AccessDenied = 200,
    AccessNoMatchingPermission = 201,
    AccessConditionNotMet = 202,
    AccessInvalidKey = 203,
    AccessPathTraversal = 204,
    
    // Cryptography errors (300-399)
    CryptoKeyDerivationFailed = 300,
    CryptoEncryptionFailed = 301,
    CryptoDecryptionFailed = 302,
    CryptoInvalidKeyLength = 303,
    CryptoTagVerificationFailed = 304,
    CryptoTpmError = 305,
    CryptoKeyNotInitialized = 306,
    
    // Storage errors (400-499)
    StorageDatabaseError = 400,
    StorageKeyNotFound = 401,
    StorageTransactionFailed = 402,
    StorageSerializationError = 403,
    StorageConcurrentModification = 404,
    StorageCorrupted = 405,
    
    // Audit errors (500-599)
    AuditLoggingFailed = 500,
    AuditVerificationFailed = 501,
    AuditChainBroken = 502,
    AuditLogTampered = 503,
    
    // Configuration errors (600-699)
    ConfigInvalid = 600,
    ConfigNotFound = 601,
    ConfigPermissionError = 602,
    
    // Network errors (700-799)
    NetworkConnectionFailed = 700,
    NetworkTimeout = 701,
    NetworkTlsError = 702,
};

/**
 * @brief General exception class
 */
class GeneralException : public SecRegException {
public:
    explicit GeneralException(const std::string& message, ErrorCode code = ErrorCode::InvalidArgument)
        : SecRegException(message), error_code_(code) {}
    
    int getErrorCode() const override { return static_cast<int>(error_code_); }
    std::string getErrorCategory() const override { return "General"; }

private:
    ErrorCode error_code_;
};

/**
 * @brief Authentication exception
 */
class AuthException : public SecRegException {
public:
    explicit AuthException(const std::string& message, ErrorCode code = ErrorCode::AuthFailed)
        : SecRegException(message), error_code_(code) {}
    
    int getErrorCode() const override { return static_cast<int>(error_code_); }
    std::string getErrorCategory() const override { return "Authentication"; }

private:
    ErrorCode error_code_;
};

/**
 * @brief Authorization exception
 */
class AccessException : public SecRegException {
public:
    explicit AccessException(const std::string& message, ErrorCode code = ErrorCode::AccessDenied)
        : SecRegException(message), error_code_(code) {}
    
    int getErrorCode() const override { return static_cast<int>(error_code_); }
    std::string getErrorCategory() const override { return "Authorization"; }

private:
    ErrorCode error_code_;
};

/**
 * @brief Cryptography exception
 */
class CryptoException : public SecRegException {
public:
    explicit CryptoException(const std::string& message, ErrorCode code = ErrorCode::CryptoEncryptionFailed)
        : SecRegException(message), error_code_(code) {}
    
    int getErrorCode() const override { return static_cast<int>(error_code_); }
    std::string getErrorCategory() const override { return "Cryptography"; }

private:
    ErrorCode error_code_;
};

/**
 * @brief Storage exception
 */
class StorageException : public SecRegException {
public:
    explicit StorageException(const std::string& message, ErrorCode code = ErrorCode::StorageDatabaseError)
        : SecRegException(message), error_code_(code) {}
    
    int getErrorCode() const override { return static_cast<int>(error_code_); }
    std::string getErrorCategory() const override { return "Storage"; }

private:
    ErrorCode error_code_;
};

/**
 * @brief Audit exception
 */
class AuditException : public SecRegException {
public:
    explicit AuditException(const std::string& message, ErrorCode code = ErrorCode::AuditLoggingFailed)
        : SecRegException(message), error_code_(code) {}
    
    int getErrorCode() const override { return static_cast<int>(error_code_); }
    std::string getErrorCategory() const override { return "Audit"; }

private:
    ErrorCode error_code_;
};

/**
 * @brief Configuration exception
 */
class ConfigException : public SecRegException {
public:
    explicit ConfigException(const std::string& message, ErrorCode code = ErrorCode::ConfigInvalid)
        : SecRegException(message), error_code_(code) {}
    
    int getErrorCode() const override { return static_cast<int>(error_code_); }
    std::string getErrorCategory() const override { return "Configuration"; }

private:
    ErrorCode error_code_;
};

/**
 * @brief Error reporter interface
 */
class IErrorReporter {
public:
    virtual ~IErrorReporter() = default;
    virtual void reportError(const SecRegException& e) = 0;
    virtual void reportError(const std::string& category, int code, const std::string& message) = 0;
};

/**
 * @brief Default error reporter that logs to stderr
 */
class DefaultErrorReporter : public IErrorReporter {
public:
    void reportError(const SecRegException& e) override;
    void reportError(const std::string& category, int code, const std::string& message) override;
};

/**
 * @brief Error utilities
 */
struct ErrorUtils {
    static std::string formatErrorMessage(const SecRegException& e);
    static std::string getErrorCodeName(ErrorCode code);
    static std::string getErrorCategoryName(ErrorCode code);
    static bool isAuthenticationError(ErrorCode code);
    static bool isAuthorizationError(ErrorCode code);
    static bool isRecoverableError(ErrorCode code);
};

} // namespace secreg

#endif // SECREG_ERRORS_H
