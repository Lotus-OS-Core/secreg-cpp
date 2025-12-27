/**
 * @file errors.cpp
 * @brief Error handling implementation for SecReg-Linux
 * @author SecReg Security Team
 * @version 1.0.0
 */

#include "errors.h"
#include <iostream>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace secreg {

void DefaultErrorReporter::reportError(const SecRegException& e) {
    std::cerr << "[" << e.getErrorCategory() << "] Error " 
              << e.getErrorCode() << ": " << e.what() << std::endl;
}

void DefaultErrorReporter::reportError(const std::string& category, int code, 
                                        const std::string& message) {
    std::cerr << "[" << category << "] Error " << code 
              << ": " << message << std::endl;
}

std::string ErrorUtils::formatErrorMessage(const SecRegException& e) {
    std::ostringstream oss;
    oss << "[" << e.getErrorCategory() << "] Error " << e.getErrorCode() 
        << ": " << e.what();
    return oss.str();
}

std::string ErrorUtils::getErrorCodeName(ErrorCode code) {
    switch (code) {
        case ErrorCode::Success:
            return "SUCCESS";
        case ErrorCode::InvalidArgument:
            return "INVALID_ARGUMENT";
        case ErrorCode::OutOfMemory:
            return "OUT_OF_MEMORY";
        case ErrorCode::InvalidState:
            return "INVALID_STATE";
        case ErrorCode::NotImplemented:
            return "NOT_IMPLEMENTED";
        case ErrorCode::FileNotFound:
            return "FILE_NOT_FOUND";
        case ErrorCode::PermissionDenied:
            return "PERMISSION_DENIED";
        case ErrorCode::AuthFailed:
            return "AUTH_FAILED";
        case ErrorCode::AuthInvalidCredentials:
            return "AUTH_INVALID_CREDENTIALS";
        case ErrorCode::AuthUserNotFound:
            return "AUTH_USER_NOT_FOUND";
        case ErrorCode::AuthSessionExpired:
            return "AUTH_SESSION_EXPIRED";
        case ErrorCode::AuthSessionNotFound:
            return "AUTH_SESSION_NOT_FOUND";
        case ErrorCode::AuthMfaRequired:
            return "AUTH_MFA_REQUIRED";
        case ErrorCode::AuthRateLimited:
            return "AUTH_RATE_LIMITED";
        case ErrorCode::AuthAccountLocked:
            return "AUTH_ACCOUNT_LOCKED";
        case ErrorCode::AccessDenied:
            return "ACCESS_DENIED";
        case ErrorCode::AccessNoMatchingPermission:
            return "ACCESS_NO_MATCHING_PERMISSION";
        case ErrorCode::AccessConditionNotMet:
            return "ACCESS_CONDITION_NOT_MET";
        case ErrorCode::AccessInvalidKey:
            return "ACCESS_INVALID_KEY";
        case ErrorCode::AccessPathTraversal:
            return "ACCESS_PATH_TRAVERSAL";
        case ErrorCode::CryptoKeyDerivationFailed:
            return "CRYPTO_KEY_DERIVATION_FAILED";
        case ErrorCode::CryptoEncryptionFailed:
            return "CRYPTO_ENCRYPTION_FAILED";
        case ErrorCode::CryptoDecryptionFailed:
            return "CRYPTO_DECRYPTION_FAILED";
        case ErrorCode::CryptoInvalidKeyLength:
            return "CRYPTO_INVALID_KEY_LENGTH";
        case ErrorCode::CryptoTagVerificationFailed:
            return "CRYPTO_TAG_VERIFICATION_FAILED";
        case ErrorCode::CryptoTpmError:
            return "CRYPTO_TPM_ERROR";
        case ErrorCode::CryptoKeyNotInitialized:
            return "CRYPTO_KEY_NOT_INITIALIZED";
        case ErrorCode::StorageDatabaseError:
            return "STORAGE_DATABASE_ERROR";
        case ErrorCode::StorageKeyNotFound:
            return "STORAGE_KEY_NOT_FOUND";
        case ErrorCode::StorageTransactionFailed:
            return "STORAGE_TRANSACTION_FAILED";
        case ErrorCode::StorageSerializationError:
            return "STORAGE_SERIALIZATION_ERROR";
        case ErrorCode::StorageConcurrentModification:
            return "STORAGE_CONCURRENT_MODIFICATION";
        case ErrorCode::StorageCorrupted:
            return "STORAGE_CORRUPTED";
        case ErrorCode::AuditLoggingFailed:
            return "AUDIT_LOGGING_FAILED";
        case ErrorCode::AuditVerificationFailed:
            return "AUDIT_VERIFICATION_FAILED";
        case ErrorCode::AuditChainBroken:
            return "AUDIT_CHAIN_BROKEN";
        case ErrorCode::AuditLogTampered:
            return "AUDIT_LOG_TAMPERED";
        case ErrorCode::ConfigInvalid:
            return "CONFIG_INVALID";
        case ErrorCode::ConfigNotFound:
            return "CONFIG_NOT_FOUND";
        case ErrorCode::ConfigPermissionError:
            return "CONFIG_PERMISSION_ERROR";
        case ErrorCode::NetworkConnectionFailed:
            return "NETWORK_CONNECTION_FAILED";
        case ErrorCode::NetworkTimeout:
            return "NETWORK_TIMEOUT";
        case ErrorCode::NetworkTlsError:
            return "NETWORK_TLS_ERROR";
        default:
            return "UNKNOWN_ERROR";
    }
}

std::string ErrorUtils::getErrorCategoryName(ErrorCode code) {
    if (isAuthenticationError(code)) {
        return "Authentication";
    }
    if (isAuthorizationError(code)) {
        return "Authorization";
    }
    
    int code_int = static_cast<int>(code);
    if (code_int >= 300 && code_int < 400) {
        return "Cryptography";
    }
    if (code_int >= 400 && code_int < 500) {
        return "Storage";
    }
    if (code_int >= 500 && code_int < 600) {
        return "Audit";
    }
    if (code_int >= 600 && code_int < 700) {
        return "Configuration";
    }
    if (code_int >= 700 && code_int < 800) {
        return "Network";
    }
    
    return "General";
}

bool ErrorUtils::isAuthenticationError(ErrorCode code) {
    int code_int = static_cast<int>(code);
    return code_int >= 100 && code_int < 200;
}

bool ErrorUtils::isAuthorizationError(ErrorCode code) {
    int code_int = static_cast<int>(code);
    return code_int >= 200 && code_int < 300;
}

bool ErrorUtils::isRecoverableError(ErrorCode code) {
    // Some errors are recoverable (temporary), others are not
    switch (code) {
        case ErrorCode::OutOfMemory:
        case ErrorCode::StorageCorrupted:
        case ErrorCode::AuditLogTampered:
            return false;
        case ErrorCode::AuthRateLimited:
        case ErrorCode::NetworkTimeout:
        case ErrorCode::StorageConcurrentModification:
            return true;
        default:
            return true;
    }
}

} // namespace secreg
