/**
 * @file constants.h
 * @brief Constants for SecReg-Linux
 * @author SecReg Security Team
 * @version 1.0.0
 */

#ifndef SECREG_CONSTANTS_H
#define SECREG_CONSTANTS_H

#include <string>

namespace secreg {

/**
 * @brief Application constants
 */
struct AppConstants {
    static constexpr const char* APP_NAME = "SecReg-Linux";
    static constexpr const char* APP_VERSION = "1.0.0";
    static constexpr const char* APP_DESCRIPTION = "Secure Linux Registry System";
    static constexpr const char* APP_AUTHOR = "SecReg Security Team";
};

/**
 * @brief Path constants
 */
struct PathConstants {
    static constexpr const char* DEFAULT_DB_PATH = "/var/lib/secreg/db";
    static constexpr const char* DEFAULT_SOCKET_PATH = "/run/secreg/socket";
    static constexpr const char* DEFAULT_LOG_PATH = "/var/log/secreg/audit.log";
    static constexpr const char* DEFAULT_CONFIG_PATH = "/etc/secreg/config.toml";
    static constexpr const char* MASTER_KEY_PATH = "/var/lib/secreg/master.key";
    static constexpr const char* SOCKET_DIR = "/run/secreg";
    static constexpr const char* LOG_DIR = "/var/log/secreg";
    static constexpr const char* DB_DIR = "/var/lib/secreg";
};

/**
 * @brief Cryptographic constants
 */
struct CryptoConstants {
    // Key derivation
    static constexpr uint32_t PBKDF2_ITERATIONS = 100000;
    static constexpr size_t SALT_LENGTH = 32;
    static constexpr size_t MASTER_KEY_LENGTH = 32;
    
    // Encryption
    static constexpr size_t XCHACHA_NONCE_LENGTH = 24;
    static constexpr size_t POLY1305_TAG_LENGTH = 16;
    static constexpr size_t AES_KEY_LENGTH = 32;
    static constexpr size_t AES_IV_LENGTH = 16;
    
    // Hashing
    static constexpr size_t SHA256_DIGEST_LENGTH = 32;
    static constexpr size_t SHA512_DIGEST_LENGTH = 64;
    
    // HMAC
    static constexpr size_t HMAC_KEY_LENGTH = 32;
    
    // Session tokens
    static constexpr size_t SESSION_TOKEN_LENGTH = 32;
    static constexpr uint64_t DEFAULT_SESSION_TIMEOUT = 3600;  // 1 hour
    static constexpr uint64_t REFRESH_TOKEN_TIMEOUT = 86400;   // 24 hours
    
    // Rate limiting
    static constexpr uint32_t MAX_AUTH_ATTEMPTS = 5;
    static constexpr uint64_t RATE_LIMIT_WINDOW = 300;  // 5 minutes
};

/**
 * @brief Database constants
 */
struct DbConstants {
    static constexpr const char* DB_FILENAME = "registry.db";
    static constexpr const char* ENTRIES_TABLE = "entries";
    static constexpr const char* AUDIT_TABLE = "audit";
    static constexpr const char* ACL_TABLE = "acl";
    static constexpr const char* METADATA_TABLE = "metadata";
    
    // Schema version for migrations
    static constexpr uint32_t SCHEMA_VERSION = 1;
    
    // Limits
    static constexpr size_t MAX_KEY_LENGTH = 512;
    static constexpr size_t MAX_VALUE_SIZE = 1024 * 1024;  // 1MB
    static constexpr size_t MAX_STRING_VALUE_SIZE = 65536; // 64KB
};

/**
 * @brief Session constants
 */
struct SessionConstants {
    static constexpr uint64_t MAX_SESSIONS_PER_USER = 5;
    static constexpr uint64_t SESSION_CLEANUP_INTERVAL = 300;  // 5 minutes
    static constexpr uint64_t ACTIVITY_TIMEOUT = 300;  // 5 minutes of inactivity
};

/**
 * @brief Audit constants
 */
struct AuditConstants {
    // Retention
    static constexpr uint64_t DEFAULT_RETENTION_DAYS = 90;
    static constexpr uint64_t MAX_RETENTION_DAYS = 365;
    static constexpr uint64_t MAX_AUDIT_LOG_SIZE = 100 * 1024 * 1024;  // 100MB
    
    // Chain verification
    static constexpr size_t CHAIN_VERIFICATION_BATCH_SIZE = 1000;
    
    // Log levels
    static constexpr const char* LOG_LEVEL_DEBUG = "debug";
    static constexpr const char* LOG_LEVEL_INFO = "info";
    static constexpr const char* LOG_LEVEL_WARNING = "warning";
    static constexpr const char* LOG_LEVEL_ERROR = "error";
};

/**
 * @brief Network constants
 */
struct NetworkConstants {
    static constexpr uint16_t DEFAULT_PORT = 8443;
    static constexpr uint32_t DEFAULT_BACKLOG = 128;
    static constexpr uint32_t MAX_CONNECTIONS = 1000;
    static constexpr uint64_t CONNECTION_TIMEOUT = 30000;  // 30 seconds
    static constexpr uint64_t READ_TIMEOUT = 10000;        // 10 seconds
    static constexpr uint64_t WRITE_TIMEOUT = 10000;       // 10 seconds
    
    // TLS
    static constexpr const char* DEFAULT_TLS_VERSION = "TLSv1.3";
    static constexpr const char* DEFAULT_CIPHERS = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256";
};

/**
 * @brief CLI constants
 */
struct CliConstants {
    static constexpr const char* PROG_NAME = "sreg";
    static constexpr const char* VERSION_STRING = "1.0.0";
    static constexpr size_t MAX_PASSWORD_LENGTH = 256;
    static constexpr size_t CONFIRM_TIMEOUT = 30;  // seconds
};

/**
 * @brief Security constants
 */
struct SecurityConstants {
    // Password policy
    static constexpr uint32_t MIN_PASSWORD_LENGTH = 12;
    static constexpr uint32_t MAX_PASSWORD_LENGTH = 128;
    static constexpr bool REQUIRE_UPPERCASE = true;
    static constexpr bool REQUIRE_LOWERCASE = true;
    static constexpr bool REQUIRE_DIGIT = true;
    static constexpr bool REQUIRE_SPECIAL = true;
    
    // File permissions
    static constexpr mode_t DB_FILE_MODE = 0600;
    static constexpr mode_t KEY_FILE_MODE = 0600;
    static constexpr mode_t SOCKET_MODE = 0666;
    static constexpr mode_t LOG_FILE_MODE = 0600;
    
    // Process
    static constexpr bool DROP_PRIVILEGES = true;
    static constexpr const char* DEFAULT_USER = "root";
    static constexpr const char* DEFAULT_GROUP = "wheel";
};

} // namespace secreg

#endif // SECREG_CONSTANTS_H
