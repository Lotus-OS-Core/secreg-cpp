/**
 * @file auth.h
 * @brief Authentication for SecReg-Linux
 * @author SecReg Security Team
 * @version 1.0.0
 */

#ifndef SECREG_AUTH_H
#define SECREG_AUTH_H

#include "types.h"
#include <string>
#include <memory>
#include <functional>
#include <unordered_map>
#include <shared_mutex>

namespace secreg {

/**
 * @brief Authentication result
 */
struct AuthResult {
    bool success;
    std::string sessionId;
    std::string errorMessage;
    std::vector<std::string> roles;
    bool mfaRequired = false;
};

/**
 * @brief Rate limiter configuration
 */
struct RateLimitConfig {
    uint32_t maxAttempts = CryptoConstants::MAX_AUTH_ATTEMPTS;
    uint64_t windowSeconds = CryptoConstants::RATE_LIMIT_WINDOW;
    uint64_t lockoutDuration = 300; // 5 minutes
};

/**
 * @brief Authentication provider interface
 */
class IAuthProvider {
public:
    virtual ~IAuthProvider() = default;
    virtual AuthResult authenticate(const std::string& username,
                                    const std::string& password,
                                    const std::string& remoteAddress) = 0;
    virtual bool validateSession(const std::string& sessionId) = 0;
    virtual bool refreshSession(const std::string& sessionId) = 0;
    virtual bool revokeSession(const std::string& sessionId) = 0;
};

/**
 * @brief PAM-based authentication provider
 */
class PamAuthProvider : public IAuthProvider {
public:
    explicit PamAuthProvider(const std::string& serviceName);
    ~PamAuthProvider() override;
    
    AuthResult authenticate(const std::string& username,
                           const std::string& password,
                           const std::string& remoteAddress) override;
    bool validateSession(const std::string& sessionId) override;
    bool refreshSession(const std::string& sessionId) override;
    bool revokeSession(const std::string& sessionId) override;

private:
    std::string serviceName_;
};

/**
 * @brief Simple file-based authentication provider (for testing)
 */
class SimpleAuthProvider : public IAuthProvider {
public:
    explicit SimpleAuthProvider(const std::string& userFilePath);
    
    AuthResult authenticate(const std::string& username,
                           const std::string& password,
                           const std::string& remoteAddress) override;
    bool validateSession(const std::string& sessionId) override;
    bool refreshSession(const std::string& sessionId) override;
    bool revokeSession(const std::string& sessionId) override;

private:
    std::string userFilePath_;
    
    bool verifyPassword(const std::string& username, 
                        const std::string& password);
};

/**
 * @brief Session manager
 */
class SessionManager {
public:
    explicit SessionManager(uint64_t sessionTimeout);
    ~SessionManager();
    
    std::string createSession(const Session& session);
    std::optional<Session> getSession(const std::string& sessionId);
    bool validateSession(const std::string& sessionId);
    bool refreshSession(const std::string& sessionId);
    void revokeSession(const std::string& sessionId);
    void revokeAllUserSessions(uint32_t userId);
    void cleanupExpiredSessions();
    size_t getActiveSessionCount() const;
    size_t getUserSessionCount(uint32_t userId) const;

private:
    uint64_t sessionTimeout_;
    std::unordered_map<std::string, Session> sessions_;
    mutable std::shared_mutex mutex_;
};

/**
 * @brief Rate limiter
 */
class RateLimiter {
public:
    explicit RateLimiter(const RateLimitConfig& config);
    
    bool check(const std::string& key);
    void recordAttempt(const std::string& key);
    bool isLockedOut(const std::string& key);
    void reset(const std::string& key);

private:
    RateLimitConfig config_;
    std::unordered_map<std::string, std::vector<uint64_t>> attempts_;
    mutable std::shared_mutex mutex_;
};

/**
 * @brief Authentication manager
 */
class AuthManager {
public:
    explicit AuthManager(std::shared_ptr<IAuthProvider> authProvider,
                        uint64_t sessionTimeout);
    ~AuthManager();
    
    AuthResult login(const std::string& username,
                     const std::string& password,
                     const std::string& remoteAddress);
    bool logout(const std::string& sessionId);
    std::optional<Session> getSession(const std::string& sessionId);
    bool isValidSession(const std::string& sessionId);
    
    void setRateLimiter(std::shared_ptr<RateLimiter> rateLimiter);
    void setMaxSessionsPerUser(size_t max);

private:
    std::shared_ptr<IAuthProvider> authProvider_;
    std::shared_ptr<RateLimiter> rateLimiter_;
    std::unique_ptr<SessionManager> sessionManager_;
    size_t maxSessionsPerUser_ = SessionConstants::MAX_SESSIONS_PER_USER;
};

} // namespace secreg

#endif // SECREG_AUTH_H
