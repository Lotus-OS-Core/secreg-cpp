/**
 * @file auth.cpp
 * @brief Authentication implementation for SecReg-Linux
 * @author SecReg Security Team
 * @version 1.0.0
 */

#include "auth.h"
#include "constants.h"
#include "utils.h"
#include <pwd.h>
#include <shadow.h>
#include <unistd.h>
#include <sys/time.h>

namespace secreg {

// SessionManager implementation

SessionManager::SessionManager(uint64_t sessionTimeout)
    : sessionTimeout_(sessionTimeout) {}

SessionManager::~SessionManager() {
    sessions_.clear();
}

std::string SessionManager::createSession(const Session& session) {
    std::string sessionId = generateUuid();
    
    std::unique_lock lock(mutex_);
    
    // Check if user has too many sessions
    size_t userSessions = getUserSessionCount(session.user_id);
    if (userSessions >= SessionConstants::MAX_SESSIONS_PER_USER) {
        // Revoke oldest session for this user
        for (auto it = sessions_.begin(); it != sessions_.end(); ) {
            if (it->second.user_id == session.user_id) {
                it = sessions_.erase(it);
                break;
            } else {
                ++it;
            }
        }
    }
    
    Session sessionCopy = session;
    sessionCopy.session_id = sessionId;
    sessionCopy.created_at = getCurrentTimestampSeconds();
    sessionCopy.expires_at = sessionCopy.created_at + sessionTimeout_;
    sessionCopy.last_activity = sessionCopy.created_at;
    
    sessions_[sessionId] = sessionCopy;
    
    return sessionId;
}

std::optional<Session> SessionManager::getSession(const std::string& sessionId) {
    std::shared_lock lock(mutex_);
    
    auto it = sessions_.find(sessionId);
    if (it != sessions_.end()) {
        return it->second;
    }
    
    return std::nullopt;
}

bool SessionManager::validateSession(const std::string& sessionId) {
    auto session = getSession(sessionId);
    return session.has_value() && session->isValid();
}

bool SessionManager::refreshSession(const std::string& sessionId) {
    std::unique_lock lock(mutex_);
    
    auto it = sessions_.find(sessionId);
    if (it != sessions_.end()) {
        it->second.last_activity = getCurrentTimestampSeconds();
        it->second.expires_at = it->second.last_activity + sessionTimeout_;
        return true;
    }
    
    return false;
}

void SessionManager::revokeSession(const std::string& sessionId) {
    std::unique_lock lock(mutex_);
    sessions_.erase(sessionId);
}

void SessionManager::revokeAllUserSessions(uint32_t userId) {
    std::unique_lock lock(mutex_);
    
    for (auto it = sessions_.begin(); it != sessions_.end(); ) {
        if (it->second.user_id == userId) {
            it = sessions_.erase(it);
        } else {
            ++it;
        }
    }
}

void SessionManager::cleanupExpiredSessions() {
    uint64_t now = getCurrentTimestampSeconds();
    
    std::unique_lock lock(mutex_);
    
    for (auto it = sessions_.begin(); it != sessions_.end(); ) {
        if (it->second.expires_at < now) {
            it = sessions_.erase(it);
        } else {
            ++it;
        }
    }
}

size_t SessionManager::getActiveSessionCount() const {
    std::shared_lock lock(mutex_);
    return sessions_.size();
}

size_t SessionManager::getUserSessionCount(uint32_t userId) const {
    std::shared_lock lock(mutex_);
    
    size_t count = 0;
    for (const auto& [_, session] : sessions_) {
        if (session.user_id == userId) {
            count++;
        }
    }
    
    return count;
}

// RateLimiter implementation

RateLimiter::RateLimiter(const RateLimitConfig& config)
    : config_(config) {}

bool RateLimiter::check(const std::string& key) {
    return !isLockedOut(key);
}

void RateLimiter::recordAttempt(const std::string& key) {
    std::unique_lock lock(mutex_);
    
    uint64_t now = getCurrentTimestampSeconds();
    auto& attempts = attempts_[key];
    
    // Remove old attempts
    attempts.erase(
        std::remove_if(attempts.begin(), attempts.end(),
            [this, now](uint64_t timestamp) {
                return now - timestamp > config_.windowSeconds;
            }),
        attempts.end()
    );
    
    attempts.push_back(now);
}

bool RateLimiter::isLockedOut(const std::string& key) {
    std::shared_lock lock(mutex_);
    
    auto it = attempts_.find(key);
    if (it == attempts_.end()) {
        return false;
    }
    
    uint64_t now = getCurrentTimestampSeconds();
    
    // Remove old attempts
    std::vector<uint64_t> valid;
    for (uint64_t timestamp : it->second) {
        if (now - timestamp <= config_.windowSeconds) {
            valid.push_back(timestamp);
        }
    }
    
    return valid.size() >= config_.maxAttempts;
}

void RateLimiter::reset(const std::string& key) {
    std::unique_lock lock(mutex_);
    attempts_.erase(key);
}

// AuthManager implementation

AuthManager::AuthManager(std::shared_ptr<IAuthProvider> authProvider,
                         uint64_t sessionTimeout)
    : authProvider_(authProvider) {
    sessionManager_ = std::make_unique<SessionManager>(sessionTimeout);
}

AuthManager::~AuthManager() {
    sessions_.clear();
}

AuthResult AuthManager::login(const std::string& username,
                               const std::string& password,
                               const std::string& remoteAddress) {
    // Check rate limiter
    if (rateLimiter_ && !rateLimiter_->check(remoteAddress)) {
        AuthResult result;
        result.success = false;
        result.errorMessage = "Too many authentication attempts. Please try again later.";
        return result;
    }
    
    // Attempt authentication
    AuthResult result = authProvider_->authenticate(username, password, remoteAddress);
    
    // Record attempt
    if (rateLimiter_) {
        rateLimiter_->recordAttempt(remoteAddress);
    }
    
    if (result.success && !result.sessionId.empty()) {
        // Session already created by provider
        return result;
    }
    
    if (result.success) {
        // Create session
        Session session;
        session.user_name = username;
        session.roles = result.roles;
        session.mfa_authenticated = !result.mfaRequired;
        session.remote_address = remoteAddress;
        
        // Get user ID
        struct passwd* pwd = getpwnam(username.c_str());
        if (pwd) {
            session.user_id = pwd->pw_uid;
        } else {
            session.user_id = 0;
        }
        
        std::string sessionId = sessionManager_->createSession(session);
        result.sessionId = sessionId;
    }
    
    return result;
}

bool AuthManager::logout(const std::string& sessionId) {
    if (!sessionManager_->validateSession(sessionId)) {
        return false;
    }
    
    sessionManager_->revokeSession(sessionId);
    return true;
}

std::optional<Session> AuthManager::getSession(const std::string& sessionId) {
    return sessionManager_->getSession(sessionId);
}

bool AuthManager::isValidSession(const std::string& sessionId) {
    return sessionManager_->validateSession(sessionId);
}

void AuthManager::setRateLimiter(std::shared_ptr<RateLimiter> rateLimiter) {
    rateLimiter_ = rateLimiter;
}

void AuthManager::setMaxSessionsPerUser(size_t max) {
    maxSessionsPerUser_ = max;
}

// SimpleAuthProvider implementation (for testing)

SimpleAuthProvider::SimpleAuthProvider(const std::string& userFilePath)
    : userFilePath_(userFilePath) {}

AuthResult SimpleAuthProvider::authenticate(const std::string& username,
                                             const std::string& password,
                                             const std::string& remoteAddress) {
    AuthResult result;
    
    // Simple authentication for testing
    // In production, use PAM or proper authentication
    if (username == "root" && password == "root") {
        result.success = true;
        result.roles = {"admin", "operator", "auditor"};
    } else if (username == "admin" && password == "admin") {
        result.success = true;
        result.roles = {"admin"};
    } else {
        result.success = false;
        result.errorMessage = "Invalid credentials";
    }
    
    return result;
}

bool SimpleAuthProvider::validateSession(const std::string& sessionId) {
    return !sessionId.empty();
}

bool SimpleAuthProvider::refreshSession(const std::string& sessionId) {
    return !sessionId.empty();
}

bool SimpleAuthProvider::revokeSession(const std::string& sessionId) {
    return true;
}

// PamAuthProvider implementation

PamAuthProvider::PamAuthProvider(const std::string& serviceName)
    : serviceName_(serviceName) {}

PamAuthProvider::~PamAuthProvider() = default;

AuthResult PamAuthProvider::authenticate(const std::string& username,
                                          const std::string& password,
                                          const std::string& remoteAddress) {
    AuthResult result;
    
    // PAM authentication would be implemented here
    // For now, fall back to simple auth
    SimpleAuthProvider simple("/etc/secreg/users");
    result = simple.authenticate(username, password, remoteAddress);
    
    return result;
}

bool PamAuthProvider::validateSession(const std::string& sessionId) {
    return !sessionId.empty();
}

bool PamAuthProvider::refreshSession(const std::string& sessionId) {
    return !sessionId.empty();
}

bool PamAuthProvider::revokeSession(const std::string& sessionId) {
    return true;
}

} // namespace secreg
