/**
 * @file acl.cpp
 * @brief Access Control List implementation for SecReg-Linux
 * @author SecReg Security Team
 * @version 1.0.0
 */

#include "acl.h"
#include "constants.h"
#include "utils.h"
#include <iostream>

namespace secreg {

// AclManager implementation

AclManager::AclManager() {
    // Set up default ACL
    defaultAcl_.owner = "root";
    defaultAcl_.owner_group = "wheel";
    
    // Admin gets full access by default
    Permission adminPerm;
    adminPerm.principal_type = PrincipalType::Role;
    adminPerm.principal_name = "admin";
    adminPerm.actions = {Action::Read, Action::Write, Action::Delete, 
                         Action::Grant, Action::Admin};
    defaultAcl_.permissions.push_back(adminPerm);
}

AclManager::~AclManager() {
    aclStore_.clear();
}

AccessDecision AclManager::checkAccess(const Session& session,
                                        const std::string& keyPath,
                                        Action action) {
    // Check if user is admin
    for (const auto& role : session.roles) {
        if (role == "admin") {
            return {true, "Admin access granted", std::nullopt};
        }
    }
    
    // Resolve ACL for the key path
    auto aclOpt = resolveAcl(keyPath);
    if (!aclOpt.has_value()) {
        return {false, "No ACL found for key", std::nullopt};
    }
    
    const AccessControlEntry& acl = aclOpt.value();
    
    // Check each permission
    for (const auto& permission : acl.permissions) {
        if (matchPrincipal(permission, session)) {
            // Check if action is allowed
            bool actionAllowed = false;
            for (const auto& permAction : permission.actions) {
                if (permAction == action) {
                    actionAllowed = true;
                    break;
                }
            }
            
            if (actionAllowed) {
                // Check conditions
                if (checkConditions(permission.conditions, session)) {
                    return {true, "Access granted", permission};
                } else {
                    return {false, "Access condition not met", std::nullopt};
                }
            }
        }
    }
    
    return {false, "No matching permission", std::nullopt};
}

void AclManager::setAcl(const std::string& keyPath, 
                        const AccessControlEntry& acl) {
    std::unique_lock lock(mutex_);
    aclStore_[keyPath] = acl;
}

std::optional<AccessControlEntry> AclManager::getAcl(const std::string& keyPath) {
    std::shared_lock lock(mutex_);
    
    auto it = aclStore_.find(keyPath);
    if (it != aclStore_.end()) {
        return it->second;
    }
    
    return std::nullopt;
}

bool AclManager::deleteAcl(const std::string& keyPath) {
    std::unique_lock lock(mutex_);
    return aclStore_.erase(keyPath) > 0;
}

std::vector<std::string> AclManager::listAcls(const std::string& prefix) {
    std::shared_lock lock(mutex_);
    
    std::vector<std::string> result;
    for (const auto& [key, _] : aclStore_) {
        if (key.find(prefix) == 0) {
            result.push_back(key);
        }
    }
    
    return result;
}

bool AclManager::grantPermission(const std::string& keyPath,
                                  const Permission& permission) {
    std::unique_lock lock(mutex_);
    
    auto& acl = aclStore_[keyPath];
    acl.permissions.push_back(permission);
    
    return true;
}

bool AclManager::revokePermission(const std::string& keyPath,
                                   const std::string& principalName) {
    std::unique_lock lock(mutex_);
    
    auto it = aclStore_.find(keyPath);
    if (it == aclStore_.end()) {
        return false;
    }
    
    auto& permissions = it->second.permissions;
    permissions.erase(
        std::remove_if(permissions.begin(), permissions.end(),
            [&principalName](const Permission& p) {
                return p.principal_name == principalName;
            }),
        permissions.end()
    );
    
    return true;
}

bool AclManager::revokeAllPermissions(const std::string& keyPath) {
    std::unique_lock lock(mutex_);
    
    auto it = aclStore_.find(keyPath);
    if (it == aclStore_.end()) {
        return false;
    }
    
    it->second.permissions.clear();
    return true;
}

void AclManager::setDefaultAcl(const AccessControlEntry& acl) {
    std::unique_lock lock(mutex_);
    defaultAcl_ = acl;
}

AccessControlEntry AclManager::getDefaultAcl() const {
    std::shared_lock lock(mutex_);
    return defaultAcl_;
}

void AclManager::clearCache() {
    std::unique_lock lock(mutex_);
    aclStore_.clear();
}

void AclManager::invalidateCache(const std::string& keyPath) {
    std::unique_lock lock(mutex_);
    aclStore_.erase(keyPath);
}

std::optional<AccessControlEntry> AclManager::resolveAcl(const std::string& keyPath) {
    std::shared_lock lock(mutex_);
    
    // Check for exact match
    auto it = aclStore_.find(keyPath);
    if (it != aclStore_.end()) {
        return it->second;
    }
    
    // Check for inherited ACL
    KeyPath kp(keyPath);
    auto parent = kp.getParent();
    
    if (parent.has_value()) {
        auto parentAclOpt = resolveAcl(parent.value().toString());
        if (parentAclOpt.has_value()) {
            const auto& parentAcl = parentAclOpt.value();
            if (parentAcl.inheritance.has_value()) {
                return parentAcl;
            }
        }
    }
    
    // Return default ACL
    return defaultAcl_;
}

bool AclManager::matchPrincipal(const Permission& permission,
                                 const Session& session) {
    switch (permission.principal_type) {
        case PrincipalType::User:
            return permission.principal_name == session.user_name;
            
        case PrincipalType::Group:
            // Would check user's groups
            return false;
            
        case PrincipalType::Role:
            for (const auto& role : session.roles) {
                if (role == permission.principal_name) {
                    return true;
                }
            }
            return false;
            
        case PrincipalType::Service:
            return false;
    }
    
    return false;
}

bool AclManager::checkConditions(const std::vector<AccessCondition>& conditions,
                                  const Session& session) {
    for (const auto& condition : conditions) {
        switch (condition.type) {
            case ConditionType::TimeRange: {
                uint64_t now = getCurrentTimestampSeconds();
                uint64_t secondsToday = now % 86400;
                if (secondsToday < condition.start_time || 
                    secondsToday > condition.end_time) {
                    return false;
                }
                break;
            }
            case ConditionType::IpRange: {
                if (session.remote_address.has_value()) {
                    // Would check IP range
                }
                break;
            }
            case ConditionType::RequireMfa: {
                if (condition.require_mfa && !session.mfa_authenticated) {
                    return false;
                }
                break;
            }
            case ConditionType::RequireTpm: {
                // Would check for TPM
                break;
            }
        }
    }
    
    return true;
}

void AclManager::cacheAcl(const std::string& keyPath,
                          const AccessControlEntry& acl) {
    std::unique_lock lock(mutex_);
    aclStore_[keyPath] = acl;
}

// RbacManager implementation

RbacManager::RbacManager() {
    initializeDefaultRoles();
}

RbacManager::~RbacManager() {
    roles_.clear();
    userRoles_.clear();
}

void RbacManager::initializeDefaultRoles() {
    // Admin role - full access
    roles_[ADMIN_ROLE] = {
        Permission{PrincipalType::Role, ADMIN_ROLE, 
                   {Action::Read, Action::Write, Action::Delete, 
                    Action::Grant, Action::Admin}, {}}
    };
    
    // Operator role - read/write but no grant
    roles_[OPERATOR_ROLE] = {
        Permission{PrincipalType::Role, OPERATOR_ROLE,
                   {Action::Read, Action::Write}, {}}
    };
    
    // Auditor role - read only
    roles_[AUDITOR_ROLE] = {
        Permission{PrincipalType::Role, AUDITOR_ROLE,
                   {Action::Read}, {}}
    };
}

void RbacManager::createRole(const std::string& roleName,
                              const std::vector<Permission>& permissions) {
    std::unique_lock lock(mutex_);
    roles_[roleName] = permissions;
}

void RbacManager::deleteRole(const std::string& roleName) {
    std::unique_lock lock(mutex_);
    roles_.erase(roleName);
    
    // Remove from all users
    for (auto& [user, userRoles] : userRoles_) {
        userRoles.erase(
            std::remove(userRoles.begin(), userRoles.end(), roleName),
            userRoles.end()
        );
    }
}

void RbacManager::updateRole(const std::string& roleName,
                              const std::vector<Permission>& permissions) {
    std::unique_lock lock(mutex_);
    
    if (roles_.find(roleName) != roles_.end()) {
        roles_[roleName] = permissions;
    }
}

void RbacManager::assignRole(const std::string& userName,
                              const std::string& roleName) {
    std::unique_lock lock(mutex_);
    userRoles_[userName].push_back(roleName);
}

void RbacManager::revokeRole(const std::string& userName,
                              const std::string& roleName) {
    std::unique_lock lock(mutex_);
    
    auto it = userRoles_.find(userName);
    if (it != userRoles_.end()) {
        it->second.erase(
            std::remove(it->second.begin(), it->second.end(), roleName),
            it->second.end()
        );
    }
}

std::vector<std::string> RbacManager::getUserRoles(const std::string& userName) {
    std::shared_lock lock(mutex_);
    
    auto it = userRoles_.find(userName);
    if (it != userRoles_.end()) {
        return it->second;
    }
    
    return {};
}

void RbacManager::addPermissionToRole(const std::string& roleName,
                                       const Permission& permission) {
    std::unique_lock lock(mutex_);
    roles_[roleName].push_back(permission);
}

void RbacManager::removePermissionFromRole(const std::string& roleName,
                                            const std::string& permissionName) {
    std::unique_lock lock(mutex_);
    
    auto it = roles_.find(roleName);
    if (it != roles_.end()) {
        it->second.erase(
            std::remove_if(it->second.begin(), it->second.end(),
                [&permissionName](const Permission& p) {
                    return p.principal_name == permissionName;
                }),
            it->second.end()
        );
    }
}

std::vector<Permission> RbacManager::getRolePermissions(const std::string& roleName) {
    std::shared_lock lock(mutex_);
    
    auto it = roles_.find(roleName);
    if (it != roles_.end()) {
        return it->second;
    }
    
    return {};
}

bool RbacManager::hasPermission(const Session& session,
                                 const std::string& resource,
                                 Action action) {
    std::shared_lock lock(mutex_);
    
    // Check user's roles
    for (const auto& roleName : session.roles) {
        auto it = roles_.find(roleName);
        if (it != roles_.end()) {
            for (const auto& permission : it->second) {
                // Check if permission applies to this resource
                // For now, just check if action is in the list
                for (const auto& permAction : permission.actions) {
                    if (permAction == action) {
                        return true;
                    }
                }
            }
        }
    }
    
    return false;
}

} // namespace secreg
