/**
 * @file acl.h
 * @brief Access Control List for SecReg-Linux
 * @author SecReg Security Team
 * @version 1.0.0
 */

#ifndef SECREG_ACL_H
#define SECREG_ACL_H

#include "types.h"
#include "errors.h"
#include <string>
#include <memory>
#include <unordered_map>
#include <vector>
#include <shared_mutex>

namespace secreg {

/**
 * @brief ACL manager
 */
class AclManager {
public:
    AclManager();
    ~AclManager();
    
    // Permission checking
    AccessDecision checkAccess(const Session& session,
                               const std::string& keyPath,
                               Action action);
    
    // ACL management
    void setAcl(const std::string& keyPath, const AccessControlEntry& acl);
    std::optional<AccessControlEntry> getAcl(const std::string& keyPath);
    bool deleteAcl(const std::string& keyPath);
    std::vector<std::string> listAcls(const std::string& prefix);
    
    // Permission management
    bool grantPermission(const std::string& keyPath,
                        const Permission& permission);
    bool revokePermission(const std::string& keyPath,
                          const std::string& principalName);
    bool revokeAllPermissions(const std::string& keyPath);
    
    // Default ACLs
    void setDefaultAcl(const AccessControlEntry& acl);
    AccessControlEntry getDefaultAcl() const;
    
    // Cache management
    void clearCache();
    void invalidateCache(const std::string& keyPath);
    
private:
    std::unordered_map<std::string, AccessControlEntry> aclStore_;
    mutable std::shared_mutex mutex_;
    AccessControlEntry defaultAcl_;
    
    std::optional<AccessControlEntry> resolveAcl(const std::string& keyPath);
    bool matchPrincipal(const Permission& permission, const Session& session);
    bool checkConditions(const std::vector<AccessCondition>& conditions,
                         const Session& session);
    void cacheAcl(const std::string& keyPath, const AccessControlEntry& acl);
};

/**
 * @brief Role-based access control
 */
class RbacManager {
public:
    RbacManager();
    ~RbacManager();
    
    // Role management
    void createRole(const std::string& roleName, 
                    const std::vector<Permission>& permissions);
    void deleteRole(const std::string& roleName);
    void updateRole(const std::string& roleName,
                    const std::vector<Permission>& permissions);
    
    // User-role assignment
    void assignRole(const std::string& userName, const std::string& roleName);
    void revokeRole(const std::string& userName, const std::string& roleName);
    std::vector<std::string> getUserRoles(const std::string& userName);
    
    // Role permissions
    void addPermissionToRole(const std::string& roleName,
                             const Permission& permission);
    void removePermissionFromRole(const std::string& roleName,
                                  const std::string& permissionName);
    std::vector<Permission> getRolePermissions(const std::string& roleName);
    
    // Check permissions
    bool hasPermission(const Session& session, const std::string& resource,
                       Action action);
    
private:
    std::unordered_map<std::string, std::vector<Permission>> roles_;
    std::unordered_map<std::string, std::vector<std::string>> userRoles_;
    mutable std::shared_mutex mutex_;
    
    static constexpr const char* ADMIN_ROLE = "admin";
    static constexpr const char* OPERATOR_ROLE = "operator";
    static constexpr const char* AUDITOR_ROLE = "auditor";
    
    void initializeDefaultRoles();
};

} // namespace secreg

#endif // SECREG_ACL_H
