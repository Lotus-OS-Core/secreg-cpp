/**
 * @file types.h
 * @brief Common type definitions for SecReg-Linux
 * @author SecReg Security Team
 * @version 1.0.0
 */

#ifndef SECREG_TYPES_H
#define SECREG_TYPES_H

#include <string>
#include <vector>
#include <variant>
#include <optional>
#include <chrono>
#include <cstdint>
#include <memory>

namespace secreg {

/**
 * @brief Enumeration of supported value types
 */
enum class ValueType {
    String,
    Integer,
    Boolean,
    Binary,
    Json,
    EncryptedString
};

/**
 * @brief Union-like structure for storing different value types
 */
class RegistryValue {
public:
    RegistryValue() : type_(ValueType::String), string_value_("") {}
    
    explicit RegistryValue(const std::string& value) 
        : type_(ValueType::String), string_value_(value) {}
    
    explicit RegistryValue(int64_t value)
        : type_(ValueType::Integer), integer_value_(value) {}
    
    explicit RegistryValue(bool value)
        : type_(ValueType::Boolean), boolean_value_(value) {}
    
    explicit RegistryValue(const std::vector<uint8_t>& value)
        : type_(ValueType::Binary), binary_value_(value) {}
    
    static RegistryValue fromString(const std::string& value, ValueType type) {
        switch (type) {
            case ValueType::String:
                return RegistryValue(value);
            case ValueType::Integer:
                return RegistryValue(std::stoll(value));
            case ValueType::Boolean:
                return RegistryValue(value == "true" || value == "1");
            case ValueType::Binary:
                return RegistryValue(std::vector<uint8_t>(value.begin(), value.end()));
            case ValueType::Json:
                return RegistryValue(value);
            case ValueType::EncryptedString:
                return RegistryValue(value);
            default:
                return RegistryValue(value);
        }
    }
    
    ValueType getType() const { return type_; }
    
    std::string asString() const {
        switch (type_) {
            case ValueType::String:
            case ValueType::Json:
            case ValueType::EncryptedString:
                return string_value_;
            case ValueType::Integer:
                return std::to_string(integer_value_);
            case ValueType::Boolean:
                return boolean_value_ ? "true" : "false";
            case ValueType::Binary:
                return std::string(binary_value_.begin(), binary_value_.end());
            default:
                return string_value_;
        }
    }
    
    int64_t asInteger() const {
        switch (type_) {
            case ValueType::Integer:
                return integer_value_;
            case ValueType::String:
                return std::stoll(string_value_);
            case ValueType::Boolean:
                return boolean_value_ ? 1 : 0;
            default:
                return 0;
        }
    }
    
    bool asBoolean() const {
        switch (type_) {
            case ValueType::Boolean:
                return boolean_value_;
            case ValueType::Integer:
                return integer_value_ != 0;
            case ValueType::String:
                return string_value_ == "true" || string_value_ == "1";
            default:
                return false;
        }
    }
    
    std::vector<uint8_t> asBinary() const {
        switch (type_) {
            case ValueType::Binary:
                return binary_value_;
            case ValueType::String:
                return std::vector<uint8_t>(string_value_.begin(), string_value_.end());
            default:
                return std::vector<uint8_t>();
        }
    }
    
    std::vector<uint8_t> serialize() const;
    static RegistryValue deserialize(const std::vector<uint8_t>& data);

private:
    ValueType type_;
    std::string string_value_;
    int64_t integer_value_;
    bool boolean_value_;
    std::vector<uint8_t> binary_value_;
};

/**
 * @brief Principal types for access control
 */
enum class PrincipalType {
    User,
    Group,
    Role,
    Service
};

/**
 * @brief Actions that can be performed on registry keys
 */
enum class Action {
    Read,
    Write,
    Delete,
    Grant,
    Admin
};

/**
 * @brief Access condition types
 */
enum class ConditionType {
    TimeRange,
    IpRange,
    RequireMfa,
    RequireTpm
};

/**
 * @brief Access condition specification
 */
struct AccessCondition {
    ConditionType type;
    uint64_t start_time;      // For TimeRange (seconds from midnight)
    uint64_t end_time;        // For TimeRange (seconds from midnight)
    std::string min_ip;       // For IpRange
    std::string max_ip;       // For IpRange
    bool require_mfa;         // For RequireMfa
    bool require_tpm;         // For RequireTpm
};

/**
 * @brief Permission specification
 */
struct Permission {
    PrincipalType principal_type;
    std::string principal_name;
    std::vector<Action> actions;
    std::vector<AccessCondition> conditions;
};

/**
 * @brief Inheritance mode for ACLs
 */
enum class InheritanceMode {
    None,
    Parent,
    All
};

/**
 * @brief Inheritance rule specification
 */
struct InheritanceRule {
    InheritanceMode mode;
    uint32_t depth;
};

/**
 * @brief Access control entry for a key path
 */
struct AccessControlEntry {
    std::string owner;
    std::string owner_group;
    std::vector<Permission> permissions;
    std::optional<InheritanceRule> inheritance;
    
    AccessControlEntry() 
        : owner("root"), owner_group("wheel"), 
          permissions(), inheritance(std::nullopt) {}
};

/**
 * @brief Registry entry metadata
 */
struct EntryMetadata {
    std::optional<std::string> description;
    std::vector<std::string> tags;
    std::optional<uint64_t> ttl_seconds;
    AccessControlEntry access_control;
};

/**
 * @brief Main registry entry structure
 */
struct RegistryEntry {
    std::string key;
    RegistryValue value;
    ValueType value_type;
    uint64_t created_at;
    uint64_t modified_at;
    std::string created_by;
    std::string modified_by;
    uint64_t version;
    bool is_encrypted;
    EntryMetadata metadata;
    
    RegistryEntry() 
        : key(""), value(""), value_type(ValueType::String),
          created_at(0), modified_at(0), created_by(""), modified_by(""),
          version(1), is_encrypted(false), metadata() {}
    
    RegistryEntry(const std::string& k, const RegistryValue& v, ValueType vt, 
                  const std::string& creator)
        : key(k), value(v), value_type(vt),
          created_at(std::chrono::system_clock::now().time_since_epoch().count()),
          modified_at(created_at), created_by(creator), modified_by(creator),
          version(1), is_encrypted(false), metadata() {}
};

/**
 * @brief Key path structure for hierarchical operations
 */
class KeyPath {
public:
    explicit KeyPath(const std::string& path);
    
    std::string toString() const;
    std::vector<std::string> getComponents() const;
    std::optional<KeyPath> getParent() const;
    bool isChildOf(const KeyPath& other) const;
    bool isValid() const;
    
private:
    std::vector<std::string> components_;
    static bool isValidComponent(const std::string& component);
};

/**
 * @brief Actor information for audit logging
 */
struct ActorInfo {
    uint32_t user_id;
    std::string user_name;
    uint32_t group_id;
    uint32_t process_id;
    uint32_t session_id;
    std::optional<std::string> tty;
    std::optional<std::string> remote_address;
    std::string authentication_method;
    bool mfa_used;
};

/**
 * @brief Source information for audit logging
 */
struct SourceInfo {
    std::optional<std::string> socket_path;
    std::optional<std::string> network_address;
    std::string client_version;
};

/**
 * @brief Audit record structure
 */
struct AuditRecord {
    std::string id;
    uint64_t timestamp;
    ActorInfo actor;
    Action action;
    std::string target_key;
    bool success;
    std::optional<std::string> error_message;
    SourceInfo source_info;
    std::string request_hash;
    std::optional<std::string> previous_value_hash;
    std::optional<std::string> new_value_hash;
};

/**
 * @brief Session information for authenticated users
 */
struct Session {
    std::string session_id;
    uint32_t user_id;
    std::string user_name;
    uint64_t created_at;
    uint64_t expires_at;
    uint64_t last_activity;
    bool mfa_authenticated;
    std::vector<std::string> roles;
    std::optional<std::string> remote_address;
    
    bool isExpired() const {
        auto now = std::chrono::system_clock::now().time_since_epoch().count();
        return now > expires_at;
    }
    
    bool isValid() const {
        return !isExpired();
    }
};

/**
 * @brief Access decision result
 */
struct AccessDecision {
    bool allowed;
    std::string reason;
    std::optional<Permission> matched_permission;
};

} // namespace secreg

#endif // SECREG_TYPES_H
