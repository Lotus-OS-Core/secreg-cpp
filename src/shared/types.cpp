/**
 * @file types.cpp
 * @brief Implementation of type definitions for SecReg-Linux
 * @author SecReg Security Team
 * @version 1.0.0
 */

#include "types.h"
#include <sstream>
#include <iomanip>
#include <regex>

namespace secreg {

// RegistryValue implementation

std::vector<uint8_t> RegistryValue::serialize() const {
    std::vector<uint8_t> data;
    
    // Write type
    data.push_back(static_cast<uint8_t>(type_));
    
    // Write value based on type
    switch (type_) {
        case ValueType::String:
        case ValueType::Json:
        case ValueType::EncryptedString: {
            uint32_t len = static_cast<uint32_t>(string_value_.size());
            data.insert(data.end(), 
                reinterpret_cast<const uint8_t*>(&len),
                reinterpret_cast<const uint8_t*>(&len) + sizeof(len));
            data.insert(data.end(), string_value_.begin(), string_value_.end());
            break;
        }
        case ValueType::Integer: {
            data.insert(data.end(),
                reinterpret_cast<const uint8_t*>(&integer_value_),
                reinterpret_cast<const uint8_t*>(&integer_value_) + sizeof(integer_value_));
            break;
        }
        case ValueType::Boolean: {
            data.push_back(boolean_value_ ? 1 : 0);
            break;
        }
        case ValueType::Binary: {
            uint32_t len = static_cast<uint32_t>(binary_value_.size());
            data.insert(data.end(),
                reinterpret_cast<const uint8_t*>(&len),
                reinterpret_cast<const uint8_t*>(&len) + sizeof(len));
            data.insert(data.end(), binary_value_.begin(), binary_value_.end());
            break;
        }
    }
    
    return data;
}

RegistryValue RegistryValue::deserialize(const std::vector<uint8_t>& data) {
    if (data.empty()) {
        return RegistryValue("");
    }
    
    ValueType type = static_cast<ValueType>(data[0]);
    size_t offset = 1;
    
    switch (type) {
        case ValueType::String:
        case ValueType::Json:
        case ValueType::EncryptedString: {
            if (data.size() < offset + sizeof(uint32_t)) {
                return RegistryValue("");
            }
            uint32_t len;
            std::memcpy(&len, &data[offset], sizeof(len));
            offset += sizeof(len);
            if (data.size() < offset + len) {
                return RegistryValue("");
            }
            return RegistryValue(std::string(
                reinterpret_cast<const char*>(&data[offset]), len));
        }
        case ValueType::Integer: {
            if (data.size() < offset + sizeof(int64_t)) {
                return RegistryValue(0);
            }
            int64_t value;
            std::memcpy(&value, &data[offset], sizeof(value));
            return RegistryValue(value);
        }
        case ValueType::Boolean: {
            return RegistryValue(data[offset] != 0);
        }
        case ValueType::Binary: {
            if (data.size() < offset + sizeof(uint32_t)) {
                return RegistryValue(std::vector<uint8_t>());
            }
            uint32_t len;
            std::memcpy(&len, &data[offset], sizeof(len));
            offset += sizeof(len);
            if (data.size() < offset + len) {
                return RegistryValue(std::vector<uint8_t>());
            }
            return RegistryValue(std::vector<uint8_t>(
                data.begin() + offset, data.begin() + offset + len));
        }
        default:
            return RegistryValue("");
    }
}

// KeyPath implementation

KeyPath::KeyPath(const std::string& path) {
    if (path.empty() || path[0] != '/') {
        components_.clear();
        return;
    }
    
    std::istringstream iss(path.substr(1));
    std::string component;
    
    while (std::getline(iss, component, '/')) {
        if (!component.empty() && isValidComponent(component)) {
            components_.push_back(component);
        }
    }
}

std::string KeyPath::toString() const {
    if (components_.empty()) {
        return "/";
    }
    std::string result = "/";
    for (size_t i = 0; i < components_.size(); ++i) {
        result += components_[i];
        if (i < components_.size() - 1) {
            result += "/";
        }
    }
    return result;
}

std::vector<std::string> KeyPath::getComponents() const {
    return components_;
}

std::optional<KeyPath> KeyPath::getParent() const {
    if (components_.empty()) {
        return std::nullopt;
    }
    
    KeyPath parent;
    parent.components_ = std::vector<std::string>(
        components_.begin(), 
        components_.end() - 1
    );
    return parent;
}

bool KeyPath::isChildOf(const KeyPath& other) const {
    if (other.components_.size() >= components_.size()) {
        return false;
    }
    
    for (size_t i = 0; i < other.components_.size(); ++i) {
        if (components_[i] != other.components_[i]) {
            return false;
        }
    }
    
    return true;
}

bool KeyPath::isValid() const {
    return !components_.empty();
}

bool KeyPath::isValidComponent(const std::string& component) {
    // Check for empty components
    if (component.empty()) {
        return false;
    }
    
    // Check for path traversal
    if (component == ".." || component.find("..") != std::string::npos) {
        return false;
    }
    
    // Check for null bytes
    if (component.find('\0') != std::string::npos) {
        return false;
    }
    
    // Check for reserved characters
    static const std::regex reserved_pattern(R"([\*\?\[\]|&;$<>`\\!])");
    if (std::regex_search(component, reserved_pattern)) {
        return false;
    }
    
    return true;
}

} // namespace secreg
