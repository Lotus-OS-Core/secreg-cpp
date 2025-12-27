/**
 * @file utils.cpp
 * @brief Utility functions implementation for SecReg-Linux
 * @author SecReg Security Team
 * @version 1.0.0
 */

#include "utils.h"
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <chrono>
#include <thread>
#include <algorithm>
#include <regex>

namespace secreg {

std::string generateRandomString(size_t length) {
    static const char charset[] = 
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789";
    
    std::vector<uint8_t> random_bytes(length);
    if (RAND_bytes(random_bytes.data(), length) != 1) {
        throw std::runtime_error("Failed to generate random bytes");
    }
    
    std::string result;
    result.reserve(length);
    for (size_t i = 0; i < length; ++i) {
        result += charset[random_bytes[i] % (sizeof(charset) - 1)];
    }
    
    return result;
}

std::vector<uint8_t> generateRandomBytes(size_t length) {
    std::vector<uint8_t> result(length);
    
    if (RAND_bytes(result.data(), length) != 1) {
        throw std::runtime_error("Failed to generate random bytes");
    }
    
    return result;
}

std::string generateUuid() {
    std::vector<uint8_t> bytes(16);
    if (RAND_bytes(bytes.data(), 16) != 1) {
        throw std::runtime_error("Failed to generate UUID bytes");
    }
    
    // Set version (4) and variant (8, 9, A, or B)
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < 16; ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) {
            oss << '-';
        }
        oss << std::setw(2) << static_cast<int>(bytes[i]);
    }
    
    return oss.str();
}

uint64_t getCurrentTimestamp() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

uint64_t getCurrentTimestampSeconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

std::string toLower(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(),
        [](unsigned char c) { return std::tolower(c); });
    return result;
}

std::string toUpper(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(),
        [](unsigned char c) { return std::toupper(c); });
    return result;
}

std::string trim(const std::string& str) {
    const char* whitespace = " \t\n\r\f\v";
    size_t start = str.find_first_not_of(whitespace);
    if (start == std::string::npos) {
        return "";
    }
    size_t end = str.find_last_not_of(whitespace);
    return str.substr(start, end - start + 1);
}

std::vector<std::string> split(const std::string& str, char delimiter) {
    std::vector<std::string> result;
    std::stringstream ss(str);
    std::string item;
    
    while (std::getline(ss, item, delimiter)) {
        result.push_back(item);
    }
    
    return result;
}

std::string join(const std::vector<std::string>& strings, const std::string& delimiter) {
    if (strings.empty()) {
        return "";
    }
    
    std::ostringstream oss;
    for (size_t i = 0; i < strings.size(); ++i) {
        if (i > 0) {
            oss << delimiter;
        }
        oss << strings[i];
    }
    
    return oss.str();
}

bool startsWith(const std::string& str, const std::string& prefix) {
    if (prefix.size() > str.size()) {
        return false;
    }
    return str.compare(0, prefix.size(), prefix) == 0;
}

bool endsWith(const std::string& str, const std::string& suffix) {
    if (suffix.size() > str.size()) {
        return false;
    }
    return str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::string replaceAll(const std::string& str, const std::string& from, const std::string& to) {
    if (from.empty()) {
        return str;
    }
    
    std::string result = str;
    size_t pos = 0;
    
    while ((pos = result.find(from, pos)) != std::string::npos) {
        result.replace(pos, from.length(), to);
        pos += to.length();
    }
    
    return result;
}

std::string base64Encode(const std::vector<uint8_t>& data) {
    static const char* charset = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    std::string result;
    result.reserve((data.size() + 2) / 3 * 4);
    
    size_t i = 0;
    while (i < data.size()) {
        uint32_t n = data[i++] << 16;
        if (i < data.size()) {
            n += data[i++] << 8;
        }
        if (i < data.size()) {
            n += data[i++];
        }
        
        result += charset[(n >> 18) & 0x3F];
        result += charset[(n >> 12) & 0x3F];
        result += (i > data.size() + 1) ? '=' : charset[(n >> 6) & 0x3F];
        result += (i > data.size()) ? '=' : charset[n & 0x3F];
    }
    
    return result;
}

std::vector<uint8_t> base64Decode(const std::string& str) {
    static const int8_t charset[128] = {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
        -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
        -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1
    };
    
    std::vector<uint8_t> result;
    result.reserve(str.size() * 3 / 4);
    
    int8_t n = 0;
    int8_t padding = 0;
    
    for (char c : str) {
        if (c == '=') {
            padding++;
            continue;
        }
        if (c < 0 || c >= 128 || charset[static_cast<unsigned char>(c)] == -1) {
            continue;
        }
        
        n = (n << 6) + charset[static_cast<unsigned char>(c)];
        
        if (n & (1 << 24)) {
            result.push_back((n >> 16) & 0xFF);
            if (padding < 2) {
                result.push_back((n >> 8) & 0xFF);
            }
            if (padding < 1) {
                result.push_back(n & 0xFF);
            }
            n = 0;
        }
    }
    
    // Remove padding bytes
    if (padding > 0) {
        result.resize(result.size() - padding);
    }
    
    return result;
}

std::string hexEncode(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    
    for (uint8_t byte : data) {
        oss << std::setw(2) << static_cast<int>(byte);
    }
    
    return oss.str();
}

std::vector<uint8_t> hexDecode(const std::string& str) {
    std::vector<uint8_t> result;
    result.reserve(str.size() / 2);
    
    for (size_t i = 0; i < str.size(); i += 2) {
        std::string byte_str = str.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
        result.push_back(byte);
    }
    
    return result;
}

std::string sha256Hash(const std::string& data) {
    return hexEncode(sha256HashBytes(std::vector<uint8_t>(data.begin(), data.end())));
}

std::vector<uint8_t> sha256HashBytes(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    
    SHA256(data.data(), data.size(), hash.data());
    
    return hash;
}

std::string readFile(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file: " + path.string());
    }
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    
    return buffer.str();
}

void writeFile(const std::filesystem::path& path, const std::string& content) {
    std::filesystem::path parent = path.parent_path();
    if (!parent.empty() && !std::filesystem::exists(parent)) {
        std::filesystem::create_directories(parent);
    }
    
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to write file: " + path.string());
    }
    
    file << content;
}

void ensureDirectory(const std::filesystem::path& path, mode_t mode) {
    if (!std::filesystem::exists(path)) {
        std::filesystem::create_directories(path);
        std::filesystem::permissions(path, 
            std::filesystem::perms::owner_all | 
            std::filesystem::perms::group_all);
    }
}

std::string formatFileSize(uint64_t bytes) {
    static const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit = 0;
    double size = bytes;
    
    while (size >= 1024 && unit < 4) {
        size /= 1024;
        unit++;
    }
    
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2) << size << " " << units[unit];
    return oss.str();
}

std::string formatDuration(uint64_t seconds) {
    if (seconds < 60) {
        return std::to_string(seconds) + "s";
    } else if (seconds < 3600) {
        return std::to_string(seconds / 60) + "m " + 
               std::to_string(seconds % 60) + "s";
    } else if (seconds < 86400) {
        return std::to_string(seconds / 3600) + "h " + 
               std::to_string((seconds % 3600) / 60) + "m";
    } else {
        return std::to_string(seconds / 86400) + "d " + 
               std::to_string((seconds % 86400) / 3600) + "h";
    }
}

bool isValidKeyPath(const std::string& key) {
    if (key.empty() || key[0] != '/') {
        return false;
    }
    
    std::vector<std::string> components = split(key, '/');
    
    for (const auto& component : components) {
        if (component.empty()) {
            return false;
        }
        if (component.find("..") != std::string::npos) {
            return false;
        }
        if (component.find('\0') != std::string::npos) {
            return false;
        }
    }
    
    return true;
}

std::string sanitizeForLogging(const std::string& str) {
    // Remove potential sensitive patterns
    std::string result = replaceAll(str, "password", "[REDACTED]");
    result = replaceAll(result, "token", "[REDACTED]");
    result = replaceAll(result, "secret", "[REDACTED]");
    result = replaceAll(result, "key", "[REDACTED]");
    result = replaceAll(result, "credential", "[REDACTED]");
    
    // Mask potential password-like values
    static const std::regex password_pattern(
        R"((?:password|passwd|pwd|secret|token|key)[=:]\s*\S+)",
        std::regex::icase
    );
    result = std::regex_replace(result, password_pattern, "$1=[REDACTED]");
    
    return result;
}

std::string maskSensitive(const std::string& str, size_t visibleChars) {
    if (str.size() <= visibleChars) {
        return str;
    }
    
    std::string result;
    result.reserve(str.size());
    result += str.substr(0, visibleChars);
    result += std::string(str.size() - visibleChars, '*');
    
    return result;
}

} // namespace secreg
