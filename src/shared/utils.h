/**
 * @file utils.h
 * @brief Utility functions for SecReg-Linux
 * @author SecReg Security Team
 * @version 1.0.0
 */

#ifndef SECREG_UTILS_H
#define SECREG_UTILS_H

#include <string>
#include <vector>
#include <chrono>
#include <functional>
#include <optional>
#include <filesystem>

namespace secreg {

/**
 * @brief Generate a random string of specified length
 * @param length Length of the string to generate
 * @return Random alphanumeric string
 */
std::string generateRandomString(size_t length);

/**
 * @brief Generate random bytes
 * @param length Number of bytes to generate
 * @return Vector of random bytes
 */
std::vector<uint8_t> generateRandomBytes(size_t length);

/**
 * @brief Generate a UUID v4
 * @return UUID string
 */
std::string generateUuid();

/**
 * @brief Get current timestamp in milliseconds
 * @return Current timestamp
 */
uint64_t getCurrentTimestamp();

/**
 * @brief Get current timestamp in seconds
 * @return Current timestamp in seconds
 */
uint64_t getCurrentTimestampSeconds();

/**
 * @brief Convert string to lowercase
 * @param str Input string
 * @return Lowercase string
 */
std::string toLower(const std::string& str);

/**
 * @brief Convert string to uppercase
 * @param str Input string
 * @return Uppercase string
 */
std::string toUpper(const std::string& str);

/**
 * @brief Trim whitespace from both ends of a string
 * @param str Input string
 * @return Trimmed string
 */
std::string trim(const std::string& str);

/**
 * @brief Split a string by delimiter
 * @param str Input string
 * @param delimiter Delimiter character
 * @return Vector of split parts
 */
std::vector<std::string> split(const std::string& str, char delimiter);

/**
 * @brief Join strings with delimiter
 * @param strings Vector of strings
 * @param delimiter Delimiter string
 * @return Joined string
 */
std::string join(const std::vector<std::string>& strings, const std::string& delimiter);

/**
 * @brief Check if string starts with prefix
 * @param str Input string
 * @param prefix Prefix to check
 * @return True if starts with prefix
 */
bool startsWith(const std::string& str, const std::string& prefix);

/**
 * @brief Check if string ends with suffix
 * @param str Input string
 * @param suffix Suffix to check
 * @return True if ends with suffix
 */
bool endsWith(const std::string& str, const std::string& suffix);

/**
 * @brief Replace all occurrences of substring
 * @param str Input string
 * @param from Substring to replace
 * @param to Replacement string
 * @return Modified string
 */
std::string replaceAll(const std::string& str, const std::string& from, const std::string& to);

/**
 * @brief Base64 encode
 * @param data Input data
 * @return Base64 encoded string
 */
std::string base64Encode(const std::vector<uint8_t>& data);

/**
 * @brief Base64 decode
 * @param str Base64 encoded string
 * @return Decoded data
 */
std::vector<uint8_t> base64Decode(const std::string& str);

/**
 * @brief Hex encode
 * @param data Input data
 * @return Hex encoded string
 */
std::string hexEncode(const std::vector<uint8_t>& data);

/**
 * @brief Hex decode
 * @param str Hex encoded string
 * @return Decoded data
 */
std::vector<uint8_t> hexDecode(const std::string& str);

/**
 * @brief Hash string using SHA-256
 * @param data Input data
 * @return Hash as hex string
 */
std::string sha256Hash(const std::string& data);

/**
 * @brief Hash bytes using SHA-256
 * @param data Input bytes
 * @return Hash bytes
 */
std::vector<uint8_t> sha256HashBytes(const std::vector<uint8_t>& data);

/**
 * @brief Read file contents
 * @param path File path
 * @return File contents as string
 * @throws std::runtime_error if file cannot be read
 */
std::string readFile(const std::filesystem::path& path);

/**
 * @brief Write string to file
 * @param path File path
 * @param content Content to write
 * @throws std::runtime_error if file cannot be written
 */
void writeFile(const std::filesystem::path& path, const std::string& content);

/**
 * @brief Ensure directory exists
 * @param path Directory path
 * @param mode Directory permissions
 */
void ensureDirectory(const std::filesystem::path& path, mode_t mode = 0755);

/**
 * @brief Execute function with retry logic
 * @param func Function to execute
 * @param maxRetries Maximum retry attempts
 * @param delayMs Delay between retries in milliseconds
 * @return Result of function or last error
 */
template<typename Func>
auto withRetry(Func func, uint32_t maxRetries = 3, uint32_t delayMs = 1000) 
    -> decltype(func()) {
    
    for (uint32_t attempt = 0; attempt <= maxRetries; ++attempt) {
        try {
            return func();
        } catch (const std::exception& e) {
            if (attempt == maxRetries) {
                throw;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
        }
    }
    throw std::runtime_error("Unexpected error in retry logic");
}

/**
 * @brief Format file size for display
 * @param bytes Size in bytes
 * @return Human-readable size string
 */
std::string formatFileSize(uint64_t bytes);

/**
 * @brief Format duration for display
 * @param seconds Duration in seconds
 * @return Human-readable duration string
 */
std::string formatDuration(uint64_t seconds);

/**
 * @brief Validate key path format
 * @param key Key path to validate
 * @return True if valid
 */
bool isValidKeyPath(const std::string& key);

/**
 * @brief Sanitize string for logging (remove sensitive data)
 * @param str Input string
 * @return Sanitized string
 */
std::string sanitizeForLogging(const std::string& str);

/**
 * @brief Mask sensitive data in string
 * @param str Input string
 * @param visibleChars Number of characters to keep visible at start
 * @return Masked string
 */
std::string maskSensitive(const std::string& str, size_t visibleChars = 4);

} // namespace secreg

#endif // SECREG_UTILS_H
