/**
 * @file cli.h
 * @brief Command-line interface for SecReg-Linux
 * @author SecReg Security Team
 * @version 1.0.0
 */

#ifndef SECREG_CLI_H
#define SECREG_CLI_H

#include "types.h"
#include <string>
#include <memory>
#include <functional>
#include <vector>
#include <unordered_map>

namespace secreg {

/**
 * @brief CLI configuration
 */
struct CliConfig {
    std::string socketPath = PathConstants::DEFAULT_SOCKET_PATH;
    std::string configPath = PathConstants::DEFAULT_CONFIG_PATH;
    bool verbose = false;
    bool jsonOutput = false;
};

/**
 * @brief Command result
 */
struct CommandResult {
    bool success;
    std::string message;
    std::string data;
    int exitCode = 0;
};

/**
 * @brief Command interface
 */
class ICommand {
public:
    virtual ~ICommand() = default;
    virtual std::string getName() const = 0;
    virtual std::string getDescription() const = 0;
    virtual std::string getUsage() const = 0;
    virtual CommandResult execute(const std::vector<std::string>& args) = 0;
};

/**
 * @brief CLI application
 */
class CliApp {
public:
    explicit CliApp(const CliConfig& config);
    ~CliApp();
    
    void addCommand(std::unique_ptr<ICommand> command);
    CommandResult run(int argc, char* argv[]);
    
    void setOnErrorCallback(std::function<void(const std::string&)> callback);
    
    const CliConfig& getConfig() const;
    
private:
    CliConfig config_;
    std::unordered_map<std::string, std::unique_ptr<ICommand>> commands_;
    std::function<void(const std::string&)> onErrorCallback_;
    
    void printHelp(const std::string& command = "");
    void printVersion();
    void printError(const std::string& message);
    
    std::unique_ptr<ICommand> findCommand(const std::string& name);
};

/**
 * @brief Connection manager for CLI
 */
class CliConnection {
public:
    explicit CliConnection(const std::string& socketPath);
    ~CliConnection();
    
    bool connect();
    void disconnect();
    bool isConnected() const;
    
    CommandResult sendRequest(const std::vector<uint8_t>& data);
    
private:
    std::string socketPath_;
    int socket_ = -1;
    
    bool write(const void* data, size_t size);
    std::vector<uint8_t> read();
};

/**
 * @brief CLI utilities
 */
struct CliUtils {
    static std::string getPassword();
    static bool confirm(const std::string& message);
    static void printTable(const std::vector<std::vector<std::string>>& rows);
    static void printJson(const std::string& json);
    static std::string formatDuration(uint64_t seconds);
    static std::string formatTimestamp(uint64_t timestamp);
};

} // namespace secreg

#endif // SECREG_CLI_H
