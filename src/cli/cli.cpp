/**
 * @file cli.cpp
 * @brief Command-line interface implementation for SecReg-Linux
 * @author SecReg Security Team
 * @version 1.0.0
 */

#include "cli.h"
#include "constants.h"
#include "utils.h"
#include <iostream>
#include <fstream>
#include <termios.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

namespace secreg {

// CliApp implementation

CliApp::CliApp(const CliConfig& config) : config_(config) {}

CliApp::~CliApp() {
    commands_.clear();
}

void CliApp::addCommand(std::unique_ptr<ICommand> command) {
    commands_[command->getName()] = std::move(command);
}

CommandResult CliApp::run(int argc, char* argv[]) {
    if (argc < 2) {
        printHelp();
        return {false, "No command specified", "", 1};
    }
    
    std::string commandName = argv[1];
    
    if (commandName == "--help" || commandName == "-h") {
        printHelp();
        return {true, "Help displayed", "", 0};
    }
    
    if (commandName == "--version" || commandName == "-v") {
        printVersion();
        return {true, "Version displayed", "", 0};
    }
    
    // Find command
    auto command = findCommand(commandName);
    if (!command) {
        printError("Unknown command: " + commandName);
        printHelp();
        return {false, "Unknown command: " + commandName, "", 1};
    }
    
    // Collect arguments
    std::vector<std::string> args;
    for (int i = 2; i < argc; ++i) {
        args.push_back(argv[i]);
    }
    
    // Execute command
    try {
        return command->execute(args);
    } catch (const std::exception& e) {
        printError(e.what());
        return {false, e.what(), "", 1};
    }
}

void CliApp::setOnErrorCallback(std::function<void(const std::string&)> callback) {
    onErrorCallback_ = callback;
}

const CliConfig& CliApp::getConfig() const {
    return config_;
}

void CliApp::printHelp(const std::string& command) {
    std::cout << AppConstants::APP_NAME << " v" << AppConstants::APP_VERSION 
              << " - " << AppConstants::APP_DESCRIPTION << std::endl;
    std::cout << std::endl;
    
    if (!command.empty()) {
        // Print help for specific command
        auto cmd = findCommand(command);
        if (cmd) {
            std::cout << "Usage: " << CliConstants::PROG_NAME << " " 
                      << cmd->getName() << " " << cmd->getUsage() << std::endl;
            std::cout << std::endl;
            std::cout << cmd->getDescription() << std::endl;
            return;
        }
    }
    
    std::cout << "Usage: " << CliConstants::PROG_NAME << " <command> [options]" 
              << std::endl;
    std::cout << std::endl;
    std::cout << "Commands:" << std::endl;
    
    for (const auto& [name, command] : commands_) {
        std::cout << "  " << name << std::endl;
    }
    
    std::cout << std::endl;
    std::cout << "Use '" << CliConstants::PROG_NAME << " <command> --help' for "
              << "more information about a command." << std::endl;
}

void CliApp::printVersion() {
    std::cout << AppConstants::APP_NAME << " v" << AppConstants::APP_VERSION 
              << std::endl;
    std::cout << AppConstants::APP_DESCRIPTION << std::endl;
}

void CliApp::printError(const std::string& message) {
    std::cerr << "Error: " << message << std::endl;
    
    if (onErrorCallback_) {
        onErrorCallback_(message);
    }
}

std::unique_ptr<ICommand> CliApp::findCommand(const std::string& name) {
    auto it = commands_.find(name);
    if (it != commands_.end()) {
        return std::unique_ptr<ICommand>(it->second->clone());
    }
    return nullptr;
}

// CliConnection implementation

CliConnection::CliConnection(const std::string& socketPath)
    : socketPath_(socketPath) {}

CliConnection::~CliConnection() {
    disconnect();
}

bool CliConnection::connect() {
    socket_ = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socket_ < 0) {
        return false;
    }
    
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socketPath_.c_str(), 
            sizeof(addr.sun_path) - 1);
    
    if (connect(socket_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(socket_);
        socket_ = -1;
        return false;
    }
    
    return true;
}

void CliConnection::disconnect() {
    if (socket_ >= 0) {
        close(socket_);
        socket_ = -1;
    }
}

bool CliConnection::isConnected() const {
    return socket_ >= 0;
}

CommandResult CliConnection::sendRequest(const std::vector<uint8_t>& data) {
    if (!isConnected()) {
        return {false, "Not connected to daemon", "", 1};
    }
    
    // Send request
    if (!write(data.data(), data.size())) {
        return {false, "Failed to send request", "", 1};
    }
    
    // Read response
    auto response = read();
    if (response.empty()) {
        return {false, "Failed to read response", "", 1};
    }
    
    return {true, "", std::string(response.begin(), response.end()), 0};
}

bool CliConnection::write(const void* data, size_t size) {
    ssize_t sent = 0;
    while (sent < static_cast<ssize_t>(size)) {
        ssize_t n = ::write(socket_, 
                           static_cast<const char*>(data) + sent, 
                           size - sent);
        if (n <= 0) {
            return false;
        }
        sent += n;
    }
    return true;
}

std::vector<uint8_t> CliConnection::read() {
    std::vector<uint8_t> buffer;
    buffer.resize(4096);
    
    ssize_t n = ::read(socket_, buffer.data(), buffer.size());
    if (n <= 0) {
        return {};
    }
    
    buffer.resize(n);
    return buffer;
}

// CliUtils implementation

std::string CliUtils::getPassword() {
    struct termios oldt, newt;
    std::string password;
    
    // Disable echo
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    
    std::getline(std::cin, password);
    
    // Restore echo
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    
    return password;
}

bool CliUtils::confirm(const std::string& message) {
    std::cout << message << " [y/N]: ";
    std::cout.flush();
    
    std::string response;
    std::getline(std::cin, response);
    
    return response == "y" || response == "Y";
}

void CliUtils::printTable(const std::vector<std::vector<std::string>>& rows) {
    if (rows.empty()) {
        return;
    }
    
    // Calculate column widths
    std::vector<size_t> widths;
    for (size_t col = 0; col < rows[0].size(); ++col) {
        size_t width = 0;
        for (const auto& row : rows) {
            if (col < row.size() && row[col].length() > width) {
                width = row[col].length();
            }
        }
        widths.push_back(width + 2);
    }
    
    // Print rows
    for (const auto& row : rows) {
        for (size_t col = 0; col < row.size(); ++col) {
            std::cout << std::left << std::setw(widths[col]) << row[col];
        }
        std::cout << std::endl;
    }
}

void CliUtils::printJson(const std::string& json) {
    std::cout << json << std::endl;
}

std::string CliUtils::formatDuration(uint64_t seconds) {
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

std::string CliUtils::formatTimestamp(uint64_t timestamp) {
    auto time = std::chrono::system_clock::from_time_t(timestamp);
    auto timeStr = std::chrono::system_clock::to_time_t(time);
    
    std::tm* tm = std::localtime(&timeStr);
    char buffer[64];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tm);
    
    return std::string(buffer);
}

} // namespace secreg
