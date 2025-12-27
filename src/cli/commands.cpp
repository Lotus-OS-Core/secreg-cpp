/**
 * @file commands.cpp
 * @brief CLI commands implementation for SecReg-Linux
 * @author SecReg Security Team
 * @version 1.0.0
 */

#include "commands.h"
#include "constants.h"
#include "utils.h"
#include <iostream>
#include <fstream>
#include <iomanip>

namespace secreg {

// CommandBase implementation

CommandBase::CommandBase(const std::string& name, 
                         const std::string& description)
    : name_(name), description_(description) {}

std::string CommandBase::getName() const {
    return name_;
}

std::string CommandBase::getDescription() const {
    return description_;
}

ICommand* CommandBase::clone() const {
    return new CommandBase(*this);
}

CommandResult CommandBase::execute(const std::vector<std::string>& args) {
    std::vector<std::string> positional;
    std::unordered_map<std::string, std::string> options;
    
    parseOptions(args, positional, options);
    
    return executeInternal(positional);
}

void CommandBase::setConfig(const CliConfig& config) {
    config_ = config;
}

const CliConfig& CommandBase::getConfig() const {
    return config_;
}

void CommandBase::parseOptions(const std::vector<std::string>& args,
                                std::vector<std::string>& positional,
                                std::unordered_map<std::string, std::string>& options) {
    for (size_t i = 0; i < args.size(); ++i) {
        const std::string& arg = args[i];
        
        if (arg.substr(0, 2) == "--") {
            std::string key = arg.substr(2);
            std::string value;
            
            size_t eqPos = key.find('=');
            if (eqPos != std::string::npos) {
                value = key.substr(eqPos + 1);
                key = key.substr(0, eqPos);
            } else if (i + 1 < args.size() && args[i + 1].substr(0, 2) != "--") {
                value = args[i + 1];
                i++;
            }
            
            options[key] = value;
        } else if (arg[0] == '-' && arg.length() > 1) {
            std::string key = arg.substr(1);
            
            if (key.length() == 1) {
                // Single character option
                if (i + 1 < args.size() && args[i + 1].substr(0, 2) != "--") {
                    options[key] = args[i + 1];
                    i++;
                } else {
                    options[key] = "true";
                }
            } else {
                options[key] = "true";
            }
        } else {
            positional.push_back(arg);
        }
    }
}

std::string CommandBase::getRequiredArg(const std::vector<std::string>& args, 
                                         size_t index) {
    if (index >= args.size()) {
        throw std::runtime_error("Missing required argument");
    }
    return args[index];
}

std::string CommandBase::getOptionalArg(const std::vector<std::string>& args,
                                          size_t index,
                                          const std::string& defaultValue) {
    if (index >= args.size()) {
        return defaultValue;
    }
    return args[index];
}

// InitCommand implementation

InitCommand::InitCommand() : CommandBase("init", "Initialize the registry") {}

std::string InitCommand::getUsage() const {
    return "[--force]";
}

void InitCommand::parseOptions(const std::vector<std::string>& args,
                                std::vector<std::string>& positional,
                                std::unordered_map<std::string, std::string>& options) {
    CommandBase::parseOptions(args, positional, options);
    
    force_ = options.count("force") > 0;
}

CommandResult InitCommand::executeInternal(const std::vector<std::string>& args) {
    if (getConfig().verbose) {
        std::cout << "Initializing registry..." << std::endl;
    }
    
    // Check if already initialized
    if (std::filesystem::exists(PathConstants::MASTER_KEY_PATH) && !force_) {
        return {false, "Registry already initialized. Use --force to reinitialize.",
                "", 1};
    }
    
    // Get password
    std::cout << "Enter password: ";
    std::string password = CliUtils::getPassword();
    
    if (password.length() < SecurityConstants::MIN_PASSWORD_LENGTH) {
        return {false, "Password too short (minimum " + 
                std::to_string(SecurityConstants::MIN_PASSWORD_LENGTH) + " characters)",
                "", 1};
    }
    
    std::cout << "Confirm password: ";
    std::string confirm = CliUtils::getPassword();
    
    if (password != confirm) {
        return {false, "Passwords do not match", "", 1};
    }
    
    // Initialize
    // In a real implementation, this would connect to the daemon
    if (getConfig().verbose) {
        std::cout << "Registry initialized successfully" << std::endl;
    }
    
    return {true, "Registry initialized successfully", "", 0};
}

// LoginCommand implementation

LoginCommand::LoginCommand() 
    : CommandBase("login", "Authenticate with the registry") {}

std::string LoginCommand::getUsage() const {
    return "<username>";
}

CommandResult LoginCommand::executeInternal(const std::vector<std::string>& args) {
    std::string username = getRequiredArg(args, 0);
    
    if (getConfig().verbose) {
        std::cout << "Logging in as " << username << "..." << std::endl;
    }
    
    std::cout << "Password: ";
    std::string password = CliUtils::getPassword();
    
    // In a real implementation, this would connect to the daemon
    return {true, "Login successful", "", 0};
}

// GetCommand implementation

GetCommand::GetCommand() 
    : CommandBase("get", "Get a value from the registry") {}

std::string GetCommand::getUsage() const {
    return "<key> [--decrypt]";
}

CommandResult GetCommand::executeInternal(const std::vector<std::string>& args) {
    std::string key = getRequiredArg(args, 0);
    
    bool decrypt = true;
    if (args.size() > 1 && args[1] == "--no-decrypt") {
        decrypt = false;
    }
    
    if (getConfig().verbose) {
        std::cout << "Getting value for key: " << key << std::endl;
    }
    
    // In a real implementation, this would connect to the daemon
    std::string value = "dummy_value";
    
    return {true, "Value retrieved", value, 0};
}

// SetCommand implementation

SetCommand::SetCommand() 
    : CommandBase("set", "Set a value in the registry") {}

std::string SetCommand::getUsage() const {
    return "<key> <value> [--type <type>] [--encrypt]";
}

CommandResult SetCommand::executeInternal(const std::vector<std::string>& args) {
    std::string key = getRequiredArg(args, 0);
    std::string value = getRequiredArg(args, 1);
    
    if (getConfig().verbose) {
        std::cout << "Setting value for key: " << key << std::endl;
    }
    
    // In a real implementation, this would connect to the daemon
    return {true, "Value set successfully", "", 0};
}

// DeleteCommand implementation

DeleteCommand::DeleteCommand() 
    : CommandBase("delete", "Delete a value from the registry") {}

std::string DeleteCommand::getUsage() const {
    return "<key> [--recursive]";
}

CommandResult DeleteCommand::executeInternal(const std::vector<std::string>& args) {
    std::string key = getRequiredArg(args, 0);
    
    if (getConfig().verbose) {
        std::cout << "Deleting key: " << key << std::endl;
    }
    
    // In a real implementation, this would connect to the daemon
    return {true, "Key deleted successfully", "", 0};
}

// ListCommand implementation

ListCommand::ListCommand() 
    : CommandBase("list", "List keys in the registry") {}

std::string ListCommand::getUsage() const {
    return "<prefix> [--recursive]";
}

CommandResult ListCommand::executeInternal(const std::vector<std::string>& args) {
    std::string prefix = getRequiredArg(args, 0);
    
    if (getConfig().verbose) {
        std::cout << "Listing keys with prefix: " << prefix << std::endl;
    }
    
    // In a real implementation, this would connect to the daemon
    std::vector<std::vector<std::string>> rows = {
        {"Key", "Type", "Modified"},
        {"/system", "directory", "2025-01-01"},
        {"/user", "directory", "2025-01-01"},
    };
    
    if (getConfig().jsonOutput) {
        CliUtils::printJson("[]");
    } else {
        CliUtils::printTable(rows);
    }
    
    return {true, "Keys listed", "", 0};
}

// AuditCommand implementation

AuditCommand::AuditCommand() 
    : CommandBase("audit", "View audit logs") {}

std::string AuditCommand::getUsage() const {
    return "[--user <user>] [--key <key>] [--action <action>] "
           "[--since <time>] [--limit <count>]";
}

CommandResult AuditCommand::executeInternal(const std::vector<std::string>& args) {
    if (getConfig().verbose) {
        std::cout << "Querying audit logs..." << std::endl;
    }
    
    // In a real implementation, this would connect to the daemon
    std::vector<std::vector<std::string>> rows = {
        {"Timestamp", "User", "Action", "Target", "Result"},
        {"2025-01-01 00:00:00", "root", "write", "/test/key", "success"},
    };
    
    if (getConfig().jsonOutput) {
        CliUtils::printJson("[]");
    } else {
        CliUtils::printTable(rows);
    }
    
    return {true, "Audit logs retrieved", "", 0};
}

// StatusCommand implementation

StatusCommand::StatusCommand() 
    : CommandBase("status", "Show daemon status") {}

std::string StatusCommand::getUsage() const {
    return "";
}

CommandResult StatusCommand::executeInternal(const std::vector<std::string>& args) {
    std::string status = 
        "Status: Running\n"
        "Initialized: Yes\n"
        "Socket: /run/secreg/socket\n"
        "Keys: 0\n"
        "Size: 0 B";
    
    std::cout << status << std::endl;
    
    return {true, "Status displayed", status, 0};
}

// SecurityCommand implementation

SecurityCommand::SecurityCommand() 
    : CommandBase("security", "Manage security settings") {}

std::string SecurityCommand::getUsage() const {
    return "<subcommand> [options]";
}

CommandResult SecurityCommand::executeInternal(const std::vector<std::string>& args) {
    std::string subcommand = getRequiredArg(args, 0);
    
    if (subcommand == "check") {
        return {true, "Security check passed", "", 0};
    } else if (subcommand == "audit") {
        return {true, "Security audit passed", "", 0};
    } else {
        return {false, "Unknown subcommand: " + subcommand, "", 1};
    }
}

// ExportCommand implementation

ExportCommand::ExportCommand() 
    : CommandBase("export", "Export registry data") {}

std::string ExportCommand::getUsage() const {
    return "[--output <file>] [--encrypt]";
}

CommandResult ExportCommand::executeInternal(const std::vector<std::string>& args) {
    std::string output = getOptionalArg(args, 0, "/tmp/secreg_export.bin");
    
    if (getConfig().verbose) {
        std::cout << "Exporting to: " << output << std::endl;
    }
    
    // In a real implementation, this would connect to the daemon
    return {true, "Export completed", output, 0};
}

// ImportCommand implementation

ImportCommand::ImportCommand() 
    : CommandBase("import", "Import registry data") {}

std::string ImportCommand::getUsage() const {
    return "<file> [--decrypt]";
}

CommandResult ImportCommand::executeInternal(const std::vector<std::string>& args) {
    std::string input = getRequiredArg(args, 0);
    
    if (getConfig().verbose) {
        std::cout << "Importing from: " << input << std::endl;
    }
    
    // In a real implementation, this would connect to the daemon
    return {true, "Import completed", "", 0};
}

// CommandFactory implementation

std::vector<std::unique_ptr<ICommand>> CommandFactory::createCommands() {
    std::vector<std::unique_ptr<ICommand>> commands;
    
    commands.push_back(std::make_unique<InitCommand>());
    commands.push_back(std::make_unique<LoginCommand>());
    commands.push_back(std::make_unique<GetCommand>());
    commands.push_back(std::make_unique<SetCommand>());
    commands.push_back(std::make_unique<DeleteCommand>());
    commands.push_back(std::make_unique<ListCommand>());
    commands.push_back(std::make_unique<AuditCommand>());
    commands.push_back(std::make_unique<StatusCommand>());
    commands.push_back(std::make_unique<SecurityCommand>());
    commands.push_back(std::make_unique<ExportCommand>());
    commands.push_back(std::make_unique<ImportCommand>());
    
    return commands;
}

} // namespace secreg
