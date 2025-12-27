/**
 * @file main.cpp
 * @brief Main entry point for SecReg-Linux CLI
 * @author SecReg Security Team
 * @version 1.0.0
 */

#include "cli.h"
#include "commands.h"
#include "constants.h"
#include <iostream>
#include <getopt.h>

void printUsage(const char* programName) {
    std::cout << "Usage: " << programName << " [OPTIONS] <command> [arguments]" 
              << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -s, --socket <path>    Socket path (default: /run/secreg/socket)" 
              << std::endl;
    std::cout << "  -j, --json             Output in JSON format" << std::endl;
    std::cout << "  -v, --verbose          Enable verbose output" << std::endl;
    std::cout << "  -h, --help             Show this help message" << std::endl;
    std::cout << "  --version              Show version information" << std::endl;
    std::cout << std::endl;
    std::cout << "Commands:" << std::endl;
    std::cout << "  init                   Initialize the registry" << std::endl;
    std::cout << "  login                  Authenticate with the registry" << std::endl;
    std::cout << "  get                    Get a value from the registry" << std::endl;
    std::cout << "  set                    Set a value in the registry" << std::endl;
    std::cout << "  delete                 Delete a value from the registry" 
              << std::endl;
    std::cout << "  list                   List keys in the registry" << std::endl;
    std::cout << "  audit                  View audit logs" << std::endl;
    std::cout << "  status                 Show daemon status" << std::endl;
    std::cout << "  security               Manage security settings" << std::endl;
    std::cout << "  export                 Export registry data" << std::endl;
    std::cout << "  import                 Import registry data" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  " << programName << " get /system/kernel/hostname" << std::endl;
    std::cout << "  " << programName << " set /app/config/database_host localhost" 
              << std::endl;
    std::cout << "  " << programName << " list /app/ --recursive" << std::endl;
    std::cout << "  " << programName << " audit --since 1h" << std::endl;
}

void printVersion() {
    std::cout << AppConstants::APP_NAME << " v" << AppConstants::APP_VERSION 
              << std::endl;
    std::cout << AppConstants::APP_DESCRIPTION << std::endl;
    std::cout << "Author: " << AppConstants::APP_AUTHOR << std::endl;
}

int main(int argc, char* argv[]) {
    // Parse global options
    static const struct option longOptions[] = {
        {"socket", required_argument, nullptr, 's'},
        {"json", no_argument, nullptr, 'j'},
        {"verbose", no_argument, nullptr, 'v'},
        {"help", no_argument, nullptr, 'h'},
        {"version", no_argument, nullptr, 1},
        {nullptr, 0, nullptr, 0}
    };
    
    secreg::CliConfig config;
    bool jsonOutput = false;
    bool verbose = false;
    
    int opt;
    while ((opt = getopt_long(argc, argv, "s:jvh", longOptions, nullptr)) != -1) {
        switch (opt) {
            case 's':
                config.socketPath = optarg;
                break;
            case 'j':
                jsonOutput = true;
                break;
            case 'v':
                verbose = true;
                break;
            case 'h':
                printUsage(argv[0]);
                return 0;
            case 1:
                printVersion();
                return 0;
            default:
                printUsage(argv[0]);
                return 1;
        }
    }
    
    config.jsonOutput = jsonOutput;
    config.verbose = verbose;
    
    // Create CLI application
    secreg::CliApp app(config);
    
    // Add commands
    auto commands = secreg::CommandFactory::createCommands();
    for (auto& cmd : commands) {
        app.addCommand(std::move(cmd));
    }
    
    // Set error callback
    app.setOnErrorCallback([](const std::string& error) {
        std::cerr << "Error: " << error << std::endl;
    });
    
    // Run command
    secreg::CommandResult result = app.run(argc, argv);
    
    return result.exitCode;
}
