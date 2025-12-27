/**
 * @file main.cpp
 * @brief Main entry point for SecReg-Linux daemon
 * @author SecReg Security Team
 * @version 1.0.0
 */

#include "daemon.h"
#include "constants.h"
#include "utils.h"
#include <iostream>
#include <csignal>
#include <unistd.h>
#include <sys/stat.h>
#include <getopt.h>

static std::atomic<bool> g_running{true};
static secreg::RegistryDaemon* g_daemon = nullptr;

void signalHandler(int sig) {
    std::cout << "Received signal " << sig << std::endl;
    g_running = false;
    
    if (g_daemon) {
        g_daemon->stop();
    }
}

void printUsage(const char* programName) {
    std::cout << "Usage: " << programName << " [OPTIONS]" << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -c, --config <file>     Configuration file path" << std::endl;
    std::cout << "  -d, --daemon            Run as daemon" << std::endl;
    std::cout << "  -i, --initialize        Initialize the registry" << std::endl;
    std::cout << "  -p, --password <pass>   Password for initialization" << std::endl;
    std::cout << "  -v, --verbose           Enable verbose output" << std::endl;
    std::cout << "  -h, --help              Show this help message" << std::endl;
    std::cout << "  --version               Show version information" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  " << programName << " --initialize --password mypass" << std::endl;
    std::cout << "  " << programName << " --daemon" << std::endl;
    std::cout << "  " << programName << " --config /etc/secreg/config.toml" << std::endl;
}

void printVersion() {
    std::cout << AppConstants::APP_NAME << " v" << AppConstants::APP_VERSION << std::endl;
    std::cout << AppConstants::APP_DESCRIPTION << std::endl;
    std::cout << "Author: " << AppConstants::APP_AUTHOR << std::endl;
}

int main(int argc, char* argv[]) {
    // Parse command line options
    static const struct option longOptions[] = {
        {"config", required_argument, nullptr, 'c'},
        {"daemon", no_argument, nullptr, 'd'},
        {"initialize", no_argument, nullptr, 'i'},
        {"password", required_argument, nullptr, 'p'},
        {"verbose", no_argument, nullptr, 'v'},
        {"help", no_argument, nullptr, 'h'},
        {"version", no_argument, nullptr, 1},
        {nullptr, 0, nullptr, 0}
    };
    
    std::string configPath = PathConstants::DEFAULT_CONFIG_PATH;
    bool runAsDaemon = false;
    bool doInitialize = false;
    std::string password;
    bool verbose = false;
    
    int opt;
    while ((opt = getopt_long(argc, argv, "c:dip:vh", longOptions, nullptr)) != -1) {
        switch (opt) {
            case 'c':
                configPath = optarg;
                break;
            case 'd':
                runAsDaemon = true;
                break;
            case 'i':
                doInitialize = true;
                break;
            case 'p':
                password = optarg;
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
    
    // Print version info
    if (verbose) {
        printVersion();
        std::cout << std::endl;
    }
    
    // Setup signal handlers
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    signal(SIGHUP, signalHandler);
    
    // Create daemon
    secreg::DaemonConfig config;
    config.configPath = configPath;
    
    g_daemon = new secreg::RegistryDaemon(config);
    
    // Initialize if requested
    if (doInitialize) {
        if (password.empty()) {
            std::cerr << "Error: Password required for initialization" << std::endl;
            return 1;
        }
        
        if (verbose) {
            std::cout << "Initializing registry..." << std::endl;
        }
        
        try {
            g_daemon->initialize(password);
            
            if (verbose) {
                std::cout << "Registry initialized successfully" << std::endl;
            }
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return 1;
        }
    }
    
    // Check if already initialized
    if (!g_daemon->isInitialized()) {
        std::cerr << "Error: Registry not initialized. Use --initialize." << std::endl;
        return 1;
    }
    
    // Run as daemon if requested
    if (runAsDaemon) {
        // Daemonize the process
        pid_t pid = fork();
        
        if (pid < 0) {
            std::cerr << "Error: Failed to fork daemon" << std::endl;
            return 1;
        }
        
        if (pid > 0) {
            // Parent process exits
            return 0;
        }
        
        // Child process becomes session leader
        setsid();
        
        // Change working directory
        chdir("/");
        
        // Close standard file descriptors
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
        
        // Redirect to /dev/null
        open("/dev/null", O_RDONLY);
        open("/dev/null", O_WRONLY);
        open("/dev/null", O_WRONLY);
    }
    
    if (verbose) {
        std::cout << "Starting " << AppConstants::APP_NAME << "..." << std::endl;
    }
    
    // Start daemon
    try {
        g_daemon->start();
        
        if (verbose) {
            std::cout << "Daemon started successfully" << std::endl;
            std::cout << g_daemon->getStatus() << std::endl;
        }
        
        // Wait for shutdown signal
        while (g_running) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        
        if (verbose) {
            std::cout << "Shutting down..." << std::endl;
        }
        
        g_daemon->stop();
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    delete g_daemon;
    
    if (verbose) {
        std::cout << "Daemon stopped" << std::endl;
    }
    
    return 0;
}
