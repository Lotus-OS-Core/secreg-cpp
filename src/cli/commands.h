/**
 * @file commands.h
 * @brief CLI commands for SecReg-Linux
 * @author SecReg Security Team
 * @version 1.0.0
 */

#ifndef SECREG_COMMANDS_H
#define SECREG_COMMANDS_H

#include "cli.h"
#include "types.h"
#include <string>
#include <vector>

namespace secreg {

/**
 * @brief Base command class
 */
class CommandBase : public ICommand {
public:
    CommandBase(const std::string& name, const std::string& description);
    ~CommandBase() override = default;
    
    std::string getName() const override;
    std::string getDescription() const override;
    ICommand* clone() const override;
    
protected:
    std::string name_;
    std::string description_;
    CliConfig config_;
    
    virtual CommandResult executeInternal(const std::vector<std::string>& args) = 0;
    
    CommandResult execute(const std::vector<std::string>& args) override;
    
    void setConfig(const CliConfig& config);
    const CliConfig& getConfig() const;
    
    virtual void parseOptions(const std::vector<std::string>& args,
                              std::vector<std::string>& positional,
                              std::unordered_map<std::string, std::string>& options);
    
    std::string getRequiredArg(const std::vector<std::string>& args, size_t index);
    std::string getOptionalArg(const std::vector<std::string>& args, size_t index,
                                const std::string& defaultValue);
};

/**
 * @brief Init command - Initialize the registry
 */
class InitCommand : public CommandBase {
public:
    InitCommand();
    
    std::string getUsage() const override;
    CommandResult executeInternal(const std::vector<std::string>& args) override;
    
private:
    bool force_ = false;
    
    void parseOptions(const std::vector<std::string>& args,
                      std::vector<std::string>& positional,
                      std::unordered_map<std::string, std::string>& options) override;
};

/**
 * @brief Login command - Authenticate with the registry
 */
class LoginCommand : public CommandBase {
public:
    LoginCommand();
    
    std::string getUsage() const override;
    CommandResult executeInternal(const std::vector<std::string>& args) override;
};

/**
 * @brief Get command - Get a value from the registry
 */
class GetCommand : public CommandBase {
public:
    GetCommand();
    
    std::string getUsage() const override;
    CommandResult executeInternal(const std::vector<std::string>& args) override;
};

/**
 * @brief Set command - Set a value in the registry
 */
class SetCommand : public CommandBase {
public:
    SetCommand();
    
    std::string getUsage() const override;
    CommandResult executeInternal(const std::vector<std::string>& args) override;
};

/**
 * @brief Delete command - Delete a value from the registry
 */
class DeleteCommand : public CommandBase {
public:
    DeleteCommand();
    
    std::string getUsage() const override;
    CommandResult executeInternal(const std::vector<std::string>& args) override;
};

/**
 * @brief List command - List keys in the registry
 */
class ListCommand : public CommandBase {
public:
    ListCommand();
    
    std::string getUsage() const override;
    CommandResult executeInternal(const std::vector<std::string>& args) override;
};

/**
 * @brief Audit command - View audit logs
 */
class AuditCommand : public CommandBase {
public:
    AuditCommand();
    
    std::string getUsage() const override;
    CommandResult executeInternal(const std::vector<std::string>& args) override;
};

/**
 * @brief Status command - Show daemon status
 */
class StatusCommand : public CommandBase {
public:
    StatusCommand();
    
    std::string getUsage() const override;
    CommandResult executeInternal(const std::vector<std::string>& args) override;
};

/**
 * @brief Security command - Manage security settings
 */
class SecurityCommand : public CommandBase {
public:
    SecurityCommand();
    
    std::string getUsage() const override;
    CommandResult executeInternal(const std::vector<std::string>& args) override;
};

/**
 * @brief Export command - Export registry data
 */
class ExportCommand : public CommandBase {
public:
    ExportCommand();
    
    std::string getUsage() const override;
    CommandResult executeInternal(const std::vector<std::string>& args) override;
};

/**
 * @brief Import command - Import registry data
 */
class ImportCommand : public CommandBase {
public:
    ImportCommand();
    
    std::string getUsage() const override;
    CommandResult executeInternal(const std::vector<std::string>& args) override;
};

/**
 * @brief Command factory
 */
class CommandFactory {
public:
    static std::vector<std::unique_ptr<ICommand>> createCommands();
};

} // namespace secreg

#endif // SECREG_COMMANDS_H
