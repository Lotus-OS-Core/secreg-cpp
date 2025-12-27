/**
 * @file server.h
 * @brief Server implementation for SecReg-Linux
 * @author SecReg Security Team
 * @version 1.0.0
 */

#ifndef SECREG_SERVER_H
#define SECREG_SERVER_H

#include "types.h"
#include "errors.h"
#include <string>
#include <memory>
#include <functional>
#include <thread>
#include <atomic>
#include <unordered_map>
#include <sys/socket.h>
#include <sys/un.h>

namespace secreg {

/**
 * @brief Server configuration
 */
struct ServerConfig {
    std::string socketPath = "/run/secreg/socket";
    uint32_t backlog = NetworkConstants::DEFAULT_BACKLOG;
    uint32_t maxConnections = NetworkConstants::MAX_CONNECTIONS;
    uint64_t readTimeout = NetworkConstants::READ_TIMEOUT;
    uint64_t writeTimeout = NetworkConstants::WRITE_TIMEOUT;
};

/**
 * @brief Connection handler interface
 */
class IConnectionHandler {
public:
    virtual ~IConnectionHandler() = default;
    virtual void handleConnection(int clientSocket, 
                                   const std::string& remoteAddress) = 0;
    virtual void handleDisconnect(int clientSocket) = 0;
};

/**
 * @brief Unix domain socket server
 */
class UnixServer {
public:
    explicit UnixServer(const ServerConfig& config);
    ~UnixServer();
    
    bool start();
    bool stop();
    bool isRunning() const;
    
    void setConnectionHandler(std::shared_ptr<IConnectionHandler> handler);
    
private:
    ServerConfig config_;
    int serverSocket_ = -1;
    std::atomic<bool> running_{false};
    std::thread acceptThread_;
    std::shared_ptr<IConnectionHandler> connectionHandler_;
    
    void acceptLoop();
    void handleClient(int clientSocket);
    std::string readClientInfo(int clientSocket);
};

/**
 * @brief Message types for the protocol
 */
enum class MessageType {
    AuthRequest = 1,
    AuthResponse = 2,
    GetRequest = 3,
    GetResponse = 4,
    SetRequest = 5,
    SetResponse = 6,
    DeleteRequest = 7,
    DeleteResponse = 8,
    ListRequest = 9,
    ListResponse = 10,
    ErrorResponse = 255
};

/**
 * @brief Protocol message structure
 */
struct Message {
    MessageType type;
    std::vector<uint8_t> payload;
    uint64_t timestamp;
    std::string sessionId;
    
    Message() : type(MessageType::ErrorResponse), timestamp(0) {}
    Message(MessageType t, const std::vector<uint8_t>& p) 
        : type(t), payload(p), timestamp(getCurrentTimestamp()) {}
    
    std::vector<uint8_t> serialize() const;
    static Message deserialize(const std::vector<uint8_t>& data);
};

/**
 * @brief Protocol handler
 */
class ProtocolHandler {
public:
    explicit ProtocolHandler(IConnectionHandler& connectionHandler);
    
    void handleMessage(int clientSocket, const Message& message);
    void sendResponse(int clientSocket, const Message& response);

private:
    IConnectionHandler& connectionHandler_;
    
    void handleAuth(int clientSocket, const Message& message);
    void handleGet(int clientSocket, const Message& message);
    void handleSet(int clientSocket, const Message& message);
    void handleDelete(int clientSocket, const Message& message);
    void handleList(int clientSocket, const Message& message);
    
    void sendError(int clientSocket, int errorCode, const std::string& message);
    void sendSuccess(int clientSocket, MessageType responseType, 
                     const std::vector<uint8_t>& data);
};

/**
 * @brief Session manager for the server
 */
class ServerSessionManager {
public:
    std::string createSession(const Session& session);
    std::optional<Session> getSession(const std::string& sessionId);
    bool validateSession(const std::string& sessionId);
    void refreshSession(const std::string& sessionId);
    void revokeSession(const std::string& sessionId);
    void revokeAllUserSessions(uint32_t userId);
    void cleanupExpiredSessions();

private:
    std::unordered_map<std::string, Session> sessions_;
    mutable std::shared_mutex mutex_;
};

} // namespace secreg

#endif // SECREG_SERVER_H
