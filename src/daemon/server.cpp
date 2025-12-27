/**
 * @file server.cpp
 * @brief Server implementation for SecReg-Linux
 * @author SecReg Security Team
 * @version 1.0.0
 */

#include "server.h"
#include "constants.h"
#include "utils.h"
#include <iostream>
#include <chrono>
#include <thread>

namespace secreg {

// UnixServer implementation

UnixServer::UnixServer(const ServerConfig& config)
    : config_(config) {}

UnixServer::~UnixServer() {
    stop();
}

bool UnixServer::start() {
    if (running_) {
        return true;
    }
    
    // Create socket
    serverSocket_ = socket(AF_UNIX, SOCK_STREAM, 0);
    if (serverSocket_ < 0) {
        std::cerr << "Failed to create socket" << std::endl;
        return false;
    }
    
    // Remove existing socket file
    unlink(config_.socketPath.c_str());
    
    // Set socket options
    int opt = 1;
    setsockopt(serverSocket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    // Bind
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, config_.socketPath.c_str(), 
            sizeof(addr.sun_path) - 1);
    
    if (bind(serverSocket_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "Failed to bind socket" << std::endl;
        close(serverSocket_);
        return false;
    }
    
    // Set permissions
    chmod(config_.socketPath.c_str(), 0666);
    
    // Listen
    if (listen(serverSocket_, config_.backlog) < 0) {
        std::cerr << "Failed to listen" << std::endl;
        close(serverSocket_);
        return false;
    }
    
    running_ = true;
    acceptThread_ = std::thread(&UnixServer::acceptLoop, this);
    
    return true;
}

bool UnixServer::stop() {
    if (!running_) {
        return true;
    }
    
    running_ = false;
    
    // Close server socket
    if (serverSocket_ >= 0) {
        close(serverSocket_);
        serverSocket_ = -1;
    }
    
    // Remove socket file
    unlink(config_.socketPath.c_str());
    
    // Wait for accept thread
    if (acceptThread_.joinable()) {
        acceptThread_.join();
    }
    
    return true;
}

bool UnixServer::isRunning() const {
    return running_;
}

void UnixServer::setConnectionHandler(std::shared_ptr<IConnectionHandler> handler) {
    connectionHandler_ = handler;
}

void UnixServer::acceptLoop() {
    while (running_) {
        struct sockaddr_un addr;
        socklen_t addrLen = sizeof(addr);
        
        int clientSocket = accept(serverSocket_, 
                                   (struct sockaddr*)&addr, &addrLen);
        
        if (clientSocket < 0) {
            if (running_) {
                std::cerr << "Accept failed" << std::endl;
            }
            break;
        }
        
        std::string remoteAddress = addr.sun_path;
        if (remoteAddress.empty()) {
            remoteAddress = "localhost";
        }
        
        std::thread clientThread(&UnixServer::handleClient, this, 
                                  clientSocket);
        clientThread.detach();
    }
}

void UnixServer::handleClient(int clientSocket) {
    std::string remoteAddress = readClientInfo(clientSocket);
    
    if (connectionHandler_) {
        connectionHandler_->handleConnection(clientSocket, remoteAddress);
    }
    
    // Handle client messages in a loop
    std::vector<uint8_t> buffer(4096);
    
    while (true) {
        ssize_t bytesRead = read(clientSocket, buffer.data(), buffer.size());
        
        if (bytesRead <= 0) {
            break;
        }
        
        std::vector<uint8_t> data(buffer.begin(), 
                                   buffer.begin() + bytesRead);
        
        try {
            Message message = Message::deserialize(data);
            
            ProtocolHandler handler(*connectionHandler_);
            handler.handleMessage(clientSocket, message);
        } catch (const std::exception& e) {
            std::cerr << "Error handling message: " << e.what() << std::endl;
            break;
        }
    }
    
    if (connectionHandler_) {
        connectionHandler_->handleDisconnect(clientSocket);
    }
    
    close(clientSocket);
}

std::string UnixServer::readClientInfo(int clientSocket) {
    struct sockaddr_un addr;
    socklen_t addrLen = sizeof(addr);
    
    if (getpeername(clientSocket, (struct sockaddr*)&addr, &addrLen) < 0) {
        return "localhost";
    }
    
    return std::string(addr.sun_path);
}

// Message implementation

std::vector<uint8_t> Message::serialize() const {
    std::vector<uint8_t> data;
    
    // Write type (1 byte)
    data.push_back(static_cast<uint8_t>(type));
    
    // Write timestamp (8 bytes)
    uint64_t ts = timestamp;
    for (int i = 7; i >= 0; --i) {
        data.push_back(static_cast<uint8_t>((ts >> (i * 8)) & 0xFF));
    }
    
    // Write session ID length (1 byte) and session ID
    uint8_t sessionLen = static_cast<uint8_t>(
        std::min(sessionId.size(), static_cast<size_t>(255)));
    data.push_back(sessionLen);
    data.insert(data.end(), sessionId.begin(), 
                sessionId.begin() + sessionLen);
    
    // Write payload length (4 bytes)
    uint32_t payloadLen = static_cast<uint32_t>(payload.size());
    for (int i = 3; i >= 0; --i) {
        data.push_back(static_cast<uint8_t>((payloadLen >> (i * 8)) & 0xFF));
    }
    
    // Write payload
    data.insert(data.end(), payload.begin(), payload.end());
    
    return data;
}

Message Message::deserialize(const std::vector<uint8_t>& data) {
    if (data.size() < 14) {
        throw std::runtime_error("Invalid message format");
    }
    
    Message message;
    
    size_t offset = 0;
    
    // Read type
    message.type = static_cast<MessageType>(data[offset++]);
    
    // Read timestamp
    message.timestamp = 0;
    for (int i = 0; i < 8; ++i) {
        message.timestamp = (message.timestamp << 8) | data[offset++];
    }
    
    // Read session ID
    uint8_t sessionLen = data[offset++];
    message.sessionId = std::string(
        reinterpret_cast<const char*>(&data[offset]), sessionLen);
    offset += sessionLen;
    
    // Read payload length
    uint32_t payloadLen = 0;
    for (int i = 0; i < 4; ++i) {
        payloadLen = (payloadLen << 8) | data[offset++];
    }
    
    // Read payload
    if (offset + payloadLen != data.size()) {
        throw std::runtime_error("Invalid payload length");
    }
    
    message.payload = std::vector<uint8_t>(
        data.begin() + offset, data.end());
    
    return message;
}

// ProtocolHandler implementation

ProtocolHandler::ProtocolHandler(IConnectionHandler& connectionHandler)
    : connectionHandler_(connectionHandler) {}

void ProtocolHandler::handleMessage(int clientSocket, const Message& message) {
    switch (message.type) {
        case MessageType::AuthRequest:
            handleAuth(clientSocket, message);
            break;
        case MessageType::GetRequest:
            handleGet(clientSocket, message);
            break;
        case MessageType::SetRequest:
            handleSet(clientSocket, message);
            break;
        case MessageType::DeleteRequest:
            handleDelete(clientSocket, message);
            break;
        case MessageType::ListRequest:
            handleList(clientSocket, message);
            break;
        default:
            sendError(clientSocket, -1, "Unknown message type");
            break;
    }
}

void ProtocolHandler::sendResponse(int clientSocket, const Message& response) {
    std::vector<uint8_t> data = response.serialize();
    write(clientSocket, data.data(), data.size());
}

void ProtocolHandler::handleAuth(int clientSocket, const Message& message) {
    // Authentication handling would go here
    sendSuccess(clientSocket, MessageType::AuthResponse, 
                std::vector<uint8_t>{1});
}

void ProtocolHandler::handleGet(int clientSocket, const Message& message) {
    // Get handling would go here
    sendSuccess(clientSocket, MessageType::GetResponse, 
                std::vector<uint8_t>{});
}

void ProtocolHandler::handleSet(int clientSocket, const Message& message) {
    // Set handling would go here
    sendSuccess(clientSocket, MessageType::SetResponse, 
                std::vector<uint8_t>{1});
}

void ProtocolHandler::handleDelete(int clientSocket, const Message& message) {
    // Delete handling would go here
    sendSuccess(clientSocket, MessageType::DeleteResponse, 
                std::vector<uint8_t>{1});
}

void ProtocolHandler::handleList(int clientSocket, const Message& message) {
    // List handling would go here
    sendSuccess(clientSocket, MessageType::ListResponse, 
                std::vector<uint8_t>{});
}

void ProtocolHandler::sendError(int clientSocket, int errorCode, 
                                 const std::string& message) {
    std::vector<uint8_t> payload;
    payload.push_back(static_cast<uint8_t>(errorCode & 0xFF));
    payload.insert(payload.end(), message.begin(), message.end());
    
    Message response(MessageType::ErrorResponse, payload);
    sendResponse(clientSocket, response);
}

void ProtocolHandler::sendSuccess(int clientSocket, MessageType responseType,
                                   const std::vector<uint8_t>& data) {
    Message response(responseType, data);
    sendResponse(clientSocket, response);
}

// ServerSessionManager implementation

std::string ServerSessionManager::createSession(const Session& session) {
    std::string sessionId = generateUuid();
    
    std::unique_lock lock(mutex_);
    sessions_[sessionId] = session;
    
    return sessionId;
}

std::optional<Session> ServerSessionManager::getSession(const std::string& sessionId) {
    std::shared_lock lock(mutex_);
    
    auto it = sessions_.find(sessionId);
    if (it != sessions_.end()) {
        return it->second;
    }
    
    return std::nullopt;
}

bool ServerSessionManager::validateSession(const std::string& sessionId) {
    auto session = getSession(sessionId);
    return session.has_value() && session->isValid();
}

void ServerSessionManager::refreshSession(const std::string& sessionId) {
    std::unique_lock lock(mutex_);
    
    auto it = sessions_.find(sessionId);
    if (it != sessions_.end()) {
        it->second.last_activity = getCurrentTimestampSeconds();
    }
}

void ServerSessionManager::revokeSession(const std::string& sessionId) {
    std::unique_lock lock(mutex_);
    sessions_.erase(sessionId);
}

void ServerSessionManager::revokeAllUserSessions(uint32_t userId) {
    std::unique_lock lock(mutex_);
    
    for (auto it = sessions_.begin(); it != sessions_.end(); ) {
        if (it->second.user_id == userId) {
            it = sessions_.erase(it);
        } else {
            ++it;
        }
    }
}

void ServerSessionManager::cleanupExpiredSessions() {
    uint64_t now = getCurrentTimestampSeconds();
    
    std::unique_lock lock(mutex_);
    
    for (auto it = sessions_.begin(); it != sessions_.end(); ) {
        if (it->second.expires_at < now) {
            it = sessions_.erase(it);
        } else {
            ++it;
        }
    }
}

} // namespace secreg
