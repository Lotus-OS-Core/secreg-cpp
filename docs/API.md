# API Reference

This document describes the API for SecReg-Linux.

## Protocol

The daemon communicates with clients via a custom protocol over Unix domain sockets.

### Message Format

```
┌──────────┬──────────────┬─────────────┬─────────────────┐
│  Type    │  Timestamp   │ Session ID  │    Payload      │
│ (1 byte) │  (8 bytes)   │ (1 byte +)  │    (variable)   │
└──────────┴──────────────┴─────────────┴─────────────────┘
```

### Message Types

| Type | Value | Description |
|------|-------|-------------|
| AuthRequest | 0x01 | Authentication request |
| AuthResponse | 0x02 | Authentication response |
| GetRequest | 0x03 | Get value request |
| GetResponse | 0x04 | Get value response |
| SetRequest | 0x05 | Set value request |
| SetResponse | 0x06 | Set value response |
| DeleteRequest | 0x07 | Delete value request |
| DeleteResponse | 0x08 | Delete value response |
| ListRequest | 0x09 | List keys request |
| ListResponse | 0x0A | List keys response |
| ErrorResponse | 0xFF | Error response |

### Authentication

```json
// AuthRequest
{
    "username": "string",
    "password": "string"
}

// AuthResponse
{
    "success": true,
    "session_id": "uuid",
    "roles": ["admin", "operator"]
}
```

### Key Operations

```json
// GetRequest
{
    "key": "/system/kernel/hostname",
    "decrypt": true
}

// GetResponse
{
    "value": "myhost",
    "type": "string",
    "encrypted": false
}

// SetRequest
{
    "key": "/app/config/setting",
    "value": "newvalue",
    "type": "string",
    "encrypt": false
}

// DeleteRequest
{
    "key": "/app/config/oldsetting"
}

// ListRequest
{
    "prefix": "/app/",
    "recursive": true
}

// ListResponse
{
    "keys": [
        "/app/config/setting1",
        "/app/config/setting2"
    ]
}
```

## C++ Library API

### Connecting to the Daemon

```cpp
#include <secreg/client.h>

secreg::Client client("/run/secreg/socket");
client.connect();
```

### Authentication

```cpp
secreg::AuthResult result = client.login("username", "password");
if (result.success) {
    std::string sessionId = result.sessionId;
}
```

### Registry Operations

```cpp
// Set a value
client.set("/app/config/database", "localhost", secreg::ValueType::String);

// Get a value
std::optional<std::string> value = client.get("/app/config/database");

// Delete a value
client.remove("/app/config/oldkey");

// List keys
std::vector<std::string> keys = client.list("/app/", true);
```

### Encrypted Values

```cpp
// Set encrypted value
client.set("/app/secret/api_key", "secret123", secreg::ValueType::String, true);

// Get decrypted value
auto value = client.get("/app/secret/api_key", true);
```

### Error Handling

```cpp
try {
    client.get("/nonexistent/key");
} catch (const secreg::KeyNotFoundException& e) {
    std::cerr << "Key not found: " << e.what() << std::endl;
} catch (const secreg::AccessDeniedException& e) {
    std::cerr << "Access denied: " << e.what() << std::endl;
} catch (const secreg::SecRegException& e) {
    std::cerr << "Error: " << e.what() << std::endl;
}
```

## CLI Commands

### sreg init

Initialize the registry.

```bash
sreg init [--force]
```

### sreg login

Authenticate with the registry.

```bash
sreg login <username>
```

### sreg get

Get a value from the registry.

```bash
sreg get <key> [--decrypt] [--json]
```

### sreg set

Set a value in the registry.

```bash
sreg set <key> <value> [--type <type>] [--encrypt]
```

Type can be: string, integer, boolean, json

### sreg delete

Delete a value from the registry.

```bash
sreg delete <key> [--recursive]
```

### sreg list

List keys in the registry.

```bash
sreg list <prefix> [--recursive] [--json]
```

### sreg audit

View audit logs.

```bash
sreg audit [--user <user>] [--key <key>] 
           [--action <action>] [--since <time>]
           [--limit <count>] [--json]
```

### sreg status

Show daemon status.

```bash
sreg status [--json]
```

### sreg export

Export registry data.

```bash
sreg export [--output <file>] [--encrypt]
```

### sreg import

Import registry data.

```bash
sreg import <file> [--decrypt] [--force]
```

## Configuration File

```toml
# /etc/secreg/config.toml

# Database configuration
[database]
path = "/var/lib/secreg"
cache_size = 67108864  # 64MB

# Socket configuration
[socket]
path = "/run/secreg/socket"
backlog = 128

# Session configuration
[session]
timeout = 3600  # 1 hour
max_per_user = 5

# Security configuration
[security]
require_mfa = false
rate_limit_attempts = 5
rate_limit_window = 300  # 5 minutes

# Audit configuration
[audit]
path = "/var/log/secreg"
retention_days = 90
async_write = true
```

## Return Codes

| Code | Name | Description |
|------|------|-------------|
| 0 | Success | Operation completed successfully |
| 1 | InvalidArgument | Invalid command arguments |
| 2 | NotFound | Key or resource not found |
| 3 | AccessDenied | Permission denied |
| 4 | AuthFailed | Authentication failed |
| 5 | AlreadyExists | Resource already exists |
| 6 | InvalidState | Invalid system state |
| 7 | DatabaseError | Database operation failed |
| 8 | CryptoError | Cryptographic operation failed |
