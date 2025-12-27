# Architecture

This document describes the architecture of SecReg-Linux, a secure configuration management system for Linux.

## System Overview

SecReg-Linux consists of several components that work together to provide a secure, centralized configuration database:

```
┌─────────────────────────────────────────────────────────────┐
│                      Client Applications                    │
│                    (sreg CLI, libraries)                    │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      Unix Domain Socket                     │
│                    (/run/secreg/socket)                     │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│                     secregd (Daemon)                         │
│  ┌─────────────┐  ┌────────────┐  ┌────────────────────────┐ │
│  │  Auth Mgr   │  │  ACL Mgr   │  │   Storage Engine       │ │
│  └─────────────┘  └────────────┘  └────────────────────────┘ │
│  ┌─────────────┐  ┌────────────┐  ┌────────────────────────┐ │
│  │ Audit Logger│  │ Crypto Mgr │  │   Session Manager      │ │
│  └─────────────┘  └────────────┘  └────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│                    SQLite Database                           │
│              (/var/lib/secreg/registry.db)                   │
│  ┌─────────────┐  ┌────────────┐  ┌────────────────────────┐ │
│  │   Entries   │  │   Audit    │  │   ACLs                 │ │
│  │   Table     │  │   Table    │  │   Table                │ │
│  └─────────────┘  └────────────┘  └────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

## Components

### Daemon (secregd)

The daemon is the core service that manages the registry database. It:

- Listens on a Unix domain socket for client connections
- Handles authentication via PAM
- Enforces access control policies
- Manages the encrypted database
- Logs all operations to the audit trail

### Storage Engine

The storage engine uses SQLite as the backend database with:

- **WAL mode** for concurrent read access
- **Encrypted fields** for sensitive data
- **Transactional updates** for atomic operations
- **Indexing** for efficient key lookups

### Crypto Manager

The crypto manager provides:

- **XChaCha20-Poly1305** authenticated encryption
- **PBKDF2** key derivation from passwords
- **HKDF** for key diversification
- **SHA-256** hashing for integrity

### Authentication Manager

Handles user authentication through:

- PAM integration for system credentials
- Session token management
- Rate limiting for brute force protection

### ACL Manager

Manages access control with:

- Role-based permissions (admin, operator, auditor)
- Path-based ACL inheritance
- Conditional access rules

### Audit Logger

Provides tamper-evident logging with:

- Hash chaining for integrity verification
- Configurable retention policies
- Structured query capabilities

## Key Structure

The registry uses a hierarchical key structure similar to a filesystem:

```
/registry
├── system/
│   ├── kernel/
│   │   ├── hostname
│   │   └── version
│   ├── network/
│   │   └── hostname
│   └── services/
│       └── sshd/
├── user/
│   └── <username>/
├── security/
│   ├── firewall/
│   └── audit/
└── applications/
    └── <appname>/
        └── config/
```

## Security Architecture

### Defense in Depth

SecReg-Linux implements multiple layers of security:

1. **Network Layer**: Unix domain socket with permissions
2. **Authentication Layer**: PAM integration with session tokens
3. **Authorization Layer**: RBAC with ACLs
4. **Encryption Layer**: Field-level encryption with derived keys
5. **Audit Layer**: Cryptographically chained audit logs

### Trust Model

The system assumes:

- The root user is trusted but audited
- Data at rest is protected by encryption
- Access is denied by default (zero trust)
- All operations leave an audit trail

## Performance Considerations

### Concurrency

- SQLite WAL mode allows concurrent reads
- Write operations are serialized
- Session management is thread-safe

### Scalability

- Suitable for single-server deployments
- Not designed for distributed configurations
- Consider etcd/ZooKeeper for clustered environments

## Failure Modes

### Recovery

- Corrupted databases can be restored from backups
- Master key recovery requires the password
- Audit logs can be verified for tampering

### Availability

- Daemon can be restarted without data loss
- Database recovery is automatic on startup
- Session recovery requires re-authentication
