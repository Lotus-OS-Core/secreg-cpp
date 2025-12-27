> **[!]** this is not latest release

# SecReg-Linux

Secure Linux Registry System - A centralized, secure configuration management solution for Linux.\
**LINUX Distro: LotusOS-Core**

## Overview

SecReg-Linux is inspired by the Windows Registry but designed with modern security principles for Linux systems. It provides a hierarchical, encrypted database for storing system and application configurations with strong access controls and comprehensive audit logging.

## Features

- **Hierarchical Key Structure**: Organize configurations in a logical tree structure
- **Strong Encryption**: XChaCha20-Poly1305 for authenticated encryption
- **Access Control**: Role-based access control (RBAC) with ACL support
- **Audit Logging**: Tamper-evident audit trail with hash chaining
- **PAM Integration**: Authenticate using system credentials
- **Secure Key Management**: Password-based key derivation with PBKDF2

## Quick Start

### Installation

```bash
# Build from source
mkdir build && cd build
cmake ..
make
sudo make install

# Start the daemon
sudo systemctl enable secreg
sudo systemctl start secreg

# Initialize the registry
sreg init
```

### Basic Usage

```bash
# Set a configuration value
sreg set /app/database/host localhost
sreg set /app/database/port 5432 --type integer

# Get a configuration value
sreg get /app/database/host

# List configuration keys
sreg list /app/

# Set a sensitive value (encrypted)
sreg set /app/database/password "secret123" --encrypt
```

## Architecture

### Components

- **secregd**: The daemon process that manages the registry database
- **sreg**: Command-line interface for interacting with the registry
- **libsecreg**: Shared library for programmatic access
- **pam_secreg**: PAM module for authentication

### Directory Structure

```
/var/lib/secreg/          # Database files
/run/secreg/              # Socket files
/etc/secreg/              # Configuration files
/var/log/secreg/          # Audit logs
```

## Security Model

### Encryption

All data at rest is encrypted using XChaCha20-Poly1305 with keys derived from a master password using PBKDF2-HMAC-SHA256 with 100,000 iterations.

### Authentication

- Local users authenticate via PAM
- Sessions are tracked with secure tokens
- Rate limiting protects against brute force attacks

### Authorization

- Role-based access control with predefined roles (admin, operator, auditor)
- Fine-grained ACLs on key paths
- Conditional access based on time, IP, and MFA status

### Audit Logging

All operations are logged to an immutable chain with cryptographic hashes for tamper detection.

## Documentation

- [Architecture](docs/ARCHITECTURE.md) - System architecture details
- [Security Model](docs/SECURITY.md) - Security features and guarantees
- [API Reference](docs/API.md) - API documentation
- [Configuration](docs/CONFIG.md) - Configuration options

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and code quality checks
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.\
This app is **as/is** release, using at your own knowledge/risks.

## Support

- GitHub Issues: Report bugs and request features
- Documentation: See the docs/ directory
- Security: Report security issues to security@lotuschain.org

## Acknowledgments

- OpenSSL for cryptographic primitives
- SQLite for the database engine
- The Linux community for inspiration
