# Security Model

This document describes the security features and guarantees of SecReg-Linux.

## Cryptographic Specifications

### Encryption

**Algorithm**: XChaCha20-Poly1305 (IETF variant)

- **Key Size**: 256 bits (32 bytes)
- **Nonce Size**: 192 bits (24 bytes)
- **Tag Size**: 128 bits (16 bytes)

This provides:
- **Confidentiality**: Authenticated encryption prevents reading encrypted data
- **Integrity**: Modification of ciphertext is detected
- **Speed**: ChaCha20 is fast in software, no hardware acceleration required

### Key Derivation

**Algorithm**: PBKDF2-HMAC-SHA256

- **Iterations**: 100,000
- **Salt Size**: 256 bits (32 bytes)
- **Output Size**: 256 bits (32 bytes)

This provides:
- **Resistance to brute force**: High iteration count slows attacks
- **Unique keys**: Salt ensures different keys for same password

### Key Diversification

**Algorithm**: HKDF-SHA256

Used to derive different keys for:
- Field encryption
- HMAC signing
- Session tokens

### Hashing

**Algorithm**: SHA-256

Used for:
- Audit log chain hashing
- Data integrity verification
- Password entropy estimation

## Authentication

### PAM Integration

SecReg-Linux integrates with the Linux PAM system for authentication:

```
/etc/pam.d/secreg
```

This allows:
- System password reuse
- Multi-factor authentication support
- Account policy enforcement

### Session Management

- Session tokens are 256-bit random values
- Default timeout: 1 hour
- Sliding expiration on activity
- Maximum 5 sessions per user

### Rate Limiting

- Maximum 5 authentication attempts per 5-minute window
- Account lockout after threshold exceeded
- Separate limits per IP address

## Authorization

### Role-Based Access Control

Predefined roles:

| Role | Permissions |
|------|-------------|
| admin | Read, Write, Delete, Grant, Admin |
| operator | Read, Write |
| auditor | Read |
| user | Defined by ACL |

### Access Control Lists

ACLs are stored per key path and include:

- **Owner**: User who owns the key
- **Owner Group**: Group that owns the key
- **Permissions**: List of principal-based permissions
- **Inheritance**: ACL inheritance rules

### Permission Structure

```cpp
struct Permission {
    PrincipalType principal_type;  // User, Group, Role, Service
    std::string principal_name;    // Name of the principal
    std::vector<Action> actions;   // Read, Write, Delete, Grant, Admin
    std::vector<Condition> conditions;  // TimeRange, IpRange, RequireMfa
}
```

### Condition Types

| Condition | Description |
|-----------|-------------|
| TimeRange | Allow access only during specific hours |
| IpRange | Allow access only from specific IPs |
| RequireMfa | Require multi-factor authentication |
| RequireTpm | Require TPM-backed key |

## Audit Logging

### Chain Structure

Audit entries form a hash chain:

```
entry[i].chain_hash = SHA256(entry[i-1].chain_hash + entry[i].data + entry[i].timestamp)
```

This provides:
- **Tamper detection**: Any modification breaks the chain
- **Ordering**: Entries cannot be reordered
- **Completeness**: Deletion is detectable

### Log Contents

Each audit entry includes:

- **Timestamp**: UTC timestamp with millisecond precision
- **Actor**: User ID, name, process ID, session ID
- **Action**: Operation performed
- **Target**: Key path affected
- **Result**: Success/failure with reason
- **Source**: Client information

### Log Retention

- Default retention: 90 days
- Maximum retention: 365 days
- Automatic truncation based on age

## Data Protection

### At Rest

All sensitive data is encrypted before storage:

- Field-level encryption (not whole database)
- Different keys for different fields
- Key hierarchy prevents compromise propagation

### In Transit

- Local communication via Unix domain socket
- Socket permissions restrict access
- Optional TLS for remote access

### Key Management

- Master key derived from password
- Password never stored
- Key sealed with authenticated data

## Threat Model

### Protected Against

- **Unauthorized read**: Access control + encryption
- **Unauthorized write**: Access control + audit logging
- **Data tampering**: Hash chain verification
- **Replay attacks**: Nonces and timestamps
- **Brute force**: Rate limiting + high iteration count

### Not Protected Against

- **Physical access**: If attacker has disk access and password
- **Root compromise**: Root can access but is audited
- **Side channels**: Timing attacks on crypto operations
- **Social engineering**: Users sharing passwords

## Security Best Practices

### Password Selection

Use strong passwords:
- Minimum 12 characters
- Mix of upper/lower case, numbers, symbols
- Avoid dictionary words
- Use a password manager

### Access Control

- Follow principle of least privilege
- Regular ACL reviews
- Audit permission changes

### Monitoring

- Review audit logs regularly
- Set up alerts for failures
- Monitor for suspicious patterns

## Compliance

SecReg-Linux helps meet compliance requirements for:

- **PCI-DSS**: Access tracking, encryption, audit logs
- **HIPAA**: Access controls, audit trails
- **SOC 2**: Change management, security logging
