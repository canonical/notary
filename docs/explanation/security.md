# Security

Notary is designed with security as a core principle, implementing robust measures to safeguard sensitive data and ensure secure communication. This document outlines the key security features of Notary.

If you discover a security issue, see the [Notary security policy](https://github.com/canonical/notary/blob/main/SECURITY.md) for information on how to report the issue.

## Encryption at Rest

Notary encrypts sensitive data at rest using AES-256 in Galois/Counter Mode (GCM). 

The encryption key is stored alongside the data and can be encrypted with one of the following encryption backends:
- **PKCS#11**: Uses a hardware security module (HSM) to manage encryption keys.
- **HashiCorp Vault**: Utilizes Vault's Transit secrets engine for encryption.
- **None**: Disables encryption, not recommended for production environments.

### Configuration

The encryption backend is configured in the [configuration file](../reference/config_file.md).

## Transport Layer Security (TLS)

Notary uses TLS to secure its API and web interface. The use of TLS is mandatory, Notary will not start if the TLS configuration is missing or invalid.

### Configuration

The TLS configuration is defined in the [configuration file](../reference/config_file.md). 

### Certificate Management

To update TLS certificates:
- Replace the certificate and key files on disk.
- Restart Notary to apply the changes.

### Supported TLS Versions

Notary supports TLS versions `1.2` and `1.3`.

## Authentication

Notary implements token-based authentication for its API and web interface. Users must provide a valid authentication token in the `Authorization` header of their requests. Notary hashes passwords  using Argon2id before storage, ensuring that even if the database is compromised, user passwords remain secure.

## Authorization

Notary uses role-based access control (RBAC) to manage user permissions. Each user is assigned a role that defines their permissions within the system.
