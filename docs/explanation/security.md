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

## Cluster trust

Clustered members authenticate each other with dqlite mTLS, separate from the HTTPS API certificate. There are two modes.

**Shared pair (default).** If `cluster.tls` is not configured, the first member generates a self-signed pair on bootstrap and stores it in `db_path` as `cluster.crt` and `cluster.key`. Every member presents the same certificate, and each verifies its peer against it.

**CA mode.** Set `cluster.tls.ca_path`, `cert_path`, `key_path`, and `peer_san`. Each unit presents its own leaf signed by a dedicated cluster CA that Notary does not operate. Peers must present that CA plus the group SAN (`peer_san`). The unit private key is not copied into `db_path`. Do not reuse the HTTPS API CA.

Joining members do not receive cluster key material by copying files. `notary cluster add` issues a one-time token carrying the member name, the API addresses, a secret, an expiry, and the SHA-256 fingerprint of the issuing member's **HTTPS** certificate. The joiner redeems the token against that member's API over a connection pinned to the fingerprint. In shared-pair mode the response includes the cluster certificate and key. In CA mode the response is dqlite addresses only; the joiner must already have `ca_path` and its own leaf. The token itself never contains a private key.

dqlite has no protocol authentication. TLS trust on the dqlite port **is** authorisation. Join tokens only constrain `notary start --join`. Restrict the dqlite port to cluster members.

Three consequences are worth planning for:

- **A join token is a bearer credential.** Until it is redeemed or expires, whoever holds it can obtain the shared cluster private key (default mode) or the current dqlite addresses (CA mode). Treat it like a password: pass it over a secure channel, do not put it in tickets or chat, and prefer `notary start --join` over storing it in a configuration file.
- **Removing a member is not revocation.** `notary cluster remove` evicts a node from raft but does not invalidate credentials. Until you stop that process it can still reach the cluster database as a client. In shared-pair mode, genuinely revoking a member means generating a new cluster certificate and key, setting `cluster.tls` on every remaining member, and restarting them. In CA mode, stop the unit then revoke or expire its cluster leaf at your CA; until then a holder of that leaf can still speak dqlite.
- **Backups can contain cluster keys.** In shared-pair mode `cluster.key` lives in `db_path`. In CA mode the unit key stays at `cluster.tls.key_path`; still store backups of that path with the archive. See [Back up and restore Notary](../how-to/backup_restore.md).

There is no automatic rotation of the generated shared cluster certificate. That pair is valid for ten years; replacing it earlier is the manual procedure described above.

## Authentication

Notary implements token-based authentication for its API and web interface. Users must provide a valid authentication token in the `Authorization` header of their requests. Notary hashes passwords using Argon2id before storage, ensuring that even if the database is compromised, user passwords remain secure.

## Authorization

Notary uses role-based access control (RBAC) to manage user permissions. Each user is assigned a role that defines their permissions within the system. Roles are assigned to accounts when they are created, either via the API (see the [API account reference](../reference/api/accounts.md#create-an-account)) or the web interface. To view the role definitions, see the [Roles reference](../reference/roles.md).

