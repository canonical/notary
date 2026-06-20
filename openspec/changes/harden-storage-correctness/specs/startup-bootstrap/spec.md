## ADDED Requirements

### Requirement: Singleton bootstrap is create-or-fetch
Initialization of singleton state — the AES-256-GCM encryption key, the JWT secret, and the OpenFGA store and authorization model — SHALL be idempotent. If creation fails because the entity already exists, the initializer MUST fetch and use the existing entity instead of failing.

#### Scenario: Two processes bootstrap an empty database concurrently
- **WHEN** two Notary processes start simultaneously against the same empty database
- **THEN** both processes finish startup successfully and both end up using the same encryption key, JWT secret, and OpenFGA store

#### Scenario: Encryption key creation loses a race
- **WHEN** a process generates a new encryption key but its insert fails with "already exists"
- **THEN** the process re-reads the stored key, decrypts it with the configured encryption backend, and continues startup

#### Scenario: OpenFGA store creation loses a race
- **WHEN** a process attempts to create the "notary" OpenFGA store and it already exists
- **THEN** the process uses the existing store and its latest authorization model

### Requirement: Connection settings apply to every pooled connection
Per-connection database settings — foreign-key enforcement and busy timeout — SHALL be applied to every connection the pool opens, not executed once against a single connection.

#### Scenario: Foreign keys enforced on all connections
- **WHEN** writes that violate a foreign-key constraint are issued repeatedly so that every pooled connection serves at least one of them
- **THEN** every violating write is rejected, regardless of which pooled connection executes it

### Requirement: Bootstrap never persists secrets that lost a race
When a bootstrap race is lost, the generated-but-unused secret material MUST NOT be persisted or used for any cryptographic operation.

#### Scenario: Losing key generation is discarded
- **WHEN** a process loses the encryption-key creation race
- **THEN** the locally generated key is discarded and only the winning stored key is used to decrypt the JWT secret and private keys
