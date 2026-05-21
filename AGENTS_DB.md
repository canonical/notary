# AGENTS_DB.md — Database Reference for AI Coding Agents

> For build commands, code style, and general conventions, see [AGENTS.md](./AGENTS.md).

## Tables

### `certificate_requests`

| Column           | Type    | Constraints           | Purpose                                        |
| ---------------- | ------- | --------------------- | ---------------------------------------------- |
| `csr_id`         | INTEGER | PK, AUTOINCREMENT     | Unique CSR identifier                          |
| `csr`            | TEXT    | NOT NULL, UNIQUE      | PEM-encoded certificate signing request        |
| `status`         | TEXT    | DEFAULT 'Outstanding' | One of: Outstanding, Rejected, Revoked, Active |
| `certificate_id` | INTEGER | nullable              | FK → `certificates.certificate_id`             |
| `user_email`     | TEXT    | nullable              | Email of the user who submitted the CSR        |

Status constraints enforced via CHECK:

- Active requires a non-null `certificate_id`
- Outstanding/Rejected/Revoked require null `certificate_id`

### `certificates`

| Column           | Type    | Constraints       | Purpose                                                   |
| ---------------- | ------- | ----------------- | --------------------------------------------------------- |
| `certificate_id` | INTEGER | PK, AUTOINCREMENT | Unique certificate identifier                             |
| `certificate`    | TEXT    | NOT NULL, UNIQUE  | PEM-encoded certificate                                   |
| `issuer_id`      | INTEGER | nullable          | FK → `certificates.certificate_id` (0 = self-signed/root) |

### `certificate_authorities`

| Column                     | Type    | Constraints       | Purpose                            |
| -------------------------- | ------- | ----------------- | ---------------------------------- |
| `certificate_authority_id` | INTEGER | PK, AUTOINCREMENT | Unique CA identifier               |
| `crl`                      | TEXT    | nullable          | PEM-encoded CRL                    |
| `enabled`                  | INTEGER | DEFAULT 0         | 0 = disabled, 1 = enabled          |
| `private_key_id`           | INTEGER | nullable          | FK → `private_keys.private_key_id` |
| `certificate_id`           | INTEGER | nullable          | FK → `certificates.certificate_id` |
| `csr_id`                   | INTEGER | NOT NULL, UNIQUE  | FK → `certificate_requests.csr_id` |

A CA is always backed by a CSR. The `csr_id` is the link between a CA and its CSR row.

### `private_keys`

| Column           | Type    | Constraints       | Purpose                               |
| ---------------- | ------- | ----------------- | ------------------------------------- |
| `private_key_id` | INTEGER | PK, AUTOINCREMENT | Unique private key identifier         |
| `private_key`    | TEXT    | NOT NULL, UNIQUE  | **Encrypted** PEM-encoded private key |

Private keys are stored encrypted using `utils.Encrypt()` with the DB encryption key.

### `users`

| Column            | Type    | Constraints            | Purpose                                        |
| ----------------- | ------- | ---------------------- | ---------------------------------------------- |
| `id`              | INTEGER | PK, AUTOINCREMENT      | Unique user identifier                         |
| `oidc_subject`    | TEXT    | nullable, unique index | OIDC provider's `sub` claim                    |
| `email`           | TEXT    | nullable, unique index | User email (nullable for OIDC-only users)      |
| `hashed_password` | TEXT    | nullable               | bcrypt hash (null for OIDC-only users)         |
| `role_id`         | INTEGER | NOT NULL               | 0=admin, 1=cert_manager, 2=requestor, 3=reader |

CHECK: at least one of `email` or `oidc_subject` must be non-empty.
Partial unique indexes on both `email` and `oidc_subject` (only non-NULL values).

### `encryption_keys`

| Column              | Type    | Constraints       | Purpose                        |
| ------------------- | ------- | ----------------- | ------------------------------ |
| `encryption_key_id` | INTEGER | PK, AUTOINCREMENT | Always 1 (singleton)           |
| `encryption_key`    | TEXT    | NOT NULL, UNIQUE  | Base64-encoded AES-256-GCM key |

Singleton table — only one row ever exists.

### `jwt_secret`

| Column             | Type    | Constraints     | Purpose                      |
| ------------------ | ------- | --------------- | ---------------------------- |
| `id`               | INTEGER | PK, CHECK(id=1) | Always 1 (singleton)         |
| `encrypted_secret` | TEXT    | NOT NULL        | Encrypted JWT signing secret |

Singleton table — only one row ever exists. Secret is encrypted with the DB encryption key.

### `acme_accounts`

| Column              | Type    | Constraints     | Purpose                                |
| ------------------- | ------- | --------------- | -------------------------------------- |
| `id`                | INTEGER | PK, CHECK(id=1) | Always 1 (singleton)                   |
| `email`             | TEXT    | NOT NULL        | ACME account email                     |
| `private_key`       | TEXT    | NOT NULL        | **Encrypted** ACME account private key |
| `registration_uri`  | TEXT    | NOT NULL        | ACME provider registration URI         |
| `registration_body` | TEXT    | NOT NULL        | ACME registration response body        |

Singleton table — only one ACME account. Added in migration `00002_acme_accounts.sql`.

## Relationships

```
users ──(user_email)──> certificate_requests ──(certificate_id)──> certificates
                                                      │
                          certificate_authorities ──(certificate_id)
                                                      │
                          certificate_authorities ──(csr_id)──> certificate_requests
                                                      │
                          certificate_authorities ──(private_key_id)──> private_keys

certificates ──(issuer_id)──> certificates (self-referential chain)
```

- **CSR → Certificate**: A CSR gets a certificate when signed or uploaded. The `certificate_id` column links them.
- **CA → CSR**: Every CA is backed by exactly one CSR (`csr_id` is UNIQUE). The CA's CSR is also a row in `certificate_requests`.
- **CA → Certificate**: A CA may have a certificate chain (self-signed or signed by a parent CA).
- **CA → Private Key**: Each CA has one private key, stored encrypted.
- **Certificate chain**: `certificates.issuer_id` forms a linked list. Root CAs have `issuer_id = 0`. Recursive CTEs traverse the chain.

## Key Query Patterns

### Generic Helpers (used by all domain functions)

```go
ListEntities[T any](db, stmt, args...) ([]T, error)   // List all rows of type T
GetOneEntity[T any](db, stmt, args...) (*T, error)     // Get single row, returns ErrNotFound if missing
CreateEntity[T any](db, stmt, entity) (int64, error)   // Insert, returns new ID
UpdateEntity[T any](db, stmt, entity) error             // Update by primary key
DeleteEntity[T any](db, stmt, entity) error             // Delete by primary key
```

### Certificate Requests

```go
ListCertificateRequests() ([]CertificateRequest, error)
ListCertificateRequestsWithoutCAS() ([]CertificateRequest, error)           // Excludes CA CSRs
ListCertificateRequestWithCertificatesWithoutCAS(filter) ([]CertificateRequestWithChain, error) // With cert chains, scoped by email if filter.UserEmail set
GetCertificateRequest(filter CSRFilter) (*CertificateRequest, error)        // By ID or PEM
GetCertificateRequestAndChain(filter CSRFilter) (*CertificateRequestWithChain, error) // With recursive cert chain
CreateCertificateRequest(csr, userEmail) (int64, error)                     // Validates CSR format
RejectCertificateRequest(filter CSRFilter) error                            // Sets status=Rejected, clears certificate_id
DeleteCertificateRequest(filter CSRFilter) error
```

### Certificates

```go
ListCertificates() ([]Certificate, error)
GetCertificate(filter CertificateFilter) (*Certificate, error)              // By ID or PEM
GetCertificateChain(filter CertificateFilter) ([]Certificate, error)        // Recursive CTE up to root
AddCertificateChainToCertificateRequest(csrFilter, certPEM) (int64, error)  // Validates, splits bundle, builds chain
DeleteCertificate(filter CertificateFilter) error
```

### Certificate Authorities

```go
ListCertificateAuthorities() ([]CertificateAuthority, error)
ListDenormalizedCertificateAuthorities() ([]CertificateAuthorityDenormalized, error) // Embeds PEM strings
GetCertificateAuthority(filter) (*CertificateAuthority, error)
GetDenormalizedCertificateAuthority(filter) (*CertificateAuthorityDenormalized, error)
CreateCertificateAuthority(csrPEM, privPEM, crlPEM, certChainPEM, userEmail) (int64, error)
UpdateCertificateAuthorityEnabledStatus(filter, enabled) error
UpdateCertificateAuthorityCertificate(filter, certChainPEM) error          // Replaces cert chain
DeleteCertificateAuthority(filter) error
```

### Users

```go
ListUsers() ([]User, error)
GetUser(filter UserFilter) (*User, error)                                   // By ID, email, or OIDC subject
CreateUser(email, password, roleID) (int64, error)                          // Hashes password with bcrypt
CreateOIDCUser(email, oidcSubject, roleID) (*User, error)                   // No password, returns created user
UpdateUserPassword(filter, password) error                                  // Re-hashes password
UpdateUserRole(filter, roleID) error
DeleteUser(filter) error
NumUsers() (int, error)
```

### Encryption Key & JWT Secret (singletons)

```go
GetEncryptionKey() ([]byte, error)           // Decodes from base64
CreateEncryptionKey(key []byte) error
DeleteEncryptionKey() error

GetJWTSecret() ([]byte, error)               // Decrypts stored secret
CreateJWTSecret(secret []byte) error         // Encrypts before storing
```

### Private Keys

```go
GetDecryptedPrivateKey(filter) (*PrivateKey, error)  // Decrypts stored key
CreatePrivateKey(pk string) (int64, error)            // Encrypts before storing
DeletePrivateKey(filter) error
```

### ACME Accounts (singleton)

```go
CreateACMEAccount(email, privKeyPEM, regURI, regBody) error  // Encrypts private key
GetDecryptedACMEAccount() (*ACMEAccount, error)               // Decrypts private key
ACMEAccountExists() (bool, error)
```

### Filter Constructors

```go
// Certificate filters
ByCertificateID(id int64) CertificateFilter
ByCertificatePEM(pem string) CertificateFilter

// CSR filters
ByCSRID(id int64) CSRFilter
ByCSRPEM(pem string) CSRFilter
ByUserEmail(email string) CSRFilter

// User filters
ByUserID(id int64) UserFilter
ByEmail(email string) UserFilter
ByOIDCSubject(subject string) UserFilter
```

## Migration Rules

- Migrations live in `internal/db/migrations/`.
- **Never modify or delete existing migration files.**
- New migrations must follow the timestamped naming pattern: `NNNNN_description.sql`.
- Uses [goose](https://github.com/pressly/goose) for migration management.
- Migrations are embedded via `internal/db/migrations/migration.go` (Go `embed`).
- After adding a migration, run: `go test ./internal/db/...`
- The `NewDatabase()` function auto-applies migrations if `ApplyMigrations: true` and DB version < 1.

## Notes for Agents

- **Private keys are always encrypted at rest** — `CreatePrivateKey` encrypts with `db.EncryptionKey` before INSERT. `GetDecryptedPrivateKey` decrypts after SELECT. Never store plaintext keys.
- **ACME account private key is also encrypted** — same pattern as private keys.
- **JWT secret is encrypted** — stored encrypted, decrypted on read.
- **Encryption key is base64-encoded** — not encrypted itself (it's the master key). Stored as base64 in `encryption_keys`.
- **Certificate chain is built recursively** — `AddCertificateChainToCertificateRequest` splits a PEM bundle, walks it in reverse, and links via `issuer_id`. Root certs have `issuer_id = 0`.
- **CA CSRs are excluded from regular CSR listings** — `ListCertificateRequestsWithoutCAS` uses a LEFT JOIN to filter out CSRs that belong to a CA. Handlers also check `GetCertificateAuthority(ByCertificateAuthorityCSRID(id))` before operating on a CSR.
- **User email is nullable** — OIDC users may not have an email. The `users` table has a CHECK ensuring at least one of `email` or `oidc_subject` is present.
- **Partial unique indexes** — `idx_users_email` and `idx_users_oidc_subject` only index non-NULL values, allowing multiple NULLs.
- **Singleton tables** — `encryption_keys`, `jwt_secret`, and `acme_accounts` are singleton tables (only one row, enforced by CHECK(id=1) or convention).
- **sqlair is the ORM** — uses struct tags (`db:"column_name"`) for mapping. Queries use `&Type.*` syntax for SELECT and `$Type.field` for WHERE.
- **Generic CRUD** — `ListEntities`, `GetOneEntity`, `CreateEntity`, `UpdateEntity`, `DeleteEntity` are generic functions. New domain types should follow this pattern.
- **Error sentinels** — `ErrNotFound`, `ErrAlreadyExists`, `ErrInvalidFilter`, `ErrInvalidInput`, `ErrInvalidCertificate`, `ErrInvalidCertificateRequest`, `ErrInvalidPrivateKey`, `ErrInvalidUser`, `ErrInternal`. Use `errors.Is()` to check.
- **`rowFound()` / `realError()` helpers** — `rowFound(err)` returns true if err is nil (row exists). `realError(err)` returns true if err is non-nil and not `ErrNotFound`. Used in handlers to distinguish "not found" from real errors.
