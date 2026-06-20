## Why

Notary's storage layer carries latent single-process assumptions that are already bugs today and become guaranteed failures once multiple nodes share a database (the planned HA work in `add-ha-clustering`). Most urgently: Notary and the embedded OpenFGA server share goose's default `goose_db_version` table on the same database, which only works because OpenFGA's migration numbers (005, 006) happen to be higher than Notary's (00001, 00002) — the next Notary migration (00003) will be silently skipped or error. These fixes are valuable on their own and are hard prerequisites for HA.

## What Changes

- Separate schema-migration bookkeeping for Notary and the embedded OpenFGA so each subsystem tracks its own versions (fixes the shared `goose_db_version` collision and the global `goose.SetBaseFS` order-dependence).
- Make startup bootstrap idempotent and safe under concurrent execution: encryption-key creation, JWT-secret creation, and OpenFGA store/model initialization currently follow get→generate→create and fatal on `ErrAlreadyExists` if two processes race.
- Make CRL updates concurrency-safe: revocation currently does an untransacted read-modify-write of the stored CRL, which can lose revocations under concurrent writers.
- Replace the in-memory OIDC `StateStore` with a stateless HMAC-signed state parameter, removing the requirement that the OIDC callback lands on the node that issued the state (and removing the cleanup goroutine).
- Apply connection-level SQLite settings to every pooled connection via the DSN: `PRAGMA foreign_keys` is currently executed once on one of two pooled connections, so roughly half of all writes bypass foreign-key enforcement; busy-timeout is not set at all.
- Rewrite `RestoreBackup` to use only the primary driver with an atomic file replacement, removing `mattn/go-sqlite3`: today restore opens the live database file with a second SQLite implementation in the same process (defeating SQLite's file locking, which is per-process) and silently depends on CGo, so a `CGO_ENABLED=0` build fails at runtime only — during disaster recovery.

## Capabilities

### New Capabilities

- `storage-migrations`: how schema migrations for Notary and embedded subsystems (OpenFGA) are tracked and applied without interfering with each other.
- `startup-bootstrap`: concurrent-safe, idempotent initialization of singleton state (encryption key, JWT secret, OpenFGA store and authorization model) and database connection settings that hold on every pooled connection.
- `backup-restore`: restore semantics — atomic, single-driver, CGo-independent replacement of the database from a backup archive.
- `crl-management`: consistency guarantees for CRL updates under concurrent revocations.
- `oidc-login`: OIDC login CSRF state that does not depend on node-local memory.

### Modified Capabilities

(none — no existing specs)

## Impact

- `internal/db/db_init.go`, `cmd/migrate.go` — goose table separation, migration gating logic, DSN connection settings, `RestoreBackup` rewrite.
- `go.mod` — `mattn/go-sqlite3` removed entirely.
- `internal/backends/authorization/openfga.go` — own goose bookkeeping, idempotent store/model creation.
- `internal/backends/encryption/encryption.go`, `internal/db/db_jwt_secret.go` — create-or-fetch bootstrap.
- `internal/db/db_certificate_authorities.go` — transactional CRL updates.
- `internal/server/state_store.go`, `handlers_oidc.go`, `server.go` — stateless OIDC state (StateStore removed).
- No config or API surface changes; no breaking changes.
