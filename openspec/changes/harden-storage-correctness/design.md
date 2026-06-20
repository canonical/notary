## Context

Notary is a single-process service today, and several storage-layer behaviors implicitly rely on that: goose migration bookkeeping is shared between Notary and the embedded OpenFGA (same default `goose_db_version` table, same package-global `goose.SetBaseFS`), singleton bootstrap (encryption key, JWT secret, OpenFGA store) is get→generate→create with a fatal on lost races, CRL updates are untransacted read-modify-write, and OIDC CSRF state lives in an in-memory map. The `add-ha-clustering` change will put N processes on one replicated database; all four behaviors then become real failure modes. The goose collision is a live bug even single-node: OpenFGA's migrations (005, 006) sit above Notary's (00001, 00002) in the shared table, so Notary's next migration (00003) will be mishandled.

## Goals / Non-Goals

**Goals:**
- Notary and OpenFGA migrations tracked independently and safely, single- and multi-process.
- All singleton bootstrap paths idempotent under concurrent startup.
- CRL updates that cannot lose concurrent revocations.
- OIDC login that works when redirect and callback hit different processes.

**Non-Goals:**
- Any clustering, dqlite, or microcluster work (that is `add-ha-clustering`).
- Rebuilding *backup creation* for the cluster world (`CreateBackup`/`VACUUM INTO` stays; `add-ha-clustering` replaces it with a leader-side dump). The *restore* path is in scope here because it is broken independently of clustering.
- Config or public API changes.

## Decisions

**Migrations: separate goose tables via per-subsystem providers.** Use goose's per-instance provider API (or `SetTableName` around each run if the provider API is unavailable in the pinned version) so Notary uses e.g. `goose_db_version` and OpenFGA uses `goose_db_version_openfga`. A one-time repair step migrates existing databases: rows belonging to OpenFGA versions move to the new table. This also removes the order-dependent `goose.SetBaseFS` global usage. The `version < 1` gate in `db_init.go` changes to "pending Notary migrations exist".

**Bootstrap: create-or-fetch.** On `ErrAlreadyExists` from `CreateEncryptionKey` / `CreateJWTSecret` / OpenFGA `CreateStore`/`WriteAuthorizationModel`, re-read and use the stored value; discard locally generated material. No locking needed — the unique constraints already serialize; we just stop treating the loss as fatal.

**CRL updates: transaction plus conflict detection.** Wrap read-modify-write in a transaction and compare the stored CRL (or an added `crl_number`/version column) against what was read; retry a bounded number of times on conflict. Version-column comparison is preferred over raw-text comparison since CRL PEM re-encoding is not canonical. In today's single-writer SQLite this is belt-and-braces; over dqlite it is load-bearing.

**Engine specifics stay inside the CRUD helpers.** This change is the shared foundation for every planned storage mode (single-node SQLite today, dqlite clustering, and a future external-database backend — see `add-ha-clustering` and `add-external-db-backend`). The engine-specific behaviors it touches — unique-violation detection (currently string-matching `"UNIQUE constraint failed"`) and insert-ID retrieval (`LastInsertId`) — already live in the generic helpers in `db_init.go`; keep them there and do not let engine-specific SQL or error assumptions leak into callers, so a future backend swaps the helpers, not the codebase.

**Connection settings: DSN pragmas, not one-shot Exec.** `PRAGMA foreign_keys` is a per-connection SQLite setting; executing it once via `sqlConnection.Exec` (`db_init.go:45`) configures only one of the two pooled connections, so writes on the other run with FK enforcement off. Fix: encode connection settings in the DSN so the driver applies them to every new connection — modernc supports `?_pragma=foreign_keys(1)`. Add `_pragma=busy_timeout(5000)` at the same time (currently unset: concurrent access can surface spurious "database is locked" errors) and evaluate `journal_mode(WAL)` for writer/reader concurrency. Note for the HA change: dqlite has its own pragma semantics — this is a flagged spike probe there.

**Restore: validate, then atomic file replace — one driver.** `RestoreBackup` currently opens the live database file with `mattn/go-sqlite3` (CGo) while the modernc handle is open in the same process; SQLite's cross-connection protection is POSIX advisory locking, which does not exclude within a single process, and the mattn dependency means a `CGO_ENABLED=0` build compiles but fails at runtime during disaster recovery. Rewrite: extract the archive to a temp file, validate it with modernc (open, ping, integrity/schema sanity check), close all handles to the destination, then atomically replace the database file (rename onto `db.Path`, removing stale `-wal`/`-shm` siblings). Any failure before the rename leaves the existing database untouched. `mattn/go-sqlite3` is removed from `go.mod`; pure-Go builds become fully supported.

**OIDC state: HMAC token instead of server-side store.** State becomes `base64(payload) || HMAC-SHA256(payload, k)` where `k` is derived from the JWT secret (HKDF with a dedicated info string — do not reuse the JWT signing key directly) and payload carries issued-at and a user-agent hash. Validation checks signature, 5-minute window, and user-agent binding. Replay within the window is accepted: state's purpose is CSRF binding, not one-time-use nonce semantics, and the OIDC `nonce`/PKCE story is unchanged. This trade-off is recorded in the spec scenario. `StateStore` and its cleanup goroutine are deleted.

## Risks / Trade-offs

- **Goose table repair on existing databases**: mixing subsystems' rows in one table means the repair must classify rows by version number (1–2 = Notary, ≥5 = OpenFGA today). Acceptable because the version sets are disjoint and there are no production customers; the repair is covered by a migration test against a copied real database.
- **Replayable OIDC state within 5 minutes**: weaker than one-time-use; judged acceptable because state binds the callback to a browser session (CSRF), while authentication integrity comes from the code exchange. If later deemed insufficient, a DB-backed used-state table can be added without changing the token format.
- **CRL version column** touches the schema — it must ship as Notary migration 00003, which is itself the first test of the migration-bookkeeping fix.
