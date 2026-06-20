## 1. Migration bookkeeping separation

- [ ] 1.1 Move Notary's goose usage in `internal/db/db_init.go` and `cmd/migrate.go` to a per-instance goose provider (own table, own FS) with no package-global `SetBaseFS`/`SetDialect`
- [ ] 1.2 Move OpenFGA's migrations in `internal/backends/authorization/openfga.go` to their own goose table (`goose_db_version_openfga`)
- [ ] 1.3 Write the one-time repair that reclassifies existing `goose_db_version` rows into the two tables; test against a database created by the current released binary
- [ ] 1.4 Replace the `version < 1` startup gate with a "pending Notary migrations" check; error message names the subsystem that is outdated
- [ ] 1.5 Add a regression test: apply Notary 00001–00002 + OpenFGA migrations, then introduce a fake Notary 00003 and assert it is detected and applied

## 2. Idempotent bootstrap

- [ ] 2.1 `SetUpEncryptionKey`: on `ErrAlreadyExists`, re-read the stored key, decrypt via backend, continue; discard generated key
- [ ] 2.2 JWT secret setup: same create-or-fetch treatment
- [ ] 2.3 `InitializeLocalOpenFGA`: make store lookup/create/model-write idempotent under concurrent execution
- [ ] 2.4 Concurrency test: N goroutines bootstrap one empty database; all succeed and agree on key/secret/store

## 3. CRL concurrency safety

- [ ] 3.1 Add `crl_number`/version tracking to certificate authorities (Notary migration 00003)
- [ ] 3.2 Wrap CRL read-modify-write flows in `db_certificate_authorities.go` in a transaction with version conflict detection and bounded retry
- [ ] 3.3 Concurrency test: concurrent revocations against one CA all appear in the final CRL; CRL numbers strictly increase

## 4. Stateless OIDC state

- [ ] 4.1 Implement signed state tokens (HKDF-derived key from JWT secret; issued-at + user-agent hash payload; 5-minute window)
- [ ] 4.2 Rework `handlers_oidc.go` issue/validate paths to use signed state; preserve login vs other state types
- [ ] 4.3 Delete `state_store.go` and the cleanup goroutine in `server.go`; migrate `state_store_test.go` coverage to token tests
- [ ] 4.4 Test: state issued by one server instance validates on a second instance sharing the same database

## 5. Connection settings & restore path

- [ ] 5.1 Move connection settings into the DSN (`_pragma=foreign_keys(1)`, `_pragma=busy_timeout(5000)`; evaluate `journal_mode(WAL)`); remove the one-shot `Exec("PRAGMA foreign_keys = ON")`
- [ ] 5.2 Test: FK-violating writes are rejected on every pooled connection (exercise both connections)
- [ ] 5.3 Rewrite `RestoreBackup`: extract → validate with modernc → close destination handles → atomic rename onto `db.Path`, removing stale `-wal`/`-shm` files; failure before rename leaves the database untouched
- [ ] 5.4 Remove `mattn/go-sqlite3` from `go.mod`; add a `CGO_ENABLED=0` build (and restore smoke test) to CI
- [ ] 5.5 e2e test: backup → restore → data intact; corrupt archive → command fails, original database byte-identical

## 6. Verification

- [ ] 6.1 Full test suite green; manual login (local + OIDC), issue, revoke, backup/restore, and migrate flows exercised end-to-end
