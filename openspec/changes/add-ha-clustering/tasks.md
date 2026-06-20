## 1. Spike: validate the stack over dqlite (gate for everything below; throwaway code on a branch)

- [ ] 1.1 Environment: Ubuntu VM or container with `libdqlite-dev`; minimal program creating a 1-node `go-dqlite/app.App` and obtaining a `*sql.DB` (dqlite does not build on macOS — the spike runs in a VM/CI)
- [ ] 1.2 Notary path: hack an injected `*sql.DB` into `db.NewDatabase` on the spike branch; run goose migrations 00001–00002 and the full `internal/db` test suite over dqlite; explicitly probe per-connection `PRAGMA foreign_keys` behavior, `BeginTx`, `LastInsertId`, and concurrent-writer errors
- [ ] 1.3 OpenFGA path: run OpenFGA's SQLite goose migrations over the dqlite handle, then `InitializeLocalOpenFGA` via `NewWithDB`; exercise CreateStore, WriteAuthorizationModel, WriteTuple, Check, and ListObjects (NewWithDB skips OpenFGA's WAL/busy-timeout/txlock DSN handling, so only query shapes and transactions are under test)
- [ ] 1.4 Go/no-go writeup against explicit criteria — go: `internal/db` suite green, both migration sets apply, the five OpenFGA operations succeed, FK enforcement confirmed; no-go: any unsupported-SQL error or FK gap → fallback ladder (patch/wrap datastore → vendor datastore → revisit Postgres)

## 2. Storage seam

- [ ] 2.1 Refactor `db.NewDatabase` to accept an externally opened `*sql.DB`; remove driver selection from the db package
- [ ] 2.2 Replace `db_path` config with `high-availability: { node-id, storage-path, cluster-address }` (`cluster-address` defaults to loopback for single-node); update config validation and docs
- [ ] 2.3 Demote `modernc.org/sqlite` to test-only (`mattn/go-sqlite3` is already removed by `harden-storage-correctness`)

## 3. Microcluster integration

- [ ] 3.1 Restructure `cmd/start.go` around the microcluster daemon: storage-path, cluster listener, `--new-cluster`/`--join <token>` startup flags (required on empty storage-path, ignored with warning otherwise), Notary API server launched from `OnStart` with the microcluster-provided DB handle
- [ ] 3.2 Wrap Notary's goose migration set (own table, per harden-storage-correctness) in a coordinated microcluster `schema.Update`; goose SQL files remain the source of truth
- [ ] 3.3 Wrap OpenFGA's migration set the same way (separate goose table per harden-storage-correctness)
- [ ] 3.4 Wire SIGTERM/SIGINT to graceful handover before shutdown
- [ ] 3.5 Rework `notary migrate` to status/inspection over the coordinated mechanism

## 4. Cluster lifecycle surface

- [ ] 4.1 Admin API endpoints: `POST /cluster/token` (single-use, 5-min expiry, node-id-bound) and `POST /cluster/remove`; `notary cluster list --format json` CLI over the status endpoint
- [ ] 4.2 Removal handles both member states: graceful handover for live members, force path for down/permanently lost members, behind the one `/cluster/remove` interface
- [ ] 4.3 Extend `GET /cluster/status` with `cluster-state` (node-id, address, role, leader/follower/down) and quorum availability; readiness semantics for load balancers and automation
- [ ] 4.4 Cluster metrics (role, leader changes, quorum state) in the Prometheus registry

## 5. Quorum-loss read behavior

- [ ] 5.1 Dedicated stale-tolerant read path for CRL and certificate download endpoints
- [ ] 5.2 Bounded, clearly identified quorum-loss errors on all write paths
- [ ] 5.3 Tests: CRL served without quorum; issuance fails promptly without quorum

## 6. Backup, restore, import

- [ ] 6.1 Rebuild `CreateBackup` on a leader-side dqlite dump (same tar.gz envelope); works from any node
- [ ] 6.2 Restore-as-recovery flow: fresh 1-node cluster from archive + rejoin procedure; in-place restore into a running cluster fails with guidance
- [ ] 6.3 `--new-cluster --from-db <sqlite-file>` import; end-to-end test from a database created by the previous release
- [ ] 6.4 Recovery runbook in docs

## 7. Packaging & CI

- [ ] 7.1 CGo builds with `libdqlite` in snap and rock; expose cluster port; state-dir provisioning
- [ ] 7.2 CI: build matrix with libdqlite, dqlite integration test job
- [ ] 7.3 Docs: clustering tutorial, quorum sizing (1/3/5), `ExternalHostname`-must-be-LB note, HSM reachability requirement

## 8. HA test suite

- [ ] 8.1 3-node e2e: CRUD via every node; kill leader mid-workload; assert re-election and zero lost committed writes
- [ ] 8.2 Rolling upgrade test exercising coordinated schema updates
- [ ] 8.3 Concurrent fresh bootstrap of 3 nodes (exercises harden-storage-correctness under dqlite)
- [ ] 8.4 Quorum-loss test: writes fail clean, CRL keeps serving, recovery after nodes return
- [ ] 8.5 Restart-with-state-dir test: membership count stable across reschedules
