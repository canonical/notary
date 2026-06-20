## Why

Notary must survive node failure in every environment it ships to — snap on machines, container, or Kubernetes. The immediate motivation is HA Juju deployments, where every other component survives machine/unit failure and the CA must not be the single point of failure. Because Notary's database is a security ledger (issued certificates and revocations must never be lost or forked), HA must be quorum-based replication rather than async failover: a lost write is an unrevocable certificate in the wild. dqlite (raft-replicated SQLite) managed via microcluster gives self-contained HA in the binary with no external database — the pattern used by MicroCeph, MicroOVN, and Canonical Kubernetes — and is dialect-identical to the current SQLite storage.

Depends on `harden-storage-correctness` (multi-process-safe migrations, bootstrap, CRL updates, OIDC state).

## What Changes

- **BREAKING**: storage moves from a single SQLite file to a dqlite cluster managed by microcluster. Every deployment is a cluster; a single node is a 1-voter cluster. `db_path` (file) is replaced by a state directory. Builds require CGo + `libdqlite`.
- Cluster lifecycle: initialization via `--new-cluster`/`--join <token>` startup flags; token minting, member removal, and cluster state via admin API endpoints (`POST /cluster/token`, `POST /cluster/remove`, extended `GET /cluster/status`); automatic voter/standby role management and graceful handover on shutdown — all drivable by automation.
- Schema migrations become cluster-coordinated (microcluster `schema.Update`), applied exactly once per upgrade across the cluster; OpenFGA migrations keep separate bookkeeping within that framework.
- Quorum semantics: writes and certificate issuance require raft quorum and fail cleanly without it; read-only distribution endpoints (CRL download, certificate download) keep serving from local, possibly stale, replicas during quorum loss.
- Status endpoint reports cluster membership, raft role, and leader for health checks and automation.
- Backup becomes a database dump taken from the leader; restore becomes a documented cluster-recovery flow; `--new-cluster --from-db <file>` imports an existing SQLite database into a fresh 1-node cluster.
- Packaging: snap and rock ship `libdqlite`, expose the cluster port, and provision the state directory.

## Capabilities

### New Capabilities

- `cluster-membership`: forming, joining, inspecting, and shrinking the cluster, including non-interactive automation and node-identity stability across restarts/reschedules.
- `replicated-storage`: dqlite-backed storage semantics — durability, write routing, quorum requirements, and degraded-mode read behavior.
- `cluster-backup`: backup, restore/recovery, and import of pre-cluster SQLite databases.
- `cluster-observability`: cluster state exposure via status endpoint and CLI.

### Modified Capabilities

- `storage-migrations`: migration application changes from "any starting process may apply" to cluster-coordinated, exactly-once application during rolling upgrades.

## Impact

- `cmd/start.go` restructured around the microcluster daemon; new `cmd/cluster*.go`; `cmd/backup.go`/`restore.go`/`migrate.go` reworked.
- `internal/db/db_init.go` accepts an externally opened `*sql.DB`; `VACUUM INTO`/SQLite-backup-API paths removed; `modernc.org/sqlite` and `mattn/go-sqlite3` retained only for tests and `--from-db` import.
- `internal/config`: new mandatory `high-availability` section (`node-id`, `storage-path`, `cluster-address`); `db_path` removed (**BREAKING**).
- New dependencies: `github.com/canonical/microcluster/v4`, `github.com/canonical/go-dqlite` (CGo).
- `snap/snapcraft.yaml`, `rockcraft.yaml`, Makefile, CI (CGo toolchain, libdqlite).
- notary-k8s charm (separate repo) consumes the join/remove automation; its requirements are captured here so the interface is designed for it.
- Docs: clustering tutorial, quorum sizing, recovery runbook, HSM reachability requirement (all nodes must reach the same PKCS#11 HSM).
