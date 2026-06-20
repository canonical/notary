## Context

Notary must survive node failure in any deployment shape — snap on machines, container, or Kubernetes. Clustering ships in the binary, following the microcluster pattern (MicroCeph, MicroOVN, Canonical Kubernetes; the design LXD pioneered): forming a cluster and changing membership are operator actions performed through Notary's own flags and API, while leader election, failover, and voter/standby role management are automatic. No external database, coordination service, or orchestrator is involved. This change covers the *self-contained* storage family (single node and clustered — one engine, one growth path); a third deployment mode, outsourcing storage to an external PostgreSQL operated centrally (e.g. by a data-platform charm), is planned as a separate change (`add-external-db-backend`) branching off `harden-storage-correctness`, and the decisions here must not foreclose it. Notary's data is a security ledger — an unrecorded issued certificate or a lost revocation is a security incident, so replication must be quorum-based (CP), not async failover. The storage stack today: SQLite via `modernc.org/sqlite`, sqlair prepared statements, goose migrations, an embedded OpenFGA sharing the same `*sql.DB`, and backup via `VACUUM INTO`. `harden-storage-correctness` (prerequisite) removes the single-process assumptions; this change replaces the storage engine and adds the cluster control plane.

## Goals / Non-Goals

**Goals:**
- Survive loss of a minority of nodes with zero committed-write loss and automatic failover, in any deployment environment (machine, container, Kubernetes).
- Cluster lifecycle operable through Notary's own flags, CLI, and API — interactively and by automation.
- Single-node stays first-class and ceremony-free.
- Self-contained: no external database or coordination service.

**Non-Goals:**
- The external-database (PostgreSQL) backend — separate change (`add-external-db-backend`), gated on its own feasibility spike. This change only keeps that door open: portable SQL migrations, a config namespace that admits a backend discriminator, engine specifics contained in the storage seam. No engine-migration path between self-contained and external modes is planned initially; that trade-off is accepted and documented.
- The charm implementation itself (separate repo; its requirements are specified here).
- Read scaling / performance (HA is the goal; a CA's load doesn't need scale-out).
- Multi-region / geo-replication.
- Preserving the `db_path` config or pure-Go builds (**breaking**, accepted — no production customers).

## Decisions

**dqlite + microcluster, not raw go-dqlite, not Postgres, not active/passive.**
- Postgres would outsource HA to an external database the user must operate; contradicts Notary's self-contained deployment story. OpenFGA compatibility is the one argument for it — kept as fallback (below).
- Active/passive async replication keeps most of the operational complexity (fencing, failover orchestration) while retaining nonzero RPO on exactly the writes that must not be lost. Rejected.
- Raw `go-dqlite app.App` would require hand-rolling join tokens, member mTLS, and coordinated schema upgrades — re-growing microcluster badly. Microcluster (`/v3`, latest tagged line — the `/v4` module path exists but has no releases yet) provides membership + tokens + member TLS + `schema.Update` coordination + lifecycle hooks, and is the established Canonical pattern (MicroCeph/MicroOVN/MicroCloud).

**dqlite-only within the self-contained family; no plain-SQLite production mode.** Every self-contained deployment is a cluster; single node = 1 voter (LXD model). Rationale: no production customers exist, so the breaking change is nearly free now and never gets cheaper; a sqlite/dqlite dual mode would place a real migration (downtime, import, reconfiguration) exactly on the standalone→HA growth path that 1-voter makes free, while buying comfort rather than capability — unlike the external-DB mode, which serves a persona dqlite cannot. Costs accepted: CGo + `libdqlite` in all release builds, and the state directory is not an openable SQLite file (see Risks). **Testing nuance:** the SQL dialect is identical, so fast unit tests (`internal/db`, handlers) may keep running against in-memory `modernc.org/sqlite`; a dedicated integration suite runs against real dqlite clusters. `modernc` becomes a test-only dependency, also used read-only by `--from-db` import (`mattn/go-sqlite3` is removed entirely by `harden-storage-correctness`).

**Process topology.** One binary, one process per node. Microcluster daemon owns: state directory, dqlite, member mTLS, internal cluster API (cluster port), join/remove operations, schema upgrades. Notary's existing HTTPS API server runs in the same process (started from microcluster's `OnStart` hook), keeps its own port and its own TLS cert from Notary config. Two TLS identities, deliberately separate: cluster mTLS is machinery (microcluster-managed), API TLS is user-facing (operator-managed).

**Config** (aligned with the team spec). `db_path` is removed. New mandatory section:

```yaml
high-availability:
  node-id: node-0          # stable member identity, chosen by the operator or deployment automation
  storage-path: /var/lib/notary/state   # microcluster state directory (includes the database)
  cluster-address: 'https://192.168.1.10:8201'  # server-to-server address of this node
```

`node-id` is mandatory (deterministic identity beats auto-generated names for automated deployments). `cluster-address` SHOULD default to a loopback address:port when omitted, so a standalone node needs nothing beyond `node-id`, `storage-path`, and `--new-cluster` — a deliberate refinement of the team spec (which marks it mandatory) to keep single-node ceremony-light; multi-node members must set a peer-reachable address. Note: the section applies to single-node deployments too — the name `high-availability` is slightly misleading but kept for consistency with the team spec. This section also implies the default *self-contained* storage backend; the planned external-database mode (`add-external-db-backend`) will add a sibling config block, mutually exclusive with this one, rather than reshaping it. On a node with a non-empty storage-path, the recorded cluster state is authoritative; deviating config values are ignored with a warning.

**Cluster lifecycle surface** (aligned with the team spec; replaces the earlier `notary cluster bootstrap|join` command design). Initialization is via startup flags: with an empty storage-path, exactly one of `--new-cluster` (`-n`) or `--join <token>` (`-j`) is required — requiring the flag explicitly (rather than implicit bootstrap) prevents a unit that lost its volume from silently forming a second, split cluster when it should have rejoined. With a non-empty storage-path the flags are ignored with a logged warning, making restarts idempotent for automation. Runtime operations are admin-authenticated API endpoints: `POST /cluster/token {node-id}` returns a base64 join token (single-use, 5-minute expiry; the joiner's configured node-id must match), `POST /cluster/remove {node-id}` removes a member in any status (graceful handover for live members, force removal for down ones — one interface, two paths underneath), and `GET /cluster/status` gains a `cluster-state` section. `notary cluster list` remains as a CLI convenience over the status endpoint.

**Migrations: goose stays the source of truth; microcluster coordinates.** Both migration sets — Notary's and OpenFGA's — keep their goose SQL files and separate bookkeeping tables (per `harden-storage-correctness`) and run inside microcluster `schema.Update` wrappers: coordinated cluster-wide by microcluster, tracked by goose. This treats both subsystems uniformly, avoids rewriting migration history into Go functions coupled to microcluster, and keeps migrations as portable SQL — the format a future external-DB backend can carry as a per-dialect directory. `notary migrate` CLI is reduced to status/inspection; upgrades apply migrations via the coordinated path.

**Quorum-loss read behavior.** Distribution endpoints (CRL, certificate download) read from the local replica and keep serving without quorum — signed artifacts with validity windows are stale-tolerant by design (decided with user). Everything requiring consistency (issuance, revocation, login-affecting reads like user records) requires quorum. Implementation direction: a dedicated read path/connection with dqlite stale-read semantics for the distribution endpoints only.

**Backup/restore.** `VACUUM INTO` and the SQLite backup API don't exist in dqlite. Backup = dump via dqlite client API from the leader, wrapped in the existing tar.gz format. Restore = recovery flow: fresh 1-node cluster from dump, others rejoin. `--from-db` import: open the legacy file read-only with the test driver, dump, load into a fresh cluster — reusing the restore machinery.

**Kubernetes identity.** Member identity lives in the state directory; the charm must use a StatefulSet-with-PVC shape so a rescheduled pod resumes its identity. Uncleanly lost units are forcibly removed by the charm (or operator). This constraint is exported to the charm repo via the `cluster-membership` spec.

## Risks / Trade-offs

- **[HIGH] OpenFGA over dqlite is unproven.** Two findings narrow the risk: Notary already injects its `*sql.DB` via `ofgaSqlite.NewWithDB` (no URI/DSN opening to intercept), and OpenFGA's connection-level pragma handling (`journal_mode(WAL)`, `busy_timeout`, `_txlock=immediate` in `PrepareDSN`) lives only in the URI path `New()`, which Notary doesn't use. Remaining unknowns are its query shapes (squirrel-built SQL, `ON CONFLICT`, index creation in migrations) and transaction behavior over dqlite. Mitigation: task 1 is a spike (concretely defined in tasks group 1) with explicit go/no-go criteria; fallback options, in order: patch/wrap the datastore, vendor a dqlite-compatible datastore implementation, or (last resort) revisit Postgres — a spike failure pauses the change rather than surprising it mid-flight.
- **sqlair over dqlite** — lower risk (standard `database/sql`), same spike covers it. Watch: `PRAGMA foreign_keys` handling and `BeginTx` behavior.
- **CGo everywhere**: slower builds, cross-compilation pain, `libdqlite` version coupling with snap/rock bases. Accepted; standard at Canonical.
- **Write latency** rises to raft-quorum fsync per commit — irrelevant at CA write rates but must be bounded in the API-timeout sense; quorum-loss failures must be prompt (spec requires bounded-time errors).
- **Stale distribution reads** can serve a CRL missing a very recent revocation during quorum loss. Accepted deliberately: identical exposure to CRL client-side caching, and strictly better than serving nothing.
- **State directory opacity.** Unlike a plain SQLite file, dqlite's raft log/snapshot storage cannot be opened with the `sqlite3` CLI for ad-hoc inspection or recovered by copying a file. Accepted for the self-contained model; mitigations: `notary backup` produces a plain openable SQLite dump, and the recovery runbook (task 6.4) covers the failure modes that file-copying used to.

## Resolved Questions

- **node-id in a certificate SAN — resolved: microcluster-internal, self-healing, no operator action.** The team spec's requirement that the node-id appear in "the SAN of the certificate of the new node" describes microcluster's own machinery, verified against microcluster v3.1.0 source: on init, if the member name is missing from the self-generated cluster cert's DNS SANs, microcluster deletes and regenerates its keypair with the member name as CN/SAN (`internal/rest/resources/control.go:141-156`); the cluster side validates the joiner's cert SANs contain the member name on join (`cluster.go:150`); internal TLS uses the cert's first DNSName as ServerName (`client/tls.go:40`). This applies to the *cluster* certificate microcluster manages in the state directory — never to the operator-provided API certificate. The two-TLS-identity design stands unchanged; the team spec's wording should be clarified so operators don't conclude their API cert needs the node-id.
