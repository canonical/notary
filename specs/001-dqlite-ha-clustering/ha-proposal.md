# High Availability for Notary

## Abstract

High Availability in Notary is facilitated by [dqlite](https://github.com/canonical/dqlite), accessed directly through [go-dqlite](https://github.com/canonical/go-dqlite)'s `app` package — **not** through `canonical/microcluster`. dqlite provides Raft consensus for a replicated embedded database; `go-dqlite/app` provides node bootstrap, join, automatic voter/standby role management, and leadership handover as library primitives. What MicroCluster would otherwise have supplied on top of that — join-token issuance, trust distribution, and cluster membership bookkeeping — is implemented directly in Notary. The user experience is unchanged from what was originally scoped: the operator supplies cluster configuration, and Notary automatically initializes and operates as part of a Raft cluster, joins by token, and can be inspected and managed through the same shape of CLI, API, and status surface.

## Rationale

High availability is crucial for ensuring the reliability of web services, reducing downtime, and maintaining consistent performance under load. Without HA, a single point of failure can render the application unavailable, affecting users and business operations. Raft-based replication of the embedded database gives Notary automatic leader election, distributed replication, and fault tolerance without requiring an external database cluster the operator has to run and maintain separately.

### Why not `canonical/microcluster`

An earlier draft of this design used MicroCluster directly, on the assumption — stated in an earlier version of this document — that its SQL connector could be substituted for the existing `mattn/go-sqlite3` driver with no change to how Notary executes SQL. That assumption does not hold, and it's worth being precise about why, since it's the reason this document looks different from that earlier draft.

MicroCluster's only public database primitive is:

```go
Transaction(ctx context.Context, f func(context.Context, *sql.Tx) error) error
```

There is no `*sql.DB` accessor anywhere in its public API. Two things Notary depends on — `sqlair` (the query/struct-mapping library used throughout `internal/db`) and `goose` (schema migrations) — both require a genuine `*sql.DB`: they call `Begin()` themselves and hold the resulting transaction open across multiple, separately-timed calls, deciding what to do next based on earlier results. MicroCluster's `Transaction()` doesn't support that usage pattern — it expects the *entire* unit of work as one complete function, and on a transient error (a busy/locked condition, a leadership change mid-request) it may **discard that attempt and call the function again from scratch**, with a fresh `*sql.Tx`, up to 250 times. A generic adapter that tries to make this look like a normal `Begin()`/`Commit()` handle to outside callers cannot safely guarantee exactly-once execution: a caller can be told a write succeeded, and then have the closure silently replayed without it, because the caller has no way to know a replay happened. This isn't a theoretical concern — it was traced through to a concrete silent-data-loss scenario before this design changed course.

Two mitigations were evaluated and rejected before settling on the approach below:

- **`sqlx`** (a different, popular Go SQL convenience library) can wrap an externally-obtained `*sql.Tx` — unlike `sqlair`, its `Tx` type embeds `*sql.Tx` via an exported field, so it doesn't need to own `Begin()` itself. This would have let `sqlair` be replaced with something MicroCluster-compatible while keeping struct-mapping convenience. It was set aside because its upstream has had no commits in over two years — a real risk to take on in exchange for MicroCluster's plumbing.
- **`sqlc`**, a SQL code generator, was verified directly against Notary's actual queries — including its recursive CTEs (used for certificate-chain traversal) — and works correctly, with one specific, fixable requirement (column references in a recursive CTE's anchor branch must be table-qualified for `sqlc`'s SQLite analyzer). It is actively maintained (commits as recent as the day this was checked). It was still set aside: adopting it means porting roughly 60 existing SQL statements, introducing a code-generation step into the build, and maintaining a schema file kept in sync with the actual migration source of truth — real, ongoing cost, for the sole purpose of making MicroCluster's plumbing usable. That cost was judged larger than simply building Notary's own thin membership layer directly on `go-dqlite/app`, which needs none of it.

`go-dqlite/app` — the lower-level package MicroCluster itself is built on — solves the underlying problem directly: `app.Open(ctx, name)` returns a genuine `*sql.DB`, backed by a standard, complete `database/sql` driver implementation, with normal `Begin()`/`Commit()` semantics and no replay behavior. `sqlair` and `goose` work against it completely unmodified. The trade is that Notary owns the membership/token/PKI layer MicroCluster would otherwise have supplied — a small, well-understood piece of new code, detailed below, rather than a data-layer migration.

## Specification

### Glossary

- **Node**: a unique running process of Notary that is connected to a cluster.
- **Cluster**: a group of connected nodes.
- **Voter**: a node that participates in Raft consensus (leader election, log replication, quorum).
- **Standby**: a node that replicates the full log but does not vote. Exists so a lost voter can be healed by promotion rather than a fresh join.

### Solution

Notary uses `github.com/canonical/go-dqlite/v3/app` directly to run each node's Raft-replicated database. `app.Open(ctx, "notary")` returns the `*sql.DB` that `sqlair` and `goose` already run against today — **no change in how Notary executes SQL**, which is the same goal the original MicroCluster-based design had, achieved through a different mechanism.

What Notary provides on top of `go-dqlite/app`, since MicroCluster is not present to supply it:

- **Cluster-internal PKI**: a root CA and per-node mTLS certificate, generated and managed by Notary, entirely separate from Notary's product-facing certificate-issuance PKI. No cluster-membership credential is ever valid for product certificate issuance, and no issued product certificate is valid against the cluster's internal root.
- **Join-token issuance and validation**: single-use, time-limited tokens, generated by an existing member and validated by whichever member the new node contacts.
- **Trust distribution**: a join endpoint that accepts a new node's CSR alongside its token, validates the token, and signs the CSR against the cluster CA.
- **Member bookkeeping**: an operator-facing name associated with each node's underlying dqlite node ID, since `go-dqlite`'s own `NodeInfo` carries only ID, address, and role. The same records carry each member's heartbeat and seal state, which is what makes liveness observable without polling.

### New Interfaces

#### API Endpoints

Paths are shown without their `/api/v1` prefix, and every response is wrapped in Notary's standard
`{"message": ..., "data": ...}` envelope; the `Response` column describes the `data` field.

All endpoints in this table require an admin session **except `POST /cluster/members/join`**, which
sits outside session authentication entirely: a node that has not joined yet has no account on the
cluster it is joining, so requiring one would make joining impossible. The single-use,
time-limited join token is that route's whole credential, and the only thing it will do with it is
sign a CSR against the cluster CA. Every route returns `404` when clustering is disabled.

| API Endpoint | Request Body | Response (`data`) |
|---|---|---|
| `POST /cluster/members/tokens` | `{"role": "voter" \| "standby", "ttl_seconds": int}` | `{"token": "<single-use token>", "role": string, "expires_at": <unix seconds>}` |
| `POST /cluster/members/join` | `{"token": string, "csr": "<PEM-encoded CSR>", "address": string, "schema_version": int}` | `{"certificate": "<PEM>", "ca_certificate": "<PEM>", "role": string, "member_addresses": ["<address>", ...]}` |
| `DELETE /cluster/members/{id}` | `?force=true` (optional query param) | N/A |
| `POST /cluster/members/{id}/promote` | N/A | N/A |
| `GET /cluster/members` | N/A | `[{"id", "name", "address", "role", "leader", "sealed", "last_seen", "status", "message"}, ...]` |
| `GET /cluster/status` | N/A | `{"enabled", "node_id", "address", "leader_id", "voters", "members": [...]}` |

`ca_certificate` is not optional detail: it is how the joining node obtains the cluster's trust
anchor, having had none before.

`GET /cluster/status` is a new endpoint rather than a modification of `GET /status`. The existing
`GET /status` is separately extended with this node's own `node_id`, `role`, `raft_state` and
`sealed`, so a single node can be checked without an admin session.

`POST /cluster/members/tokens` and `POST /cluster/members/join` together replace the earlier single `POST /cluster/token` endpoint: token issuance is separated from the join/CSR exchange because the new node doesn't generate its keypair and CSR until it actually attempts to join, not at the point an operator requests a token on its behalf.

`DELETE /cluster/members/{id}` replaces `POST /cluster/remove`, following REST convention for the resource being deleted, and is a direct passthrough to `go-dqlite`'s own `client.Remove` — Notary does not add its own confirmation or quorum-projection logic on top of it.

#### CLI Arguments

Cluster operations are exposed as `notary cluster` subcommands rather than flags on `notary start`, so that join/bootstrap/removal/status each have their own argument shape without overloading a single command:

| Command | Parameters | Description |
|---|---|---|
| `notary cluster bootstrap` | `--config`, `--name` | Initializes a new cluster with this node as the sole voter. |
| `notary cluster token create` | `--config`, `--token`, `--role voter\|standby`, `--ttl 1h`, `--quiet` | Generates a single-use join token. `--quiet` prints only the token, for scripting. |
| `notary cluster join` | `<token>`, `--config`, `--address <existing-member-addr>`, `--name`, `--ca-cert` | Joins this node to the cluster identified by an existing member's address, using the given token. |
| `notary cluster promote` | `<member>`, `--config`, `--token` | Explicit override to promote a standby to voter ahead of automatic role convergence. |
| `notary cluster remove` | `<member>`, `--config`, `--token`, `[--force]` | Removes a member. `--force` is required for a member that isn't reachable. |
| `notary cluster status` | `--config`, `--token` | Prints each member's name, address, role, leadership, seal state, and ONLINE/OFFLINE state. |
| `notary cluster restore` | `--config`, `--file` | Disaster recovery: rebuilds a cluster from a `notary backup` archive as a fresh single node. Out of scope for this document; see spec.md §7. |

`--config` is required by every subcommand. The subcommands that drive an already-running node go
through its admin API rather than opening dqlite themselves — the running node holds its data
directory open — so they also take `--token` (or `NOTARY_TOKEN`). `bootstrap` and `join` are the
exceptions: they run against a node that is not yet serving, and open dqlite directly.

`--name` is where a member's operator-facing name comes from, on both `bootstrap` and `join`. It
defaults to the node's cluster address.

At least one of `notary cluster bootstrap` or `notary cluster join` must be run once against an empty `state_dir` before `notary start` will operate as part of a cluster.

### Configuration

The user provides cluster configuration under a `cluster` key in Notary's configuration file:

```yaml
cluster:
  enabled: true
  address: '192.168.1.10:9000'
  state_dir: /var/lib/notary/cluster
```

- **`enabled`** (optional, defaults to `false`): turns clustering on. When `false`, Notary behaves exactly as it does today — a single-node SQLite deployment via `db_path`, unaffected by anything in this document. Existing deployments require no configuration change.
- **`address`** (mandatory when `enabled: true`): the `host:port` this node listens on for cluster-internal (Raft and join-protocol) traffic. It is a bare address, not a URL — no scheme.
- **`state_dir`** (mandatory when `enabled: true`): where this node's dqlite/Raft state and its cluster-internal PKI are stored.

There is deliberately no `name` key. A member's operator-facing name is supplied once, by `--name`
on `bootstrap` or `join`, and recorded in the cluster database from then on; putting it in a file
that can be edited later would invite it drifting from what the cluster actually has recorded.

Unlike the earlier MicroCluster-based draft, `db_path` is **not** removed. It remains the storage location for non-clustered deployments, which stay fully supported and unaffected by this feature being opted into elsewhere.

### Starting Up

Cluster membership is established through explicit subcommands rather than inferred from whether `state_dir` is empty — this avoids the ambiguity of silently discarding flags when they conflict with existing on-disk state.

#### New cluster

`notary cluster bootstrap` initializes `state_dir` as a new, single-voter cluster. It generates the cluster-internal PKI, starts dqlite via `app.New` with no `app.WithCluster(...)` (which is what makes it a bootstrap rather than a join), applies the existing goose migrations against the resulting connection, and records this node's `--name` against its dqlite node ID. The node serves traffic once its DEK unwrap completes (unrelated to clustering, unchanged from single-node behavior).

#### Joining an existing cluster

On any existing member: `notary cluster token create` generates a token. The operator transfers it out-of-band to the new node, along with the address of at least one existing member.

On the new node: `notary cluster join <token> --address <existing-member-addr>`. The new node generates its own keypair and CSR, and presents `{token, csr, address, schema_version}` to the existing member's `POST /cluster/members/join` endpoint. The existing member validates the token (single-use, TTL-checked), then checks the declared schema version against the cluster's own, signs the CSR against the cluster CA, and responds with the signed certificate, the cluster CA certificate, and the current member address list. The new node then calls `app.New(..., app.WithCluster(peerAddrs))` — `go-dqlite`'s own join — and is added with role **standby** by default. Once joined, the name given by `--name` is recorded against the new node's dqlite ID in cluster membership bookkeeping.

If the token is invalid, expired, or already used, the existing member rejects the join and Notary logs the failure; the operator must issue a new token and retry. A join refused for a schema-version mismatch consumes the token as well, since the token is redeemed before the version is compared — deliberately, so that the cluster's schema version is not readable by anyone who can reach an unauthenticated endpoint.

#### Existing node

If `state_dir` is not empty, `notary start` resumes from the state already there — no `bootstrap` or `join` subcommand is needed or accepted. Cluster membership, once established, is authoritative over static configuration: the advertised address is recorded in the node's own dqlite state at bootstrap or join, and `go-dqlite` refuses to start a node whose configured `cluster.address` no longer matches it. Changing a member's address is therefore a remove-and-rejoin, not a config edit.

### Operation

On restart, a node resumes from its local dqlite state exactly as it would for the single-node case — `go-dqlite/app` handles this natively.

**Schema upgrades**: because Notary uses `goose` (unchanged) rather than MicroCluster's own schema-version-gated `Update` system, there is no built-in mechanism preventing a node running an older binary — with an older, unapplied set of migrations — from joining a cluster whose schema has already moved forward, or vice versa. This is addressed explicitly rather than left implicit: a node compares the newest migration version compiled into its own binary against the version actually applied to the replicated database, and refuses to serve on a mismatch, naming both versions in the failure. The same comparison runs at both points a mismatched node could get in — at startup, against the cluster's applied version, and at join, against the version the joining node declares in its request. An operator upgrades nodes one at a time, and a node carrying a stale or ahead-of-cluster schema simply won't start. This replaces the automatic cross-member gating MicroCluster would otherwise have provided.

**Member liveness**: each member records its own heartbeat and seal state in the replicated
database on a timer, and every other member reads them back through replication rather than by
polling anyone. A member that stops writing ages out and is reported `OFFLINE` once its last
heartbeat is older than the offline threshold; writing a heartbeat at all is itself proof that the
member can still reach the Raft leader. This is the same model, and the same `STATE`/`MESSAGE`
presentation, that `lxc cluster list` uses.

`notary cluster status` (and `GET /cluster/members`) reports, per member: name, address, role
(voter/standby/spare), whether it is the current Raft leader, seal state, last-seen timestamp, and
an `ONLINE`/`OFFLINE` state with a human-readable message.

### Decommissioning

To remove a node, an operator sends `DELETE /cluster/members/{id}` (or runs `notary cluster remove <member>`) for the node's ID, as shown in `notary cluster status` output. For a reachable node being gracefully decommissioned, this triggers `app.Handover(ctx)` first — transferring leadership/voting rights away before the node is removed — followed by `client.Remove`. For an unreachable (dead) node, `--force` is required, which skips the handover step and removes the member directly.

Operators should not delete a node's `state_dir` directly as a way of removing it from the cluster — doing so leaves the remaining members with a stale view of membership and can affect quorum accounting. `DELETE /cluster/members/{id}` (with `--force` if necessary) works for a member in any status, including one that is currently down, and is the only supported removal path.
