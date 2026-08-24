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
- **Member bookkeeping**: an operator-facing name associated with each node's underlying dqlite node ID, since `go-dqlite`'s own `NodeInfo` carries only ID, address, and role.

### New Interfaces

#### API Endpoints

All endpoints in this table require admin authentication.

| API Endpoint | Request Body | Response |
|---|---|---|
| `POST /cluster/members/tokens` | `{"role": "voter" \| "standby", "ttl": "1h"}` | `{"token": "<single-use token>", "expires_at": "<timestamp>"}` |
| `POST /cluster/members/join` | `{"token": string, "csr": "<PEM-encoded CSR>", "address": string}` | `{"certificate": "<PEM-signed cert>", "members": ["<address>", ...]}` |
| `DELETE /cluster/members/{id}` | `?force=true` (optional query param) | N/A |
| `POST /cluster/members/{id}/promote` | N/A | N/A |
| `GET /cluster/members` | N/A | `{"members": [{"id", "name", "address", "role", "raft_state", "sealed", "last_seen"}, ...]}` |
| `GET /cluster/status` (modified from the existing `GET /status`) | N/A | `{ ..., "cluster": {"members": [...], "leader": "<id>"}}` |

`POST /cluster/members/tokens` and `POST /cluster/members/join` together replace the earlier single `POST /cluster/token` endpoint: token issuance is separated from the join/CSR exchange because the new node doesn't generate its keypair and CSR until it actually attempts to join, not at the point an operator requests a token on its behalf.

`DELETE /cluster/members/{id}` replaces `POST /cluster/remove`, following REST convention for the resource being deleted, and is a direct passthrough to `go-dqlite`'s own `client.Remove` — Notary does not add its own confirmation or quorum-projection logic on top of it.

#### CLI Arguments

Cluster operations are exposed as `notary cluster` subcommands rather than flags on `notary start`, so that join/bootstrap/removal/status each have their own argument shape without overloading a single command:

| Command | Parameters | Description |
|---|---|---|
| `notary cluster bootstrap` | N/A | Initializes a new cluster with this node as the sole voter. |
| `notary cluster token create` | `--role voter\|standby`, `--ttl 1h` | Generates a single-use join token. |
| `notary cluster join` | `<token> --address <existing-member-addr>` | Joins this node to the cluster identified by an existing member's address, using the given token. |
| `notary cluster promote` | `<member>` | Explicit override to promote a standby to voter ahead of automatic role convergence. |
| `notary cluster remove` | `<member> [--force]` | Removes a member. `--force` is required for a member that isn't reachable. |
| `notary cluster status` | N/A | Prints member name, role, Raft state, and seal state. |

At least one of `notary cluster bootstrap` or `notary cluster join` must be run once against an empty data directory before `notary start` will operate as part of a cluster.

### Configuration

The user provides cluster configuration under a `cluster` key in Notary's configuration file:

```yaml
cluster:
  enabled: true
  name: node-0
  address: 'https://192.168.1.0:8201'
  data-dir: /var/lib/notary/cluster
```

- **`enabled`** (optional, defaults to `false`): turns clustering on. When `false`, Notary behaves exactly as it does today — a single-node SQLite deployment via `db_path`, unaffected by anything in this document. Existing deployments require no configuration change.
- **`name`** (mandatory when `enabled: true`): the operator-facing identifier for this node, stored against its dqlite node ID in cluster membership bookkeeping. Used in `notary cluster status` output and in join/remove operations.
- **`address`** (mandatory when `enabled: true`): the address this node listens on for cluster-internal (Raft and join-protocol) traffic.
- **`data-dir`** (mandatory when `enabled: true`): where this node's dqlite/Raft state is stored.

Unlike the earlier MicroCluster-based draft, `db_path` is **not** removed. It remains the storage location for non-clustered deployments, which stay fully supported and unaffected by this feature being opted into elsewhere.

### Starting Up

Cluster membership is established through explicit subcommands rather than inferred from whether the data directory is empty — this avoids the ambiguity of silently discarding flags when they conflict with existing on-disk state.

#### New cluster

`notary cluster bootstrap` initializes `data-dir` as a new, single-voter cluster. It generates the cluster-internal PKI, starts dqlite via `app.New` with no `app.WithCluster(...)` (which is what makes it a bootstrap rather than a join), and applies the existing goose migrations against the resulting connection. The node serves traffic once its DEK unwrap completes (unrelated to clustering, unchanged from single-node behavior).

#### Joining an existing cluster

On any existing member: `notary cluster token create` generates a token. The operator transfers it out-of-band to the new node, along with the address of at least one existing member.

On the new node: `notary cluster join <token> --address <existing-member-addr>`. The new node generates its own keypair and CSR, and presents `{token, csr}` to the existing member's `POST /cluster/members/join` endpoint. The existing member validates the token (single-use, TTL-checked), signs the CSR against the cluster CA, and responds with the signed certificate and the current member address list. The new node then calls `app.New(..., app.WithCluster(peerAddrs))` — `go-dqlite`'s own join — and is added with role **standby** by default. Once joined, the operator-supplied `name` is recorded against the new node's dqlite ID in cluster membership bookkeeping.

If the token is invalid, expired, or already used, the existing member rejects the join and Notary logs the failure; the operator must issue a new token and retry.

#### Existing node

If `data-dir` is not empty, `notary start` resumes from the state already there — no `bootstrap` or `join` subcommand is needed or accepted. If cluster configuration in the config file differs from what's recorded in `data-dir` (e.g. a changed `address`), Notary logs a warning and continues using the on-disk state, consistent with the principle that cluster membership, once established, is authoritative over static configuration.

### Operation

On restart, a node resumes from its local dqlite state exactly as it would for the single-node case — `go-dqlite/app` handles this natively.

**Schema upgrades**: because Notary uses `goose` (unchanged) rather than MicroCluster's own schema-version-gated `Update` system, there is no built-in mechanism preventing a node running an older binary — with an older, unapplied set of migrations — from joining a cluster whose schema has already moved forward, or vice versa. This is addressed explicitly rather than left implicit: at join and at every startup, a node compares its own applied goose migration version against the version already active in the cluster (readable from any reachable member) and refuses to join or start if they don't match, logging the specific mismatch so the operator can upgrade nodes in the correct order. This replaces the automatic cross-member gating MicroCluster would otherwise have provided.

`notary cluster status` (and the extended `GET /cluster/status`) reports, per member: name, role (voter/standby), Raft state (leader/follower), seal state, and last-seen timestamp.

### Decommissioning

To remove a node, an operator sends `DELETE /cluster/members/{id}` (or runs `notary cluster remove <member>`) for the node's ID, as shown in `notary cluster status` output. For a reachable node being gracefully decommissioned, this triggers `app.Handover(ctx)` first — transferring leadership/voting rights away before the node is removed — followed by `client.Remove`. For an unreachable (dead) node, `--force` is required, which skips the handover step and removes the member directly.

Operators should not delete a node's `data-dir` directly as a way of removing it from the cluster — doing so leaves the remaining members with a stale view of membership and can affect quorum accounting. `DELETE /cluster/members/{id}` (with `--force` if necessary) works for a member in any status, including one that is currently down, and is the only supported removal path.
