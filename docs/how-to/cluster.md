# Run a Notary cluster

This guide starts two Notary nodes that share one dqlite cluster. The commands match LXD: `cluster add`, start with `--join`, `cluster list`, and `cluster remove`.

HTTPS certificates (`cert_path` / `key_path`) stay per node or load balancer. Cluster TLS is a different pair used only for dqlite. The join token is a **one-time ticket**, not the cluster private key. `notary start --join` redeems that ticket over HTTPS (the existing API, pinned by the token fingerprint) and then joins dqlite. See [Configuration file](../reference/config_file.md).

## Prerequisites

* Notary installed on each machine
* Network connectivity on the dqlite address (`cluster.address`, default `9000`) **and** on the HTTPS API port (`port`). The dqlite port is a member-only database/replication port: restrict it to cluster members. It speaks the dqlite protocol with cluster TLS. dqlite has no application-level authentication; TLS trust on this port **is** authorisation. A join token only constrains `notary start --join`.
* The joiner must be able to reach an existing member's HTTPS API. The token fingerprint is the SHA-256 of that member's **HTTPS** certificate (`cert_path`).

The first node generates a shared cluster certificate on first start if you omit `cluster.tls`. You can instead supply your own shared pair (DNS SAN required), or use [CA mode](#ca-mode-dedicated-cluster-ca) with per-unit leaves:

```shell
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 \
  -nodes -keyout cluster.key -out cluster.crt -subj "/CN=notary-cluster" \
  -addext "subjectAltName=DNS:localhost,DNS:notary-cluster,IP:10.0.0.1,IP:10.0.0.2"
```

## 1. Start the first node

Use an empty data directory. Set `cluster.name` (like LXD's server name). Do **not** pass `--join`. `cluster.tls` is optional on this node.

```yaml
key_path: "/etc/notary/config/key.pem"
cert_path: "/etc/notary/config/cert.pem"
db_path: "/var/lib/notary/database"
cluster:
  name: "node1"
  address: "10.0.0.1:9000"
port: 3000
encryption_backend:
  type: "none"
```

```shell
notary start --config /etc/notary/config/config.yaml
```

Notary writes `cluster.crt` and `cluster.key` into `db_path`. Later starts reload them from that directory.

If this data directory was created before cluster TLS (a one-node store with no `cluster.crt`), resume stays plaintext and `notary cluster add` fails until you set `cluster.tls` in the YAML and restart. That restart writes the files into `db_path`.

## 2. Add a member and join

On a machine that is already in the cluster (daemon running), create a join token. This is the same idea as `lxc cluster add`:

```shell
notary cluster add node2 --config /etc/notary/config/config.yaml
```

The command prints a one-time token (valid for three hours). Until it is redeemed or expires, it is a bearer credential: anyone who presents it to an existing member's HTTPS API receives the **shared** cluster private key (default mode). In CA mode the response is dqlite addresses only; the joiner must already have `ca_path`, its unit leaf, and `peer_san`. After a successful join the token is spent.

On the second machine, use a **new empty** data directory and the name from `cluster add`. Do not copy cluster TLS files. Point HTTPS certs at this node's files:

```yaml
key_path: "/etc/notary/config/key.pem"
cert_path: "/etc/notary/config/cert.pem"
db_path: "/var/lib/notary/database"
cluster:
  name: "node2"
  address: "10.0.0.2:9000"
port: 3000
encryption_backend:
  type: "none"
```

```shell
notary start --config /etc/notary/config/config.yaml --join '<token>'
```

You can also set `cluster.join_token` in the YAML instead of `--join`. The token is used only on first start. After `info.yaml` exists in `db_path`, the node resumes without it.

If redeem succeeds but `notary start --join` then fails to reach dqlite, the token is spent. Run `cluster add` again for a new token. If redeem itself cannot list members (leadership moving at that instant), Notary restores the token and you can retry the same one.

If you set shared `cluster.tls` on the joiner, it must match the cluster certificate returned after redeeming the token. Joining with `cluster.join` addresses and no token still requires `cluster.tls` files (shared pair or CA mode).

Set `external_hostname` (host or `host:port`) when joiners should redeem against a public API address. Required when `cluster.address` is a wildcard bind (`0.0.0.0` or `::`). The default `localhost` is not enough: join tokens must not tell another machine to dial loopback.

## CA mode (dedicated cluster CA)

Notary can authenticate dqlite peers with per-unit certificates signed by an **external** cluster CA. Notary does not mint or revoke that CA. Do not reuse the HTTPS API CA.

```yaml
cluster:
  name: "node2"
  address: "10.0.0.2:9000"
  tls:
    ca_path: "/etc/notary/cluster-ca.crt"
    cert_path: "/etc/notary/unit.crt"
    key_path: "/etc/notary/unit.key"
    peer_san: "notary-cluster"
```

All four fields are required; `peer_san` has no silent default. Every leaf must carry that group SAN (DNS or URI). Host and IP SANs must match how you write `cluster.address` (an IP bind needs an IP SAN). CA mode never stores the unit key as `db_path/cluster.key`. Mix a CA member with a shared-pair member: the handshake fails.

A name-constrained intermediate (limited to `notary-cluster` or your cluster DNS) is recommended so this CA cannot issue names for the HTTPS API.

## 3. List members

With the daemon running:

```shell
notary cluster list --config /etc/notary/config/config.yaml
```

Or, as an admin, open **Cluster** in the web UI (same columns as this table), or `GET /api/v1/cluster`. You should see both names, each member's dqlite `address` and HTTPS `api_address`, and one leader. The UI can also mint a join token and remove a member.

A two-node cluster typically shows the joiner as a **spare**, not a second voter. dqlite promotes voters automatically (up to three). Add a third member the same way (`cluster add` / `--join`) when you want that quorum.

## 4. Remove a member

Like `lxc cluster remove`:

```shell
notary cluster remove node2 --config /etc/notary/config/config.yaml
```

Then stop Notary on the machine you removed. You cannot remove the last remaining member.

Stopping it is not tidiness. Removal evicts the node from raft, but its API keeps working: it still holds cluster TLS and the addresses of the other members, so it goes on serving reads and writes against the cluster as a client. Until you stop the process, that machine is a live entry point into a cluster it is no longer a member of.

In **CA mode**, stopping is not enough to revoke the unit. After `cluster remove`, stop the process **then revoke or expire that unit's cluster leaf** at your CA. Until you do, a process that still has the leaf can `Add` itself on the dqlite port: TLS trust is authorisation. Shared-pair mode has the same property for anyone who holds `cluster.key`.

If a join dies after dqlite has already added the node (for example `notary start --join` times out waiting for the cluster), `cluster list` may show a member with no name. Remove it by address:

```shell
notary cluster remove 10.0.0.2:9000 --config /etc/notary/config/config.yaml
```

## 5. Stop a node

Stop the process (Ctrl+C, or your systemd/snap stop). Notary hands cluster roles to another node when one is available, then closes dqlite.

After a clean stop, start again with the same `db_path`, `cluster.name`, and `cluster.address`. You do not need `--join` again.

## 6. Add a third member (quorum)

Two nodes are not highly available: the joiner is usually a spare. Add a third member the same way (`cluster add` / `--join`) and wait until `cluster list` shows three **voter** roles. go-dqlite promotes voters on its own; do not start three empty data directories at once (each would bootstrap a separate cluster).

```shell
notary cluster add node3 --config /etc/notary/config/config.yaml
# on the third machine, empty db_path:
notary start --config /etc/notary/config/config.yaml --join '<token>'
```

## ACME signing

ACME signing (`signing_method=acme`) runs only on the dqlite leader so nodes do not race the same public CA order. A follower returns HTTP 409 and the leader's HTTPS API address when that address is known (otherwise the leader's dqlite address). Certificate Authority signing can use any member.

Do not put ACME `POST /api/v1/certificate_requests/{id}/sign` behind a load balancer that hides which member you reached. The 409 names a host:port the **cluster** recorded; that address may not be reachable from a client that only knows the VIP. Call ACME signing **directly on a member** (retry on the address in the 409). Internal CA signing can use the VIP.

## Operator runbooks

### Replace a dead node

1. `notary cluster remove <name-or-dqlite-address>` on a surviving member (daemon running).
2. On the replacement machine, use an **empty** `db_path` and the **same** `cluster.name`.
3. `notary cluster add <name>` then `notary start --join '<token>'`.

### Back up a cluster

Stop **one follower** (not the only remaining voter), take a cold `notary backup` of that member's `db_path`, then start it again. Do not copy a live directory, and do not take this backup while another voter is already down. See [Back up and restore Notary](backup_restore.md). To put a replacement machine in the cluster, `cluster remove` then join with a fresh token and empty `db_path`; do not restore a follower archive onto a new identity.

### Recover from quorum loss

When too many members are gone to elect a leader, the survivors are read-only. Force one of them back into a writable single-member cluster.

1. Stop Notary on **every** remaining machine. `notary cluster recover` refuses to run against a data directory that a daemon still holds.
2. On each survivor, read its raft position:

   ```shell
   notary cluster recover --config /etc/notary/config/config.yaml
   ```

   Without `--force` this only reports `term` and `index`.
3. Pick the member with the highest term, then the highest index. Run it there with `--force`:

   ```shell
   notary cluster recover --config /etc/notary/config/config.yaml --force
   ```

4. Start Notary on that machine. It is now the only member and accepts writes.
5. Rejoin the other machines with an **empty** `db_path` and a fresh `notary cluster add` token.

This is destructive. Writes the lost majority had committed but never replicated to the recovered member are discarded, so always recover from the member that is furthest ahead.

### Metrics

Gauges are computed from the replicated database. Scrape **one** member only. Three Prometheus targets triple-count the same certificates. Pebble notices stay local to the process that emitted them.

### Audit logs

Audit logs are per node. Ship and aggregate them externally if you need a single compliance trail.

### Encryption backend

Every member must use the **same** `encryption_backend` configuration. The data-encryption key is stored in dqlite; a joiner that cannot decrypt it will not start. This is a hard precondition, not a suggestion.

### Schema upgrades

Goose migrations take a cluster-wide lock. Rolling upgrades are safe only for additive schema (new tables, `ADD COLUMN` with a default). Older binaries keep serving while a newer member applies that kind of migration. Do not drop or rename columns while mixed versions are running.

## Not in this release

* Live online `Dump()` of a running voter — stop a follower and take a cold backup instead.
* An extra ACME lock row — signing is a leader gate; retry on the member named in the 409.
