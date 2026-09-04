# Run a Notary cluster

This guide starts two Notary nodes that share one dqlite cluster. The commands match LXD: `cluster add`, start with `--join`, `cluster list`, and `cluster remove`.

HTTPS certificates (`cert_path` / `key_path`) stay per node or load balancer. Cluster TLS is a different pair used only for dqlite. The join token is a **one-time ticket**, not the cluster private key. `notary start --join` redeems that ticket over HTTPS (the existing API, pinned by the token fingerprint) and then joins dqlite. See [Configuration file](../reference/config_file.md).

## Prerequisites

* Notary installed on each machine
* Network connectivity on the dqlite port (`cluster.address`, default `9000`) **and** on the HTTPS API port (`port`)
* The joiner must be able to reach an existing member's HTTPS API. The token fingerprint is the SHA-256 of that member's **HTTPS** certificate (`cert_path`).

The first node generates a cluster certificate on first start if you omit `cluster.tls`. You can instead supply your own pair (DNS SAN required):

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

The command prints a one-time token (valid for three hours). Until it is redeemed or expires, it is a bearer credential: anyone who presents it to an existing member's HTTPS API receives the cluster private key. After a successful join it is spent and cannot hand out the key again.

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

If you set `cluster.tls` on the joiner, it must match the cluster certificate returned after redeeming the token. Joining with `cluster.join` addresses and no token still requires `cluster.tls` files.

Set `external_hostname` (host or `host:port`) when joiners should redeem against a public API address. Required when `cluster.address` is a wildcard bind (`0.0.0.0` or `::`); otherwise the join token would tell the joiner to dial an address that is not reachable.

## 3. List members

With the daemon running:

```shell
notary cluster list --config /etc/notary/config/config.yaml
```

Or, as an admin, `GET /api/v1/cluster` or `GET /api/v1/cluster/members`. You should see both names and one leader.

A two-node cluster typically shows the joiner as a **spare**, not a second voter. dqlite needs three voters for availability if one node fails. Add a third member the same way (`cluster add` / `--join`) when you want that quorum.

## 4. Remove a member

Like `lxc cluster remove`:

```shell
notary cluster remove node2 --config /etc/notary/config/config.yaml
```

Then stop Notary on the machine you removed. You cannot remove the last remaining member.

If a join dies after dqlite has already added the node (for example `notary start --join` times out waiting for the cluster), `cluster list` may show a member with no name. Remove it by address:

```shell
notary cluster remove 10.0.0.2:9000 --config /etc/notary/config/config.yaml
```

## 5. Stop a node

Stop the process (Ctrl+C, or your systemd/snap stop). Notary hands cluster roles to another node when one is available, then closes dqlite.

After a clean stop, start again with the same `db_path`, `cluster.name`, and `cluster.address`. You do not need `--join` again.
