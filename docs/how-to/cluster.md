# Run a Notary cluster

This guide starts two Notary nodes that share one dqlite cluster. The commands match LXD: `cluster add`, start with `--join`, `cluster list`, and `cluster remove`.

HTTPS certificates (`cert_path` / `key_path`) stay per node or load balancer. The **cluster** certificate is a different pair: the same `cluster.crt` and `cluster.key` on every node. See [Configuration file](../reference/config_file.md).

## Prerequisites

* Notary installed on each machine
* Network connectivity on the dqlite port (`cluster.address`, default `9000`)
* A shared cluster TLS certificate with a DNS SAN (and IPs or names that match each `cluster.address`)

Create a self-signed pair once and copy it to every node:

```shell
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 \
  -nodes -keyout cluster.key -out cluster.crt -subj "/CN=notary-cluster" \
  -addext "subjectAltName=DNS:localhost,DNS:notary-cluster,IP:10.0.0.1,IP:10.0.0.2"
```

Adjust the SAN IPs (or DNS names) to your nodes.

## 1. Start the first node

Use an empty data directory. Set `cluster.name` (like LXD's server name). Do **not** pass `--join`.

```yaml
key_path: "/etc/notary/config/key.pem"
cert_path: "/etc/notary/config/cert.pem"
db_path: "/var/lib/notary/database"
cluster:
  name: "node1"
  address: "10.0.0.1:9000"
  tls:
    cert_path: "/etc/notary/config/cluster.crt"
    key_path: "/etc/notary/config/cluster.key"
port: 3000
encryption_backend:
  type: "none"
```

```shell
notary start --config /etc/notary/config/config.yaml
```

## 2. Add a member and join

On a machine that is already in the cluster (daemon running), create a join token. This is the same idea as `lxc cluster add`:

```shell
notary cluster add node2 --config /etc/notary/config/config.yaml
```

The command prints a one-time token (valid for three hours).

On the second machine, use a **new empty** data directory, the **same** `cluster.crt` and `cluster.key`, and the name from `cluster add`:

```yaml
key_path: "/etc/notary/config/key.pem"
cert_path: "/etc/notary/config/cert.pem"
db_path: "/var/lib/notary/database"
cluster:
  name: "node2"
  address: "10.0.0.2:9000"
  tls:
    cert_path: "/etc/notary/config/cluster.crt"
    key_path: "/etc/notary/config/cluster.key"
port: 3000
encryption_backend:
  type: "none"
```

```shell
notary start --config /etc/notary/config/config.yaml --join '<token>'
```

You can also set `cluster.join_token` in the YAML instead of `--join`. The token is used only on first start. After `info.yaml` exists in `db_path`, the node resumes without it.

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

## 5. Stop a node

Stop the process (Ctrl+C, or your systemd/snap stop). Notary hands cluster roles to another node when one is available, then closes dqlite.

After a clean stop, start again with the same `db_path`, `cluster.name`, and `cluster.address` (and the same cluster TLS files). You do not need `--join` again.
