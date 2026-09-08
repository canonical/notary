# Configuration File

Notary is configured using a YAML file.

Start Notary with the `start` command and `--config` flag to specify the path to the configuration file.
Or If you are using the snap you can modify the config under `/var/snap/notary/common/notary.yaml`. `snap set` only rewrites that file when it is snap-managed (see [Deploy](../how-to/deploy.md)).

## Parameters

- `key_path` (string): Path to the private key for enabling HTTPS connections.
- `cert_path` (string): Path to a PEM formatted certificate for enabling HTTPS connections.
- `external_hostname` (string): The external hostname or IP address (with optional port) where Notary is accessible. Used for OIDC redirect URLs, CRL distribution points, and the HTTPS address in cluster join tokens. Defaults to `localhost`. That default is ignored for join tokens when `cluster.address` is a wildcard or a non-loopback address; set a hostname joiners can reach, or bind dqlite to a specific address. Example: `notary.example.com` or `localhost:2111`.
- `db_path` (string): Path to the data directory (not a SQLite file). Notary stores dqlite files here. If the directory does not exist, Notary creates it and bootstraps a one-node cluster. Goose schema migrations run automatically on `notary start` against the dqlite database, serialized with a cluster-wide lock. Additive migrations (new tables, new columns with defaults) are safe while older members are still serving. To back up or restore this directory, see [Back up and restore Notary](../how-to/backup_restore.md).
- `cluster` (object): Configuration for the local dqlite node.
  - `name` (string): Cluster member name (LXD-style). Defaults to the machine hostname.
  - `address` (string): Bind address for dqlite, as `host:port`. Defaults to `127.0.0.1:9000`.
  - `join_token` (string): One-time token from `notary cluster add <name>`. Used only the first time this node starts (empty data directory). Prefer `notary start --join`. The token is a join ticket (name, HTTPS addresses, secret, expiry, TLS fingerprint). It does not contain the cluster private key. The joiner redeems it over HTTPS, pinned by the fingerprint, then joins dqlite.
  - `join` (list of strings): Existing dqlite addresses. Alternative to a join token for first start only. Do not set both `join` and `join_token`. This path requires `cluster.tls` (shared pair or CA mode).
  - `tls` (object): Optional dqlite mTLS. This is not the HTTPS API certificate (`cert_path` / `key_path`). Two modes:
    - **Shared pair (default).** Omit `tls` on first start of a new cluster and Notary generates a self-signed pair into `db_path` (`cluster.crt` / `cluster.key`), with DNS SANs `localhost` and `notary-cluster`. On a joiner using `--join`, omit it; if you set `cert_path` / `key_path` without `ca_path`, they must match the certificate received when the token is redeemed. Joining with `cluster.join` addresses and no token requires this pair.
    - `cert_path` (string): Path to the shared cluster certificate PEM, or this unit's leaf in CA mode. Must include a DNS SAN.
    - `key_path` (string): Path to the matching private key PEM.
    - `ca_path` (string): Path to a dedicated cluster CA PEM. When set, Notary uses **CA mode**: each unit presents its own leaf, signed by this CA. All four of `ca_path`, `cert_path`, `key_path`, and `peer_san` are required. Notary does not mint or revoke this CA. Do not reuse the HTTPS API CA. CA mode never writes `cluster.key` into `db_path`.
    - `peer_san` (string): Group SAN that every cluster leaf must carry (DNS or URI). Required in CA mode; there is no default. Auto-generated shared certificates already include `notary-cluster`. Per-unit host/IP SANs must match the form of `cluster.address` (IP SAN for an IP bind, DNS SAN for a hostname bind); they are used as the TLS `ServerName` when dialing, not as the membership allow-list.

A data directory created without cluster TLS (typical of a one-node store from before this feature) keeps running plaintext on resume. `notary cluster add` then fails until you set `cluster.tls` and restart, which writes `cluster.crt` and `cluster.key` into `db_path`. In CA mode, resume fails closed if the four CA files are missing; Notary will not fall back to generating a shared pair.

Cluster operations while the daemon is running (same shape as LXD):

* `notary cluster add <name> --config /path/to/config.yaml` — print a join token
* `notary cluster list --config /path/to/config.yaml`
* `notary cluster remove <name> --config /path/to/config.yaml`

Admin HTTP: `GET /api/v1/cluster`, `POST /api/v1/cluster/members`, `DELETE /api/v1/cluster/members/{name}`. Stopping the daemon hands cluster roles to another node when one is available. For start order, see [Run a Notary cluster](../how-to/cluster.md).
- `port` (integer): Port number on which Notary will listen for all incoming API and frontend connections.
- `pebble_notifications` (boolean): Allow Notary to send pebble notices on certificate events (create, update, delete). Pebble needs to be running on the same system as Notary.
- `logging` (object): Optional. Configuration for logging. If omitted, system logs go to stdout at `debug` and audit logs go to stdout.
  - `system` (object): Configuration for system logging.
    - `level` (string): The level of logging. Options are `debug`, `info`, `warn`, `error`, and `fatal`.
    - `output` (string): The output destination for logs. Options are `stdout`, `stderr`, or a file path.
- `encryption_backend` (object): Configuration for the encryption backend. **Every cluster member must use the same backend settings.** The data-encryption key lives in dqlite; a joiner that cannot decrypt it will not start.
  - `type` (string): Type of encryption backend. Options are `none`, `pkcs11`, or `vault`.
  - For `type: "pkcs11"`:
    - `lib_path` (string): Path to the PKCS#11 library needed to communicate with the backend.
    - `pin` (string): PIN for authenticating with the PKCS#11 device.
    - `aes_encryption_key_id` (integer): ID of the key to use on the PKCS#11 device.
  - For `type: "vault"`:
    - `endpoint` (string): URL of the Vault server.
    - `mount` (string): Mount path of the Transit secrets engine.
    - `key_name` (string): Name of the key to use for encryption.
    - `token` (string): Vault token for authentication. Either this, or `approle_role_id` and `approle_secret_id` must be provided.
    - `approle_role_id` (string): Role ID for AppRole authentication. Either `approle_role_id` and `approle_secret_id`, or `token` must be provided.
    - `approle_secret_id` (string): Secret ID for AppRole authentication.
    - `tls_ca_cert` (string): Path to the CA certificate for TLS verification (optional).
    - `tls_skip_verify` (boolean): Whether to skip TLS certificate verification (optional, defaults to `false`). It is strongly discouraged to set this to `true` outside of development environments
- `authentication` (object): Configuration for authenticating to Notary.
  - `authentication` (object): Authentication configuration.
    - `oidc` (object): Configuration for an OIDC identity provider.
      - `domain` (string): URL of the OIDC provider not including the protocol.
      - `client_id` (string): The client ID provided to you by the OIDC provider.
      - `client_secret` (string): The client secret provided to you by the OIDC provider.
      - `audience` (string): The audience value to be included in the oauth2 process.
      - `email_scope_key` (string): The email scope and claim that will be requested as a scope and checked in the claims of the ID token. Common values: "email" (standard OIDC), or custom namespaced claims. Email is optional - users can be provisioned with only their OIDC subject identifier.
      - `permissions_scope_key` (string): The permission scope and claim that will be requested as a scope and checked in the claims of the access token.
      - `extra_scopes` ([]string): Extra scopes to request from the OIDC provider.
- `tracing` (object): Configuration for tracing.
  - `service_name` (string): The name that will identify your service in the tracing system
  - `endpoint` (string): The URL of your OpenTelemetry collector endpoint
  - `sampling_rate` (string): The percentage of traces to sample. Can be specified as a percentage (50%)
    or a decimal value between 0.0 and 1.0 (0.0, 0.5, 1.0).

## Examples

### Without an Encryption Backend

```yaml
key_path: "/etc/notary/config/key.pem"
cert_path: "/etc/notary/config/cert.pem"
db_path: "/var/lib/notary/database"
cluster:
  address: "127.0.0.1:9000"
port: 3000
pebble_notifications: true
logging:
  system:
    level: "info"
    output: "stdout"
encryption_backend:
  type: "none"
tracing:
  service_name: "notary"
  endpoint: "127.0.0.1:4317"
  sampling_rate: "100%"
```

A second node is added with `notary cluster add node2` on an existing member, then started with `--join` (no cluster TLS files):

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

If you supply a shared `cluster.tls` pair yourself, the certificate must include a DNS SAN:

```shell
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 \
  -nodes -keyout cluster.key -out cluster.crt -subj "/CN=notary-cluster" \
  -addext "subjectAltName=DNS:localhost,DNS:notary-cluster,IP:127.0.0.1"
```

CA mode (per-unit leaves under a dedicated cluster CA):

```yaml
cluster:
  name: "node1"
  address: "10.0.0.1:9000"
  tls:
    ca_path: "/etc/notary/cluster-ca.crt"
    cert_path: "/etc/notary/unit.crt"
    key_path: "/etc/notary/unit.key"
    peer_san: "notary-cluster"
```

Every leaf must include `peer_san` as a DNS or URI SAN, plus a host/IP SAN that matches that unit's `cluster.address`. Place the same `ca_path` and `peer_san` on every member before `notary start --join`; redeem does not return the CA or a cluster private key. Prefer a name-constrained intermediate for this CA so it cannot issue HTTPS names.

### With HSM as an Encryption Backend

```yaml
key_path: "/etc/notary/config/key.pem"
cert_path: "/etc/notary/config/cert.pem"
db_path: "/var/lib/notary/database"
cluster:
  address: "127.0.0.1:9000"
port: 3000
pebble_notifications: true
logging:
  system:
    level: "debug"
    output: "/var/lib/notary/logs/notary.log"
encryption_backend:
  type: "pkcs11"
  lib_path: "/path/to/yubihsm_pkcs11.so"
  pin: "0001password"
  aes_encryption_key_id: 0x1234
tracing:
  service_name: "notary"
  endpoint: "127.0.0.1:4317"
  sampling_rate: "100%"
```
