# Configuration File

Notary is configured using a YAML file.

Start Notary with the `start` command and `--config` flag to specify the path to the configuration file.
Or If you are using the snap you can modify the config under `/var/snap/notary/common/notary.yaml`

## Parameters

- `key_path` (string): Path to the private key for enabling HTTPS connections.
- `cert_path` (string): Path to a PEM formatted certificate for enabling HTTPS connections.
- `external_hostname` (string): The external hostname or IP address (with optional port) where Notary is accessible. Used for constructing OIDC redirect URLs and CRL distribution points. Example: `notary.example.com` or `localhost:2111`.
- `db_path` (string): Path to the data directory (not a SQLite file). Notary stores dqlite files here. If the directory does not exist, Notary creates it and bootstraps a one-node cluster. Goose schema migrations run automatically on `notary start` against the dqlite database. To back up or restore this directory, see [Back up and restore Notary](../how-to/backup_restore.md).
- `cluster` (object): Configuration for the local dqlite node.
  - `name` (string): Cluster member name (LXD-style). Defaults to the machine hostname.
  - `address` (string): Bind address for dqlite, as `host:port`. Defaults to `127.0.0.1:9000`.
  - `join_token` (string): One-time token from `notary cluster add <name>`. Used only the first time this node starts (empty data directory). Prefer `notary start --join`. Joining requires cluster TLS.
  - `join` (list of strings): Existing dqlite addresses. Alternative to a join token for first start only. Do not set both `join` and `join_token`.
  - `tls` (object): Shared certificate for dqlite replication. Same `cert` and `key` on every node. This is not the HTTPS API certificate (`cert_path` / `key_path`).
    - `cert_path` (string): Path to the cluster certificate PEM. Must include a DNS SAN.
    - `key_path` (string): Path to the cluster private key PEM.

Cluster operations while the daemon is running (same shape as LXD):

* `notary cluster add <name> --config /path/to/config.yaml` — print a join token
* `notary cluster list --config /path/to/config.yaml`
* `notary cluster remove <name> --config /path/to/config.yaml`

Admin HTTP: `GET /api/v1/cluster`, `POST /api/v1/cluster/members`, `DELETE /api/v1/cluster/members/{name}`. Stopping the daemon hands cluster roles to another node when one is available. For start order, see [Run a Notary cluster](../how-to/cluster.md).
- `port` (integer): Port number on which Notary will listen for all incoming API and frontend connections.
- `pebble_notifications` (boolean): Allow Notary to send pebble notices on certificate events (create, update, delete). Pebble needs to be running on the same system as Notary.
- `logging` (object): Configuration for logging.
  - `system` (object): Configuration for system logging.
    - `level` (string): The level of logging. Options are `debug`, `info`, `warn`, `error`, and `fatal`.
    - `output` (string): The output destination for logs. Options are `stdout`, `stderr`, or a file path.
- `encryption_backend` (object): Configuration for the encryption backend.
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

A second node is added with `notary cluster add node2` on an existing member, then started with `--join` and the same cluster TLS files:

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

The cluster certificate must include a DNS SAN. One way to create a shared self-signed pair:

```shell
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 \
  -nodes -keyout cluster.key -out cluster.crt -subj "/CN=notary-cluster" \
  -addext "subjectAltName=DNS:localhost,DNS:notary-cluster,IP:127.0.0.1"
```

Copy `cluster.crt` and `cluster.key` to every node. Generate a cluster certificate that names each node's `cluster.address` (DNS or IP) as appropriate.

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
