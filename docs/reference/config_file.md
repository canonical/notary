# Configuration File

Notary is configured using a YAML file.

Start Notary with the `start` command and `--config` flag to specify the path to the configuration file.
Or If you are using the snap you can modify the config under `/var/snap/notary/common/notary.yaml`

## Parameters

- `key_path` (string): Path to the private key for enabling HTTPS connections.
- `cert_path` (string): Path to a PEM formatted certificate for enabling HTTPS connections.
- `external_hostname` (string): The external hostname or IP address (with optional port) where Notary is accessible. Used for constructing OIDC redirect URLs and CRL distribution points. Example: `notary.example.com` or `localhost:2111`.
- `db_path` (string): Path to where the sqlite database should be stored. If the file does not exist Notary will attempt to create it.
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
    - `oidc` (object or list of objects): Configuration for one or more OIDC identity providers. Provide a single object to configure one provider, or a list of objects to configure several. When more than one provider is configured, the login page shows one button per provider.
      - `name` (string): A unique name identifying this provider. Shown on the login page and used in the `provider` query parameter of `/api/v1/oauth/login`. Defaults to `domain` when omitted.
      - `domain` (string): URL of the OIDC provider not including the protocol.
      - `client_id` (string): The client ID provided to you by the OIDC provider.
      - `client_secret` (string): The client secret provided to you by the OIDC provider.
      - `audience` (string): The audience value to be included in the oauth2 process.
      - `email_scope_key` (string): The email scope and claim that will be requested as a scope and checked in the claims of the ID token. Common values: "email" (standard OIDC), or custom namespaced claims. Email is optional - users can be provisioned with only their OIDC subject identifier.
      - `permissions_scope_key` (string): The permission scope and claim that will be requested as a scope and checked in the claims of the access token.
      - `extra_scopes` ([]string): Extra scopes to request from the OIDC provider.
      - `role_mapping` (object, optional): Maps an ID token claim onto a Notary role when a user is provisioned on first login. Role mappings are only ever read from this file, never from the database, so access can always be recovered by editing the configuration.
        - `claim` (string): The claim to read, e.g. `groups`. The claim may hold a single string or a list of strings.
        - `values` (object): Maps a claim value to a role ID (`0` admin, `1` certificate manager, `2` certificate requestor, `3` read-only). If a user matches several entries, the most privileged role wins. Users matching no entry get the read-only role. The very first user to log in always becomes an admin, regardless of this mapping.

For example, to configure two providers:

```yaml
authentication:
  oidc:
    - name: corp
      domain: corp.example.com
      client_id: notary
      client_secret: <secret>
      email_scope_key: email
      permissions_scope_key: permissions
      role_mapping:
        claim: groups
        values:
          notary-admins: 0
          notary-operators: 1
    - name: partner
      domain: partner.example.com
      client_id: notary
      client_secret: <secret>
      email_scope_key: email
      permissions_scope_key: permissions
```

- `tracing` (object): Configuration for tracing.
  - `service_name` (string): The name that will identify your service in the tracing system
  - `endpoint` (string): The URL of your OpenTelemetry collector endpoint
  - `sampling_rate` (string): The percentage of traces to sample. Can be specified as a percentage (50%)
    or a decimal value between 0.0 and 1.0 (0.0, 0.5, 1.0).
- `cluster` (object): Configuration for running Notary as part of a highly available cluster. Clustering is off unless `enabled` is explicitly `true`, so an existing configuration file keeps behaving exactly as it did before. Clustering is only supported on Linux.
  - `enabled` (boolean): Whether this node takes part in a cluster (optional, defaults to `false`). When `false`, Notary stores its data in the single SQLite file at `db_path` and nothing else in this section applies.
  - `address` (string): The `host:port` this node advertises to the other cluster members for replication and join traffic. Required when `enabled` is `true`. It must be reachable by every other member, and it is a bare address, not a URL — do not include a scheme.
  - `state_dir` (string): Directory holding this node's replicated database and its cluster-internal certificates. Required when `enabled` is `true`. It is created if it does not exist, and it must not be shared with another node.

`db_path` is still required when clustering is enabled, but it is not where a clustered node keeps its data; the replicated database lives in `state_dir`.

A node's operator-facing name is not part of this file. It is given once with `--name` when the node runs `notary cluster bootstrap` or `notary cluster join`, and is recorded in the cluster from then on.

Before `notary start` will serve as part of a cluster, the node must have run either `notary cluster bootstrap` (to start a new cluster) or `notary cluster join` (to join an existing one) against an empty `state_dir`. Once a node has joined, its `address` is fixed: Notary refuses to start if the configured address no longer matches the one recorded in `state_dir`.

## Examples

### Without an Encryption Backend

```yaml
key_path: "/etc/notary/config/key.pem"
cert_path: "/etc/notary/config/cert.pem"
db_path: "/var/lib/notary/database/notary.db"
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

### With HSM as an Encryption Backend

```yaml
key_path: "/etc/notary/config/key.pem"
cert_path: "/etc/notary/config/cert.pem"
db_path: "/var/lib/notary/database/notary.db"
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

### As a member of a cluster

Every node uses a configuration like this, each with its own `address` and its own `state_dir`.

```yaml
key_path: "/etc/notary/config/key.pem"
cert_path: "/etc/notary/config/cert.pem"
db_path: "/var/lib/notary/database/notary.db"
port: 3000
external_hostname: "notary-1.example.com"
pebble_notifications: true
logging:
  system:
    level: "info"
    output: "stdout"
encryption_backend:
  type: "none"
cluster:
  enabled: true
  address: "10.0.0.1:9000"
  state_dir: "/var/lib/notary/cluster"
```
