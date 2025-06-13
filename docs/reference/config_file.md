# Configuration File

Notary is configured using a YAML file.

Start Notary with the `--config` flag to specify the path to the configuration file.

## Parameters

- `key_path` (string): Path to the private key for enabling HTTPS connections.
- `cert_path` (string): Path to a PEM formatted certificate for enabling HTTPS connections.
- `db_path` (string): Path to where the sqlite database should be stored. If the file does not exist Notary will attempt to create it.
- `port` (integer): Port number on which Notary will listen for all incoming API and frontend connections.
- `pebble_notifications` (boolean): Allow Notary to send pebble notices on certificate events (create, update, delete). Pebble needs to be running on the same system as Notary.
- `logging` (object): Configuration for logging.
  - `system` (object): Configuration for system logging.
    - `level` (string): The level of logging. Options are `debug`, `info`, `warn`, `error`, and `fatal`.
    - `output` (string): The output destination for logs. Options are `stdout`, `stderr`, or a file path.
- `encryption_backend` (object): Configuration for the encryption backend
  - `type` (string): Type of the encryption backend, currently supported backends are `vault`, `pkcs11` and `none` for no encryption backend.
  - `endpoint` (string): URL endpoint for the Vault server when using the Vault backend.
  - `role_id` (string): Role ID for Vault AppRole authentication when using the Vault backend.
  - `role_secret_id` (string): Role Secret ID for Vault AppRole authentication when using the Vault backend.
  - `token` (string): Authentication token for accessing Vault when using the Vault backend.
  - `key_name` (string): Name of the encryption key to use in Vault when using the Vault backend.
  - `mount` (string): Mount path where the transit secrets engine is enabled in Vault when using the Vault backend.
  - `lib_path` (string): Path to the PKCS#11 library needed to communicate with the backend when using the PKCS#11 backend.
  - `pin` (string): PIN for authenticating with the PKCS#11 device when using the PKCS#11 backend.
  - `key_id` (integer): ID of the key to use on the PKCS#11 device when using the PKCS#11 backend.

## Example

```yaml
key_path: "/etc/notary/config/key.pem"
cert_path: "/etc/notary/config/cert.pem"
db_path: "/var/lib/notary/database/notary.db"
port: 3000
pebble_notifications: true
logging:
  system:
    level: "debug"
    output: "var/lib/notary/logs/notary.log"
encryption_backend:
  type: "pkcs11"
  lib_path: "/usr/local/lib/pkcs11/yubihsm_pkcs11.dylib"
  pin: "0001password"
  key_id: 0x1234
```
