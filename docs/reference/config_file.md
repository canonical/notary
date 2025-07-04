# Configuration File

Notary is configured using a YAML file.

Start Notary with the `--config` flag to specify the path to the configuration file.
Or If you are using the snap you can modify the config under `/var/snap/notary/common/notary.yaml`


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
- `encryption_backend` (object): Configuration for the encryption backend. Map of named backends, empty map means no encryption.
  - `backend_name` (object): User-defined name for the encryption backend (e.g., "yubihsm", "hsm1").
    - `pkcs11` (object): Configuration for PKCS#11 backend.
      - `lib_path` (string): Path to the PKCS#11 library needed to communicate with the backend.
      - `pin` (string): PIN for authenticating with the PKCS#11 device.
      - `aes_encryption_key_id` (integer): ID of the key to use on the PKCS#11 device.

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
encryption_backend: {}
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
  yubihsm:
    pkcs11:
      lib_path: "/path/to/yubihsm_pkcs11.so"
      pin: "0001password"
      aes_encryption_key_id: 0x1234
```
