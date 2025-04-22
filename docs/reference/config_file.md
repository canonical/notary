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
    - `output` (string): The output destination for logs. Options are `stdout`, and `file`.
      - `stdout`: Logs will be printed to the console.
      - `file`: Logs will be written to a file. This option requires the `path` parameter to be specified.
    - `path` (string, optional): The path to the log file. If not specified, logs will be printed to stdout. This option is only applicable when `output` is set to `file`.

## Example

```yaml
key_path:  "/etc/notary/config/key.pem"
cert_path: "/etc/notary/config/cert.pem"
db_path: "/var/lib/notary/database/notary.db"
port: 3000
pebble_notifications: true
logging:
  system:
    level: "debug"
    output: "file"
    path: "notary.log"
```
