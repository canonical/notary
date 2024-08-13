# gocert

GoCert is a certificate management tool.

## Requirements

GoCert requires 3 files to operate:
* A private key
* A TLS certificate with that private key
* A YAML config file with the required parameters

You can generate the cert and the associated key by running:
```
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 1 -out cert.pem -subj "/CN=example.com"
```

GoCert does not support insecure http connections.

### Config File
The config file requires the following parameters:
| Key                  | Type    | Description |
|----------------------|---------|----------|
| key_path             | string  | path to the private key for enabling HTTPS connections |
| cert_path            | string  | path to a PEM formatted certificate for enabling HTTPS connections |
| db_path              | string  | path to a sqlite database file. If the file does not exist GoCert will attempt to create it. |
| port                 | integer (0-65535)  | port number on which GoCert will listen for all incoming API and frontend connections. |
| pebble_notifications | boolean | Allow GoCert to send pebble notices on certificate events (create, update, delete). Pebble needs to be running on the same system as GoCert. Read more about Pebble Notices [here](https://github.com/canonical/pebble?tab=readme-ov-file#notices). |

An example config file may look like:

```yaml
key_path:  "/gocert/key.pem"
cert_path: "/gocert/cert.pem"
db_path: "/gocert/certs.db"
port: 3000
pebble_notifications: true
```

## Installation

### From OCI Image

You can run GoCert in docker by doing:

```bash
docker pull ghcr.io/canonical/gocert:latest
docker run -it ghcr.io/canonical/gocert:latest
```

You will then need to push the 3 required files before it will launch successfully. You can do this by
```bash
docker exec gocert /usr/bin/pebble mkdir /etc/config
docker cp key.pem gocert:/etc/config/key.pem
docker cp cert.pem gocert:/etc/config/cert.pem
docker cp config.yaml gocert:/etc/config/config.yaml
docker restart gocert
```

### Build from Source