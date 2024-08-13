# gocert

GoCert is a certificate management tool.

## Requirements

GoCert requires 3 files to operate:
* A private key
* A TLS certificate with that private key
* A YAML config file with the required parameters

You can generate the cert and the associated key by running:
```bash
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
key_path:  "/etc/gocert/config/key.pem"
cert_path: "/etc/gocert/config/cert.pem"
db_path: "/var/lib/gocert/database/certs.db"
port: 3000
pebble_notifications: true
```

## Installation

### From OCI Image

```bash
# Pull the OCI image from github and run it in docker
docker pull ghcr.io/canonical/gocert:latest
docker run -d --name gocert -p 3000:3000 ghcr.io/canonical/gocert:latest
# Push the 3 required files and restart the workload
docker exec gocert /usr/bin/pebble mkdir -p /etc/gocert/config
docker exec gocert /usr/bin/pebble mkdir -p /var/lib/gocert/database
docker cp key.pem gocert:/etc/gocert/config/key.pem
docker cp cert.pem gocert:/etc/gocert/config/cert.pem
docker cp config.yaml gocert:/etc/gocert/config/config.yaml
docker restart gocert
```

### From Source

go and npm CLI tools need to be installed in order to build gocert from source.
You will need to build the frontend first, and then install gocert with Go.

```bash
npm install --prefix ui && npm run build --prefix ui && go install ./...
gocert -config ./config.yaml
```
