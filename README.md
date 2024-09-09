# notary

Notary is a simple, reliable, and secure certificate management tool. Use it to request, approve, and manage certificate requests for your services. 

## Installation

### From Snap

Install the snap:
```bash
sudo snap install notary
```

Generate (or copy) a certificate and private key to the following location:
```bash
sudo openssl req -newkey rsa:2048 -nodes -keyout /var/snap/notary/common/key.pem -x509 -days 1 -out /var/snap/notary/common/cert.pem -subj "/CN=example.com"
```

Start the service:
```bash
sudo snap start notary.notaryd
```

Navigate to `https://localhost:3000` to access the Notary UI.

### From OCI Image

```bash
# Pull the OCI image from github and run it in docker
docker pull ghcr.io/canonical/notary:latest
docker run -d --name notary -p 3000:3000 ghcr.io/canonical/notary:latest
# Push the 3 required files and restart the workload
docker exec notary /usr/bin/pebble mkdir -p /etc/notary/config
docker exec notary /usr/bin/pebble mkdir -p /var/lib/notary/database
docker cp key.pem notary:/etc/notary/config/key.pem
docker cp cert.pem notary:/etc/notary/config/cert.pem
docker cp config.yaml notary:/etc/notary/config/config.yaml
docker restart notary
```

### From Source

go and npm CLI tools need to be installed in order to build notary from source.
You will need to build the frontend first, and then install notary with Go.

```bash
npm install --prefix ui && npm run build --prefix ui && go install ./...
notary start -config ./config.yaml
```

## Configuration

Notary's start command takes a YAML config file as input. The config file can be passed to Notary using the `-config` flag.

The config file requires the following parameters:
| Key                  | Type              | Description                                                                                                                                                                                                                                         |
| -------------------- | ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| key_path             | string            | path to the private key for enabling HTTPS connections                                                                                                                                                                                              |
| cert_path            | string            | path to a PEM formatted certificate for enabling HTTPS connections                                                                                                                                                                                  |
| db_path              | string            | path to a sqlite database file. If the file does not exist Notary will attempt to create it.                                                                                                                                                        |
| port                 | integer (0-65535) | port number on which Notary will listen for all incoming API and frontend connections.                                                                                                                                                              |
| pebble_notifications | boolean           | Allow Notary to send pebble notices on certificate events (create, update, delete). Pebble needs to be running on the same system as Notary. Read more about Pebble Notices [here](https://github.com/canonical/pebble?tab=readme-ov-file#notices). |

An example config file may look like:

```yaml
key_path:  "/etc/notary/config/key.pem"
cert_path: "/etc/notary/config/cert.pem"
db_path: "/var/lib/notary/database/certs.db"
port: 3000
pebble_notifications: true
```

You can generate the cert and the associated key by running:

```bash
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 1 -out cert.pem -subj "/CN=example.com"
```

Notary does not support insecure http connections.

## API

| Endpoint                                               | HTTP Method | Description                                    | Parameters         |
| ------------------------------------------------------ | ----------- | ---------------------------------------------- | ------------------ |
| `/api/v1/certificate_requests`                         | GET         | Get all blog certificate requests              |                    |
| `/api/v1/certificate_requests`                         | POST        | Create a new certificate request               | csr                |
| `/api/v1/certificate_requests/{id}`                    | GET         | Get a certificate request by id                |                    |
| `/api/v1/certificate_requests/{id}`                    | DELETE      | Delete a certificate request by id             |                    |
| `/api/v1/certificate_requests/{id}/certificate`        | POST        | Create a certificate for a certificate request |                    |
| `/api/v1/certificate_requests/{id}/certificate/reject` | POST        | Reject a certificate for a certificate request |                    |
| `/api/v1/certificate_requests/{id}/certificate`        | DELETE      | Delete a certificate for a certificate request |                    |
| `/api/v1/accounts`                                     | GET         | Get all user accounts                          |                    |
| `/api/v1/accounts`                                     | POST        | Create a new user account                      | username, password |
| `/api/v1/accounts/{id}`                                | GET         | Get a user account by id                       |                    |
| `/api/v1/accounts/{id}`                                | DELETE      | Delete a user account by id                    |                    |
| `/api/v1/accounts/{id}/change_password`                | POST        | Change a user account's password               | password           |
| `/login`                                               | POST        | Login to the Notary UI                         | username, password |
| `/status`                                              | GET         | Get the status of the Notary service           |                    |
| `/metrics`                                             | Get         | Get Prometheus metrics                         |                    |
