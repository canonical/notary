# Notary

Notary is a simple, reliable, and secure certificate management tool. Use it to request, approve, and manage certificate requests for your services. 

### Project & Community

Notary is an open source project that warmly welcomes community contributions, suggestions, fixes, and constructive feedback.

- To contribute to the code Please see [CONTRIBUTING.md](/CONTRIBUTING.md) for guidelines and best practices.
- Raise software issues or feature requests in [GitHub](https://github.com/canonical/notary/issues)
- Meet the community and chat with us on [Matrix](https://matrix.to/#/!yAkGlrYcBFYzYRvOlQ:ubuntu.com?via=ubuntu.com&via=matrix.org&via=mozilla.org)

## Getting Started

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

## How-to Guides

### Install

#### Snap

```bash
sudo snap install notary
```

#### Charmed Operator

```bash
juju deploy notary-k8s
```

For more information on using Notary in the Juju ecosystem, read the [charm documentation](https://charmhub.io/notary-k8s).

#### Source

Clone the repository:

```bash
git clone git@github.com:canonical/notary.git
```

Install the npm dependencies:

```bash
npm install --prefix ui
```

Build the UI:

```bash
npm run build --prefix ui
```

Build the Go binary:

```bash
go install ./...
```

## Reference

### Configuration

Notary takes a YAML config file as input. The config file can be passed to Notary using the `-config` flag.

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

### API

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
