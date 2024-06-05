# gocert

GoCert is a certificate management tool.

## Installation

```bash
docker pull ghcr.io/canonical/gocert:latest
docker run -it ghcr.io/canonical/gocert:latest
```

## Requirements

GoCert requires 3 files to operate:
* A private key
* A TLS certificate with that private key
* A YAML config file with the required parameters

You can generate the cert and the associated key by running:
`openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 1 -out cert.pem -subj "/CN=example.com"`
GoCert does not support insecure http connections.

### Config File
The config file requires the following parameters:
* keypath: this is the path to the private key you've generated.
* certpath: this is the path to a certificate for enabling HTTPS connections.
* dbpath: the path to a sqlite database file. If the file does not exist GoCert will attempt to create it.
* port: the port in integer form to serve all of GoCert's API and frontend
* pebblenotificationsenabled: a boolean that once enabled, will allow GoCert to send pebble notices. Read more about it (here)[https://github.com/canonical/pebble?tab=readme-ov-file#notices].

an example config file may look like:

```yaml
keypath:  "./key.pem"
certpath: "./cert.pem"
dbpath: "./certs.db"
port: 3000
pebblenotificationsenabled: true
```