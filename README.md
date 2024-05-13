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
as an example:

```yaml
keypath:  "./key.pem"
certpath: "./cert.pem"
dbpath: "./certs.db"
port: 3000
```