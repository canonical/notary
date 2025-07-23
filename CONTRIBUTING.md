# Contributing

Notary is an open source project that warmly welcomes community contributions, suggestions, fixes, and constructive feedback.

## Getting Started

This tutorial guides you through setting up a development environment for Notary.

After going through these steps, you will have a general idea of how to build and run Notary.

### Prerequisites

Install Go:

```bash
sudo snap install go --classic
```

Install NodeJS:

```bash
curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
NODE_MAJOR=20
echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_$NODE_MAJOR.x nodistro main" | sudo tee /etc/apt/sources.list.d/nodesource.list
sudo apt update
sudo apt install nodejs
```

Clone the repository:

```bash
git@github.com:canonical/notary.git
```

### Build Notary

Install the npm dependencies:

```bash
npm install --prefix ui
```

Build the frontend:

```bash
npm run build --prefix ui
```

Build the Go binary:

```bash
go build -o notary cmd/notary/main.go
```

Enable CGo:

```bash
go env -w CGO_ENABLED=1
```

Add dqlite header and library files:

```bash
go env -w CGO_CFLAGS="-I$HOME/go/deps/dqlite/include/"\
 CGO_LDFLAGS="-L$HOME/go/deps/dqlite/.libs/"\
 CGO_LDFLAGS_ALLOW="(-Wl,-wrap,pthread_create)|(-Wl,-z,now)"

export LD_LIBRARY_PATH="$HOME/go/deps/dqlite/.libs/"
```

### Run Notary

Create a certificate and private key:

```bash
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 1 -out cert.pem -subj "/CN=example.com"
```

Create a `notary.yaml` file with the following content:

```yaml
key_path: "key.pem"
cert_path: "cert.pem"
db_path: "notary.db"
port: 3000
pebble_notifications: false
logging:
  system:
    level: "info"
    output: "stdout"
encryption_backend: {}
```

Run Notary:

```bash
./notary -config notary.yaml
```

Access the Notary UI at `https://localhost:3000`.

## How-to Guides

### Run Unit Tests

Run go unit tests by running:

```bash
go test ./...
```

Run frontend vitest test suite by running:

```bash
npm run test --prefix ui
```

### Run Lint checks

Run the linter for golang by running:

```bash
golangci-lint run ./...
```

Run the linter for typescript by running:

```bash
npm run lint
```

### Create a container Image

Install rockcraft:

```bash
sudo snap install rockcraft --classic
```

Build the container image:

```bash
rockcraft pack -v
```

Copy the container image to the docker daemon:

```bash
version=$(yq '.version' rockcraft.yaml)
sudo rockcraft.skopeo --insecure-policy copy oci-archive:notary_${version}_amd64.rock docker-daemon:notary:${version}
```

Run the container image:

```bash
docker run notary:${version}
```

## Build the documentation site

Go to the `docs` directory:

```shell
cd docs
```

Install the dependencies:

```shell
make install
```

Build the documentation site:

```shell
make run
```

Navigate to `http://127.0.0.1:8000` to view the documentation site.

## Reference

- [Go Best Practices Guidelines](https://docs.google.com/document/d/1IbFXyeXYlfQ5GUEEScGS7pP335Cei-5cFBdAoR973pQ/edit?tab=t.0)
