# Contributing

## Getting Started

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

Create a certificate and private key:

```bash
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 1 -out cert.pem -subj "/CN=example.com"
```

Create a `notary.yaml` file with the following content:

```yaml
key_path:  "key.pem"
cert_path: "cert.pem"
db_path: "certs.db"
port: 3000
pebble_notifications: false
```

Run the project:

```bash
./notary -config notary.yaml
```

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

## Reference

- [Go Best Practices Guidelines](https://docs.google.com/document/d/1IbFXyeXYlfQ5GUEEScGS7pP335Cei-5cFBdAoR973pQ/edit?tab=t.0)
