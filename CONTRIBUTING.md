# Contributing

## Getting Started

1. Install Go and Nodejs
1. Fork the repository on GitHub
2. Clone the forked repository to your local machine
3. Build the frontend: `cd ui && npm build build`
4. Install the project: `go install ./...`
5. Create a `config.yaml` file:
```yaml
keypath:  "./key.pem"
certpath: "./cert.pem"
dbpath: "./certs.db"
port: 3000
```
6. Run the project: `gocert --config config.yaml`

Commands for go need to be run from the project directory, and commands for the frontend need to be run from the `ui/` directory
## Testing

### Unit Tests

Go:
```bash
go test ./...
```
Frontend:
```bash
npm run test
```

### Lint

Go:
```bash
golangci-lint run ./...
```
Frontend:
```bash
npm run lint
```

## Container image

```bash
rockcraft pack -v
version=$(yq '.version' rockcraft.yaml)
sudo skopeo --insecure-policy copy oci-archive:gocert_${version}_amd64.rock docker-daemon:gocert:${version}
docker run gocert:${version}
```
