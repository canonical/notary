# Contributing

## Getting Started

1. Install Go and Nodejs
2. Fork the repository on GitHub
3. Clone the forked repository to your local machine
4. Build the frontend: `npm i --prefix ui && npm run build --prefix ui`
5. Install the project: `go install ./...`
6. Create a `config.yaml` file as described in README.md
7. Run the project: `gocert -config config.yaml`

Commands assume you're running them from the top level git repo directory
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
