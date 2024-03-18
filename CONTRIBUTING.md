# Contributing

## Getting Started

1. Fork the repository on GitHub
2. Clone the forked repository to your local machine
3. Build the project: `go build ./...`
4. Run the project: `./gocert`

## Testing

### Unit Tests

```bash
go test ./...
```

### Lint

```bash
golangci-lint run ./...
```

## Container image

```bash
rockcraft pack -v
version=$(yq '.version' rockcraft.yaml)
sudo skopeo --insecure-policy copy oci-archive:gocert_${version}_amd64.rock docker-daemon:gocert:${version}
docker run gocert:${version}
```
