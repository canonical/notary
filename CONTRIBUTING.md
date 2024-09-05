# Contributing

## Getting Started
You can build and run the program by following these steps:

1. Install Go and Nodejs
2. Fork the repository on GitHub
3. Clone the forked repository to your local machine
4. Build the frontend: `npm i --prefix ui && npm run build --prefix ui`
5. Install the project: `go install ./...`
6. Create a `config.yaml` file as described in README.md
7. Run the project: `notary -config config.yaml`

Commands assume you're running them from the top level git repo directory

## Testing

### Unit Tests

Run go unit tests by running:
```bash
go test ./...
```

Run frontend vitest test suite by running:
```bash
npm run test --prefix ui
```

### Lint

Run the linter for golang by running:
```bash
golangci-lint run ./...
```
Run the linter for typescript by running:
```bash
npm run lint
```

## Creating the Container Image

We use rockcraft to create OCI images for use in container technologies like docker. 
You can create the container and import it into docker by running:

```bash
rockcraft pack -v
version=$(yq '.version' rockcraft.yaml)
sudo rockcraft.skopeo --insecure-policy copy oci-archive:notary_${version}_amd64.rock docker-daemon:notary:${version}
docker run notary:${version}
```