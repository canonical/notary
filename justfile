import? "https://raw.githubusercontent.com/canonical/identity-credentials-workflows/refs/tags/v3.1.1/common.just"

code-health-go: setup-go
    #!/usr/bin/env bash
    set -euo pipefail
    echo "linting Golang code..."

    sudo snap install golangci-lint --classic --channel=latest/stable
    go vet ./...
    golangci-lint run ./...

build-snap:
    #!/usr/bin/env bash
    set -euo pipefail

    sudo lxd init --auto
    sudo lxd waitready
    lxc network list
    lxc network show lxdbr0
    ip route
    ip addr
    sudo sg lxd -c "snapcraft pack --verbose"
