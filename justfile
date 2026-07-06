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

    sudo snap install snapcraft --classic --channel=${SNAPCRAFT_CHANNEL:-latest/stable}
    snapcraft version

    sudo snap install lxd --classic
    sudo lxd init --auto
    sudo lxd waitready
    getent group lxd | grep -qwF "$USER" || sudo usermod -aG lxd "$USER"
    newgrp lxd
