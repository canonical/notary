import? "https://raw.githubusercontent.com/canonical/identity-credentials-workflows/refs/tags/v3.1.1/common.just"

code-health-go: setup-go
    #!/usr/bin/env bash
    set -euo pipefail
    echo "linting Golang code..."

    sudo snap install golangci-lint --classic --channel=latest/stable
    go vet ./...
    golangci-lint run ./...

setup-rockcraft:
    #!/usr/bin/env bash
    set -euo pipefail

    sudo snap install concierge --classic
    sudo concierge prepare --preset crafts

setup-snapcraft:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Setting up snapcraft..."

    sudo snap install concierge --classic
    sudo concierge prepare --preset crafts

build-snap:
    #!/usr/bin/env bash
    set -euo pipefail

    snapcraft pack --verbose
