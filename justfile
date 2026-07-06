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
    echo "building snap..."

    snapcraft pack && LOG_FILE=$(ls -t ~/.local/state/snapcraft/log/snapcraft-*.log | head -n1) && echo "=== Log file: $LOG_FILE ===" && cat "$LOG_FILE"
