# print list of available commands
[default]
help:
    just --list --unsorted

# =============================================================================
# Install Dependencies
# =============================================================================

# install and bootstrap dependencies via a generated concierge configuration
setup:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "preparing concierge configuration..."

    sudo snap install yq

    config="concierge.yaml"
    echo "{}" > "$config"

    toolchains=(${TOOLCHAINS:-})
    for toolchain in "${toolchains[@]}"; do
        echo "installing toolchain: $toolchain"
        case "$toolchain" in
            go)
                go_version="${GO_VERSION:-}"
                if [ -z "$go_version" ] && [ -f "go.mod" ]; then
                    go_version=$(grep -m1 '^go[[:space:]]' go.mod | awk '{print $2}' | cut -d. -f1,2)
                    echo "Detected Go version from go.mod: $go_version"
                fi
                yq -i ".host.snaps.go.channel = \"${go_version:-latest}/stable\"" "$config"
                ;;
            python)
                yq -i '.host.snaps.astral-uv.channel = "latest/stable"' "$config"
                ;;
            typescript)
                sudo apt-get update
                sudo apt-get install -y unzip
                curl -fsSL https://bun.com/install | bash
                bun --version
                ;;
            charmcraft)
                yq -i ".host.snaps.charmcraft.channel = \"${CHARMCRAFT_CHANNEL:-latest/stable}\"" "$config"
                ;;
            snapcraft)
                yq -i ".host.snaps.snapcraft.channel = \"${SNAPCRAFT_CHANNEL:-latest/stable}\"" "$config"
                ;;
            rockcraft)
                yq -i ".host.snaps.rockcraft.channel = \"${ROCKCRAFT_CHANNEL:-latest/stable}\"" "$config"
                ;;
            juju-k8s)
                yq -i '.providers.k8s.enable = true | .providers.k8s.bootstrap = true' "$config"
                # lxd is enabled (but not bootstrapped) as a charmcraft build backend.
                yq -i '.providers.lxd.enable = true' "$config"
                [ -n "${K8S_CHANNEL:-}" ] && yq -i ".providers.k8s.channel = \"${K8S_CHANNEL}\"" "$config"
                [ -n "${JUJU_CHANNEL:-}" ] && yq -i ".juju.channel = \"${JUJU_CHANNEL}\"" "$config"
                ;;
            juju-machine)
                yq -i '.providers.lxd.enable = true | .providers.lxd.bootstrap = true' "$config"
                [ -n "${LXD_CHANNEL:-}" ] && yq -i ".providers.lxd.channel = \"${LXD_CHANNEL}\"" "$config"
                [ -n "${JUJU_CHANNEL:-}" ] && yq -i ".juju.channel = \"${JUJU_CHANNEL}\"" "$config"
                ;;
            *) echo "unknown toolchain: $toolchain" >&2; exit 1;;
        esac
    done

    extra_snaps=(${EXTRA_SNAPS:-})
    for snap in "${extra_snaps[@]}"; do
        sudo snap install "$snap" || true
    done

    if [ -n "${EXTRA_DEBS:-}" ]; then
        sudo apt-get update
        sudo apt-get install -y $EXTRA_DEBS
    fi

[private]
install-bun:
    #!/usr/bin/env bash
    set -euo pipefail
    bun install

[private]
install-python:
    #!/usr/bin/env bash
    set -euo pipefail
    uv sync

# =============================================================================
# Code Health
# =============================================================================

# run linters, formatters, and other code health tools
code-health:
    #!/usr/bin/env bash
    set -euo pipefail

    if [ "${GO_ENABLED:-false}" = "true" ]; then
        {{ j }} code-health-go
    fi
    if [ "${PYTHON_ENABLED:-false}" = "true" ]; then
        {{ j }} code-health-python
    fi
    if [ "${TYPESCRIPT_ENABLED:-false}" = "true" ]; then
        {{ j }} code-health-typescript
    fi
    if [ "${CHARMCRAFT_ENABLED:-false}" = "true" ]; then
        {{ j }} lint-charmcraft
    fi
    if [ "${SNAPCRAFT_ENABLED:-false}" = "true" ]; then
        {{ j }} lint-snapcraft
    fi
    if [ "${ROCKCRAFT_ENABLED:-false}" = "true" ]; then
        {{ j }} lint-rockcraft
    fi
    if [ "${GRAFANA_ENABLED:-false}" = "true" ]; then
        {{ j }} lint-grafana
    fi

[private]
code-health-go:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "linting Golang code..."

    sudo snap install golangci-lint --classic --channel=latest/stable
    go vet ./...
    golangci-lint run ./...

[private]
code-health-typescript: install-bun
    #!/usr/bin/env bash
    set -euo pipefail
    echo "linting TypeScript code..."

    bun run code-health

[private]
code-health-python: install-python
    #!/usr/bin/env bash
    set -euo pipefail
    echo "linting Python code..."

    uv tool install tox --with tox-uv 2>/dev/null || true
    tox -e lint
    tox -e static
    tox -e format -- --check

[private]
lint-grafana:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "linting Grafana dashboards..."

    go install github.com/grafana/dashboard-linter@v0.1.1
    dashboard-linter lint "$GRAFANA_DASHBOARD_FILE_PATH" --strict -c grafana.lint

[private]
lint-charmcraft:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "linting charm..."

    charmcraft expand-extensions

[private]
lint-snapcraft:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "linting snap..."

    snapcraft lint

[private]
lint-rockcraft:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "linting rock..."

    rockcraft expand-extensions

# =============================================================================
# Unit Testing
# =============================================================================

# run unit tests
test-unit:
    #!/usr/bin/env bash
    set -euo pipefail

    if [ "${GO_ENABLED:-false}" = "true" ]; then
        {{ j }} test-unit-go
    fi
    if [ "${PYTHON_ENABLED:-false}" = "true" ]; then
        {{ j }} test-unit-python
    fi
    if [ "${TYPESCRIPT_ENABLED:-false}" = "true" ]; then
        {{ j }} test-unit-typescript
    fi

[private]
test-unit-go:
    #!/usr/bin/env bash
    set -euo pipefail

    go test -v -cover ./...

[private]
test-unit-typescript: install-bun
    #!/usr/bin/env bash
    set -euo pipefail

    bun run test

[private]
test-unit-python: install-python
    #!/usr/bin/env bash
    set -euo pipefail

    uv tool install tox --with tox-uv
    tox -e unit

# =============================================================================
# Security Scanning
# =============================================================================

# run security scanning tools and generate reports
security-scan:
    #!/usr/bin/env bash
    set -euo pipefail

    if [ "${GO_SCAN_ENABLED:-false}" = "true" ]; then
        {{ j }} secscan-go
    fi
    if [ "${KEV_SCAN_ENABLED:-false}" = "true" ]; then
        {{ j }} secscan-identify-kevs
    fi

[private]
secscan-identify-kevs:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "identifying known exploited vulnerabilities (KEVs)"

    {{ justfile_directory() }}/scripts/identify-kevs.sh "$GITHUB_REPOSITORY" > cves.txt
    {{ justfile_directory() }}/scripts/create-sarif.sh < cves.txt > cves.sarif
    {{ justfile_directory() }}/scripts/upload-sarif.sh cves.sarif "$GITHUB_REPOSITORY"

[private]
secscan-go:
    #!/usr/bin/env bash
    set -euo pipefail

    # Gosec Scan
    go install github.com/securego/gosec/v2/cmd/gosec@v2.27.1
    gosec ./...

    gosec -fmt sarif -out results.sarif ./...

    # Trivy Scan
    go install github.com/aquasecurity/trivy/cmd/trivy@v0.45.1
    trivy fs --scanners vuln,secret,misconfig .

# TODO: this should be outside,
# since it doesn't operate on the code or its artifacts
[private]
secscan-canonical:
    #!/usr/bin/env bash
    set -euo pipefail

    sudo snap install canonical-secscan-client
    sudo snap connect canonical-secscan-client:home system:home

    sudo snap install juju --channel=4.0/stable
    juju download <charm-name> --arch=<architecture> --channel=<channel> --filepath=charm-under-test.charm

    set +e
    secscan-client --batch submit --scanner trivy --type package --format charm charm-under-test.charm --wait-and-print | tee charm-secscan.txt
    echo "secscan-return-code=$?"
    set -e

# =============================================================================
# Build
# =============================================================================

# build artifacts
build:
    #!/usr/bin/env bash
    set -euo pipefail

    if [ "${GO_ENABLED:-false}" = "true" ]; then
        {{ j }} build-go
    fi
    if [ "${PYTHON_ENABLED:-false}" = "true" ]; then
        {{ j }} build-python
    fi
    if [ "${TYPESCRIPT_ENABLED:-false}" = "true" ]; then
        {{ j }} build-typescript
    fi
    if [ "${CHARMCRAFT_ENABLED:-false}" = "true" ]; then
        {{ j }} build-charm
    fi
    if [ "${SNAPCRAFT_ENABLED:-false}" = "true" ]; then
        {{ j }} build-snap
    fi
    if [ "${ROCKCRAFT_ENABLED:-false}" = "true" ]; then
        {{ j }} build-rock
    fi

[private]
build-python: install-python
    #!/usr/bin/env bash
    set -euo pipefail

    uv build

[private]
build-typescript: install-bun
    #!/usr/bin/env bash
    set -euo pipefail

    bun run build

[private]
build-go:
    #!/usr/bin/env bash
    set -euo pipefail

    go build ./...

[private]
build-charm:
    #!/usr/bin/env bash
    set -euo pipefail

    charmcraft fetch-libs
    charmcraft pack --verbose

[private]
build-snap:
    #!/usr/bin/env bash
    set -euo pipefail

    snapcraft pack --verbose

[private]
build-rock:
    #!/usr/bin/env bash
    set -euo pipefail

    rockcraft pack

# =============================================================================
# Integration Testing
# =============================================================================

# test built artifacts in a production-like environment
test-integration:
    #!/usr/bin/env bash
    set -euo pipefail

    if [ "${CHARM_ENABLED:-false}" = "true" ]; then
        {{ j }} test-integration-charm
    fi
    if [ "${SNAP_ENABLED:-false}" = "true" ]; then
        {{ j }} test-integration-snap
    fi
    if [ "${ROCK_ENABLED:-false}" = "true" ]; then
        {{ j }} test-integration-rock
    fi

[private]
test-integration-charm: install-python
    #!/usr/bin/env bash
    set -euo pipefail
    echo "running integration test for $CHARM_FILE_NAME"

    uv tool install tox --with tox-uv
    tox -e integration -- --charm_path "$CHARM_FILE_NAME"

[private]
test-integration-snap:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "running integration test for $SNAP_FILE_NAME"

    sudo snap install --dangerous $SNAP_FILE_NAME
    if [ -n "${SNAP_SERVICE_NAME:-}" ]; then
        sudo snap start "$SNAP_SERVICE_NAME"
        sleep 10
        if [ -n "${SNAP_SERVICE_PORT:-}" ] && [ "$SNAP_SERVICE_PORT" != "0" ]; then
            if ss -tuln | grep ":${SNAP_SERVICE_PORT}"; then
                echo "service is listening on port ${SNAP_SERVICE_PORT}"
            else
                echo "service is NOT listening on port ${SNAP_SERVICE_PORT}"
                sudo snap remove --purge "$SNAP_FILE_NAME"
                exit 1
            fi
        fi
    fi

    command -v "$SNAP_EXECUTABLE_NAME" >/dev/null
    "$SNAP_EXECUTABLE_NAME" --help

[private]
test-integration-rock:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "running integration test for $ROCK_FILE_NAME"

    sudo rockcraft.skopeo --insecure-policy copy \
        oci-archive:"$ROCK_FILE_NAME" \
        docker-daemon:"$ROCK_FILE_NAME:latest"
    docker run --rm -d --name rock-integration-test "$ROCK_FILE_NAME:latest"
    sleep 5

    if docker ps | grep rock-integration-test; then
        echo "rock container is running successfully"
    else
        echo "rock container failed to start"
        docker logs rock-integration-test
        exit 1
    fi

# =============================================================================
# Publishing
# =============================================================================

# publish built artifacts to their respective stores/registries
publish:
    #!/usr/bin/env bash
    set -euo pipefail

    if [ "${PUBLISH_CHARM:-false}" = "true" ]; then
        {{ j }} publish-charm
    fi
    if [ "${PUBLISH_SNAP:-false}" = "true" ]; then
        {{ j }} publish-snap
    fi
    if [ "${PUBLISH_ROCK:-false}" = "true" ]; then
        {{ j }} publish-rock
    fi
    if [ "${PUBLISH_PYTHON:-false}" = "true" ]; then
        {{ j }} publish-python
    fi

# publish a charm to CharmHub
[private]
publish-charm:
    #!/usr/bin/env bash
    set -euo pipefail

    channel="${CHARM_CHANNEL:-latest}"
    channel="$channel/edge"
    echo "publishing charm(s) to channel: $channel"


    charm=$(ls *.charm 2>/dev/null | head -n 1)
    if [ -z "$charm" ]; then
        echo "::error::No charm file found to publish"
        exit 1
    fi

    charm_name=$(yq -r '.name' charmcraft.yaml)

    echo "Uploading $charm"
    revision=$(charmcraft upload "$charm" --format json | yq -r '.revision')
    echo "Releasing $charm_name revision $revision to $channel"
    charmcraft release "$charm_name" --revision "$revision" --channel "$channel"

# publish a snap to the Snap Store
[private]
publish-snap:
    #!/usr/bin/env bash
    set -euo pipefail

    release_channel="${SNAP_TRACK:-latest}/edge"

    snap=$(ls *.snap 2>/dev/null | head -n 1)
    if [ -z "$snap" ]; then
        echo "::error::No snap file found to publish"
        exit 1
    fi

    echo "Publishing $snap to $release_channel"
    snapcraft upload "$snap" --release "$release_channel"

# publish a rock to a container registry
[private]
publish-rock:
    #!/usr/bin/env bash
    set -euo pipefail

    image_name=$(yq -r '.name' rockcraft.yaml)
    version=$(yq -r '.version' rockcraft.yaml)
    prefix="ghcr.io/canonical/${image_name}"

    read -r -a ARCH_LIST <<< "${ROCK_ARCHITECTURES:-amd64}"

    for arch in "${ARCH_LIST[@]}"; do
        rock_file=$(ls *_"${arch}".rock 2>/dev/null | head -n 1)
        if [ -z "$rock_file" ]; then
            echo "::error::No rock file found for architecture: $arch"
            exit 1
        fi

        echo "importing $rock_file as ${prefix}:${version}-${arch}"
        sudo rockcraft.skopeo --insecure-policy copy \
            oci-archive:"$rock_file" \
            docker-daemon:"${prefix}:${version}-${arch}"
        docker push "${prefix}:${version}-${arch}"
    done

    # Build and push a multi-arch manifest list pointing at the per-arch images.
    echo "Creating multi-arch manifest: ${prefix}:${version}"
    MANIFEST_ARGS=()
    for arch in "${ARCH_LIST[@]}"; do
        MANIFEST_ARGS+=("${prefix}:${version}-${arch}")
    done
    docker manifest create "${prefix}:${version}" "${MANIFEST_ARGS[@]}"
    docker manifest push "${prefix}:${version}"

    echo "creating latest manifest: ${prefix}:latest"
    docker manifest create "${prefix}:latest" "${MANIFEST_ARGS[@]}"
    docker manifest push "${prefix}:latest"

# publish a package to PyPI
[private]
publish-python: install-python
    #!/usr/bin/env bash
    set -euo pipefail

    uv publish
