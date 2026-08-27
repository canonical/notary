#!/usr/bin/env bash
#
# Local 3-node Notary cluster harness.
#
# The containers idle; this script starts, kills and restarts the Notary process
# inside them, so a node can fail and come back without losing its data
# directory. That is what makes failover and recovery testable locally.
#
# Usage: ./harness.sh <command> [args]
# Run ./harness.sh help for the command list.

set -euo pipefail

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HARNESS_DIR}/../.." && pwd)"
BUILD_DIR="${HARNESS_DIR}/build"
CONF_DIR="${BUILD_DIR}/conf"
TOKEN_FILE="${BUILD_DIR}/admin-token"
IMAGE="notary-cluster-harness"
COMPOSE=(docker compose -f "${HARNESS_DIR}/compose.yaml")

NODES=(notary-1 notary-2 notary-3)
ADMIN_EMAIL="admin@canonical.com"
ADMIN_PASSWORD="Admin1234!"

log() { printf '\033[1m==>\033[0m %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# node_name turns "2" or "notary-2" into "notary-2".
node_name() {
  local node="$1"
  [[ "${node}" == notary-* ]] || node="notary-${node}"
  printf '%s' "${node}"
}

# host_port maps a node to the port its API is published on.
host_port() {
  local index="${1##*-}"
  printf '%d' $((3000 + index))
}

require_token() {
  [[ -f "${TOKEN_FILE}" ]] || die "no admin token yet; run '$0 bootstrap' first"
  cat "${TOKEN_FILE}"
}

build_image() {
  log "building the ${IMAGE} image (dqlite is compiled from source, so the first run is slow)"
  docker build -t "${IMAGE}" "${HARNESS_DIR}"
}

generate_cluster_pki() {
  local pki_root="${BUILD_DIR}/cluster-pki"
  mkdir -p "${pki_root}"
  if [[ ! -f "${pki_root}/ca.key" ]]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 365 \
      -keyout "${pki_root}/ca.key" -out "${pki_root}/cluster.crt" \
      -subj "/CN=Notary Cluster CA" \
      -addext "basicConstraints=critical,CA:TRUE" \
      -addext "keyUsage=critical,keyCertSign,cRLSign,digitalSignature" \
      2>/dev/null
  fi

  local node
  for node in "${NODES[@]}"; do
    local node_dir="${pki_root}/${node}"
    mkdir -p "${node_dir}"
    if [[ -f "${node_dir}/node.crt" ]]; then
      continue
    fi
    local ext="${node_dir}/ext.cnf"
    printf '%s\n' \
      "basicConstraints=CA:FALSE" \
      "keyUsage=digitalSignature,keyEncipherment" \
      "extendedKeyUsage=serverAuth,clientAuth" \
      "subjectAltName=DNS:notary-cluster,DNS:${node}" \
      > "${ext}"
    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
      -keyout "${node_dir}/node.key" -out "${node_dir}/node.csr" \
      -subj "/CN=${node}:9000" 2>/dev/null
    openssl x509 -req -in "${node_dir}/node.csr" \
      -CA "${pki_root}/cluster.crt" -CAkey "${pki_root}/ca.key" -CAcreateserial \
      -days 365 -extfile "${ext}" -out "${node_dir}/node.crt" 2>/dev/null
    chmod 600 "${node_dir}/node.key"
    rm -f "${node_dir}/node.csr" "${ext}"
    cp "${pki_root}/cluster.crt" "${node_dir}/cluster.crt"
  done
}

install_node_pki() {
  local node
  node="$(node_name "$1")"
  docker exec "${node}" mkdir -p /data/cluster/pki
  docker cp "${BUILD_DIR}/cluster-pki/${node}/cluster.crt" "${node}:/data/cluster/pki/cluster.crt"
  docker cp "${BUILD_DIR}/cluster-pki/${node}/node.crt" "${node}:/data/cluster/pki/node.crt"
  docker cp "${BUILD_DIR}/cluster-pki/${node}/node.key" "${node}:/data/cluster/pki/node.key"
  docker exec "${node}" chmod 600 /data/cluster/pki/node.key
}

build_binary() {
  [[ -d "${REPO_ROOT}/ui/dist" ]] || die "ui/dist is missing; run 'cd ui && bun install && bun run build' first"

  log "building the notary binary against the container's dqlite"
  mkdir -p "${BUILD_DIR}"
  docker run --rm \
    -v "${REPO_ROOT}":/src \
    -v "${HOME}/go/pkg/mod":/go/pkg/mod \
    -e GOMODCACHE=/go/pkg/mod \
    -w /src \
    "${IMAGE}" \
    go build -o dev/cluster/build/notary .
}

generate_config() {
  log "generating certificates and per-node configuration"
  mkdir -p "${CONF_DIR}"

  local certs="${BUILD_DIR}/certs"
  mkdir -p "${certs}"
  if [[ ! -f "${certs}/server.crt" ]]; then
    # One certificate shared by all three nodes, carrying every node's name as a
    # SAN. This is the API certificate only; cluster-internal certificates are
    # generated separately by generate_cluster_pki.
    openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
      -keyout "${certs}/server.key" -out "${certs}/server.crt" \
      -subj "/CN=notary-cluster-harness" \
      -addext "subjectAltName=DNS:notary-1,DNS:notary-2,DNS:notary-3,DNS:localhost,IP:127.0.0.1" \
      2>/dev/null
  fi

  local node
  for node in "${NODES[@]}"; do
    mkdir -p "${CONF_DIR}/${node}"
    sed "s/__NODE__/${node}/g" "${HARNESS_DIR}/node-config.yaml.tmpl" > "${CONF_DIR}/${node}/conf.yaml"
    cp "${certs}/server.crt" "${certs}/server.key" "${CONF_DIR}/${node}/"
  done
  generate_cluster_pki
}

# start_node launches the Notary process inside a container that is already up.
start_node() {
  local node
  node="$(node_name "$1")"
  log "starting notary on ${node}"
  docker exec -d "${node}" sh -c 'notary start -c /conf/conf.yaml >> /data/notary.log 2>&1'
  wait_for_api "${node}"
}

wait_for_api() {
  local node
  node="$(node_name "$1")"
  local attempt
  for attempt in $(seq 1 60); do
    if docker exec "${node}" curl -fsk "https://localhost:3000/status" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  die "${node} did not serve its API in time; see '$0 logs ${node}'"
}

cmd_up() {
  build_image
  build_binary
  generate_config
  log "starting containers"
  "${COMPOSE[@]}" up -d
}

cmd_bootstrap() {
  local node="notary-1"

  log "bootstrapping the cluster on ${node}"
  install_node_pki "${node}"
  docker exec "${node}" notary cluster bootstrap -c /conf/conf.yaml --name "${node}"
  start_node "${node}"

  log "creating the first admin account"
  docker exec "${node}" curl -fsk -X POST "https://localhost:3000/api/v1/accounts" \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"${ADMIN_EMAIL}\",\"password\":\"${ADMIN_PASSWORD}\",\"role_id\":0}" >/dev/null

  mkdir -p "${BUILD_DIR}"
  # /login returns the session JWT as a Set-Cookie header, not in the body.
  docker exec "${node}" curl -fsk -X POST "https://localhost:3000/login" \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"${ADMIN_EMAIL}\",\"password\":\"${ADMIN_PASSWORD}\"}" \
    -D - -o /dev/null \
    | sed -n 's/.*[Ss]et-[Cc]ookie: *user_token=\([^;]*\).*/\1/p' \
    | tr -d '\r' > "${TOKEN_FILE}"

  [[ -s "${TOKEN_FILE}" ]] || die "couldn't obtain an admin token"
  log "cluster bootstrapped; admin token saved to ${TOKEN_FILE}"
}

cmd_join() {
  [[ $# -ge 1 ]] || die "usage: $0 join <node>"
  local node token
  node="$(node_name "$1")"
  token="$(require_token)"

  log "issuing a join token on notary-1"
  local join_token identity="${node}:9000"
  join_token="$(docker exec -e NOTARY_TOKEN="${token}" notary-1 \
    notary cluster token create -c /conf/conf.yaml --identity "${identity}" --quiet | tr -d '[:space:]')"
  [[ -n "${join_token}" ]] || die "couldn't issue a join token"

  log "joining ${node} with provisioned PKI and the identity-bound token"
  install_node_pki "${node}"
  docker exec "${node}" notary cluster join "${join_token}" \
    -c /conf/conf.yaml \
    --address notary-1:3000 \
    --name "${node}" \
    --ca-cert /conf/server.crt

  start_node "${node}"
}

cmd_status() {
  local token
  token="$(require_token)"
  local node="${1:-notary-1}"
  docker exec -e NOTARY_TOKEN="${token}" "$(node_name "${node}")" \
    notary cluster status -c /conf/conf.yaml
}

# cmd_kill stops the Notary process but leaves the container and its data
# directory intact, which is what a node crash looks like to the rest of the
# cluster.
cmd_kill() {
  [[ $# -ge 1 ]] || die "usage: $0 kill <node> [--hard]"
  local node signal
  node="$(node_name "$1")"
  signal="TERM"
  [[ "${2:-}" == "--hard" ]] && signal="KILL"

  log "sending SIG${signal} to notary on ${node}"
  docker exec "${node}" pkill -"${signal}" -f 'notary start'
}

cmd_restart() {
  [[ $# -ge 1 ]] || die "usage: $0 restart <node>"
  cmd_kill "$1" || true
  sleep 2
  start_node "$1"
}

cmd_logs() {
  local node
  node="$(node_name "${1:-notary-1}")"
  docker exec "${node}" tail -n 200 -f /data/notary.log
}

cmd_shell() {
  local node
  node="$(node_name "${1:-notary-1}")"
  docker exec -it "${node}" bash
}

cmd_down() {
  log "removing containers and volumes"
  "${COMPOSE[@]}" down -v
  rm -f "${TOKEN_FILE}"
}

cmd_help() {
  cat <<'USAGE'
Local 3-node Notary cluster harness.

  up                        build the image and binary, then start three idle containers
  bootstrap                 bootstrap the cluster on notary-1 and create the admin account
  join <node>               join a node with provisioned PKI and an identity-bound token
  status [node]             print cluster status as that node sees it
  kill <node> [--hard]      stop the notary process on a node, keeping its data
  restart <node>            stop and start the notary process on a node
  logs [node]               follow a node's log
  shell [node]              open a shell in a node's container
  down                      remove the containers and their data

A full three-node cluster:

  ./harness.sh up
  ./harness.sh bootstrap
  ./harness.sh join 2
  ./harness.sh join 3
  ./harness.sh status
USAGE
}

main() {
  local command="${1:-help}"
  shift || true

  case "${command}" in
    up)        cmd_up "$@" ;;
    bootstrap) cmd_bootstrap "$@" ;;
    join)      cmd_join "$@" ;;
    status)    cmd_status "$@" ;;
    kill)      cmd_kill "$@" ;;
    restart)   cmd_restart "$@" ;;
    logs)      cmd_logs "$@" ;;
    shell)     cmd_shell "$@" ;;
    down)      cmd_down "$@" ;;
    help|-h|--help) cmd_help ;;
    *) die "unknown command '${command}'; run '$0 help'" ;;
  esac
}

main "$@"
