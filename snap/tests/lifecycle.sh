#!/bin/bash
set -euo pipefail

if [[ "${GITHUB_ACTIONS:-}" != true ]]; then
    echo 'Run only on a disposable GitHub Actions runner.' >&2
    exit 1
fi
if snap list notary >/dev/null 2>&1; then
    echo 'Refusing to modify an existing Notary installation.' >&2
    exit 1
fi

artifact="$(realpath "${1:?snap artifact required}")"
common=/var/snap/notary/common
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
base=https://localhost:3000
cookie="$work/cookies"

request() {
    curl --fail --silent --show-error --cacert "$work/cert.pem" \
        --connect-timeout 2 --max-time 10 -b "$cookie" -c "$cookie" "$@"
}

ready() {
    curl --fail --silent --show-error --cacert "$work/cert.pem" \
        --retry 30 --retry-all-errors --retry-delay 1 --retry-max-time 90 \
        --connect-timeout 2 --max-time 5 "$base/status" | jq -e '.data.version | type == "string"'
}

check_data() {
    ready
    request "$base/status" | jq -e '.data.initialized == true'
    request -H 'Content-Type: application/json' -d "$credentials" "$base/login" >/dev/null
    request "$base/api/v1/certificate_requests/$request_id" |
        jq -e --arg cert "$(cat "$work/issued.pem")" '.data.certificate_chain | contains($cert)'
}

sudo snap install --dangerous "$artifact"
[[ "$(sudo systemctl is-enabled snap.notary.notaryd.service)" == disabled ]]
if sudo systemctl is-active --quiet snap.notary.notaryd.service; then
    echo 'Fresh installation unexpectedly started the daemon.' >&2
    exit 1
fi
openssl req -newkey rsa:2048 -nodes -keyout "$work/key.pem" -x509 -days 2 \
    -out "$work/cert.pem" -subj /CN=localhost -addext subjectAltName=DNS:localhost
sudo install -m 600 "$work/key.pem" "$common/key.pem"
sudo install -m 644 "$work/cert.pem" "$common/cert.pem"
sudo snap start --enable notary.notaryd
ready
request "$base/" | grep -q 'id="app"'
request "$base/status" | jq -e '.data.initialized == false'
credentials='{"email":"admin@notary.test","password":"SnapTest1234!"}'
request -H 'Content-Type: application/json' \
    -d "$(jq '. + {role_id: 0}' <<<"$credentials")" "$base/api/v1/accounts" >/dev/null
request -H 'Content-Type: application/json' -d "$credentials" "$base/login" >/dev/null

openssl req -newkey rsa:2048 -nodes -keyout "$work/request.key" -out "$work/request.csr" -subj /CN=service.test
openssl x509 -req -in "$work/request.csr" -CA "$work/cert.pem" -CAkey "$work/key.pem" \
    -CAcreateserial -out "$work/issued.pem" -days 1
request_id="$(request -H 'Content-Type: application/json' \
    -d "$(jq -n --rawfile csr "$work/request.csr" '{csr: $csr}')" \
    "$base/api/v1/certificate_requests" | jq -er '.data.id')"
request -H 'Content-Type: application/json' \
    -d "$(jq -n --rawfile cert "$work/issued.pem" --rawfile ca "$work/cert.pem" '{certificate: ($cert + $ca)}')" \
    "$base/api/v1/certificate_requests/$request_id/certificate" >/dev/null
check_data

sudo snap set notary log-level=debug
check_data
sudo snap restart notary.notaryd
check_data
sudo mkdir -p "$common/backups"
if sudo notary backup -d "$common/database" -f "$common/backups"; then
    echo 'Backup incorrectly succeeded while the daemon was running.' >&2
    exit 1
fi
sudo snap stop notary.notaryd
[[ "$(sudo systemctl show snap.notary.notaryd.service -p ExecMainStatus --value)" == 0 ]]
sudo journalctl -u snap.notary.notaryd.service --no-pager | grep 'Shutting down server'
sudo notary backup -d "$common/database" -f "$common/backups"
archive="$(sudo find "$common/backups" -name 'backup_*.tar.gz' -print -quit)"
[[ -n "$archive" ]]
sudo notary restore -d "$common/database" -f "$archive"
sudo snap start notary.notaryd
check_data

old_pid="$(sudo systemctl show snap.notary.notaryd.service -p MainPID --value)"
sudo snap install --dangerous "$artifact"
check_data
[[ "$(sudo systemctl show snap.notary.notaryd.service -p MainPID --value)" != "$old_pid" ]]
sudo snap revert notary
check_data
[[ "$(sudo systemctl is-enabled snap.notary.notaryd.service)" == enabled ]]