#!/usr/bin/env bash
set -euo pipefail

ACTION="${1:-up}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CA_SOURCE="${CA_SOURCE:-$ROOT_DIR/data/traffic-recorder-ca.pem}"
DEST_DIR="/usr/local/share/ca-certificates"
DEST_FILE="$DEST_DIR/traffic-recorder-ca.crt"

usage() {
  cat >&2 <<EOF
Usage:
  sudo $0 up
  sudo $0 down
  $0 status

Installs or removes the recorder root CA from the Linux system trust store.
CA_SOURCE can override the source CA path; by default it uses:
  ./data/traffic-recorder-ca.pem
EOF
}

if [ "$ACTION" != "up" ] && [ "$ACTION" != "down" ] && [ "$ACTION" != "status" ]; then
  usage
  exit 2
fi

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "this action must be run as root; try: sudo $0 $ACTION" >&2
    exit 1
  fi
}

print_ca() {
  local path="$1"
  if command -v openssl >/dev/null 2>&1; then
    openssl x509 -in "$path" -noout -subject -issuer -fingerprint -sha256
  else
    echo "$path"
  fi
}

case "$ACTION" in
  up)
    require_root
    if [ ! -f "$CA_SOURCE" ]; then
      echo "CA file not found: $CA_SOURCE" >&2
      echo "start the recorder once so it can generate ./data/traffic-recorder-ca.pem, or set CA_SOURCE." >&2
      exit 1
    fi
    install -m 0644 "$CA_SOURCE" "$DEST_FILE"
    update-ca-certificates
    echo "installed recorder CA into system trust store:"
    print_ca "$DEST_FILE"
    ;;
  down)
    require_root
    rm -f "$DEST_FILE"
    update-ca-certificates --fresh
    echo "removed recorder CA from system trust store: $DEST_FILE"
    ;;
  status)
    if [ -f "$DEST_FILE" ]; then
      echo "recorder CA is installed at $DEST_FILE"
      print_ca "$DEST_FILE"
    else
      echo "recorder CA is not installed at $DEST_FILE"
      exit 1
    fi
    ;;
esac
