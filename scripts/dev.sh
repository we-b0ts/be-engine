#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat >&2 <<EOF
Usage:
  $0 [--dns|--no-dns] [config.toml] [-- extra traffic-recorder-proxy args...]

Options:
  --dns       Enable local DNS capture and fake-IP TCP redirect. This is default.
  --no-dns    Skip local DNS capture and fake-IP TCP redirect.

DNS/fake-IP rules are automatically removed when this script exits.
EOF
}

ENABLE_DNS=1
CONFIG="config.example.toml"
CONFIG_SET=0
APP_ARGS=()

while [ "$#" -gt 0 ]; do
  case "$1" in
    --dns)
      ENABLE_DNS=1
      shift
      ;;
    --no-dns)
      ENABLE_DNS=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      APP_ARGS+=("$@")
      break
      ;;
    *)
      if [ "$CONFIG_SET" -eq 0 ]; then
        CONFIG="$1"
        CONFIG_SET=1
      else
        APP_ARGS+=("$1")
      fi
      shift
      ;;
  esac
done

export RUST_LOG="${RUST_LOG:-info}"

if ! command -v cargo >/dev/null 2>&1; then
  if [ -x "$HOME/.cargo/bin/cargo" ]; then
    export PATH="$HOME/.cargo/bin:$PATH"
  else
    echo "cargo not found. Install Rust first, or source \$HOME/.cargo/env." >&2
    exit 1
  fi
fi

run_args=(-- --config "$CONFIG" "${APP_ARGS[@]}")

if ! cargo watch --version >/dev/null 2>&1; then
  echo "cargo-watch is not installed; installing with: cargo install cargo-watch" >&2
  if ! cargo install cargo-watch; then
    echo "failed to install cargo-watch" >&2
    exit 1
  fi
fi

run_as_root() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  else
    if ! command -v sudo >/dev/null 2>&1; then
      echo "sudo not found; --dns setup requires root privileges" >&2
      exit 1
    fi
    sudo env \
      "DNS_IP=${DNS_IP:-127.0.0.153}" \
      "DNS_PORT=${DNS_PORT:-15353}" \
      "UPSTREAM_DNS=${UPSTREAM_DNS:-10.10.10.10:53}" \
      "FAKE_CIDR=${FAKE_CIDR:-198.18.0.0/15}" \
      "GATEWAY_PORT=${GATEWAY_PORT:-15001}" \
      "OWNER_UID=${OWNER_UID:-}" \
      "$@"
  fi
}

DNS_CAPTURE_UP=0
FAKE_REDIRECT_UP=0

cleanup_dns() {
  local exit_code=$?
  trap - EXIT
  if [ "$ENABLE_DNS" -eq 1 ]; then
    set +e
    if [ "$FAKE_REDIRECT_UP" -eq 1 ]; then
      run_as_root "$ROOT_DIR/scripts/setup_fake_ip_redirect.sh" down
    fi
    if [ "$DNS_CAPTURE_UP" -eq 1 ]; then
      run_as_root "$ROOT_DIR/scripts/setup_local_dns.sh" down
    fi
  fi
  exit "$exit_code"
}

if [ "$ENABLE_DNS" -eq 1 ]; then
  trap cleanup_dns EXIT
  run_as_root "$ROOT_DIR/scripts/setup_local_dns.sh" up
  DNS_CAPTURE_UP=1
  run_as_root "$ROOT_DIR/scripts/setup_fake_ip_redirect.sh" up
  FAKE_REDIRECT_UP=1
fi

cargo watch \
  --watch src \
  --watch tests \
  --watch Cargo.toml \
  --watch Cargo.lock \
  --watch "$CONFIG" \
  --exec "run ${run_args[*]}"
