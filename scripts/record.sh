#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat >&2 <<EOF
Usage:
  $0 [--dns|--no-dns] [recorder-config.toml] [-- extra traffic-recorder-proxy args...]

Options:
  --dns       Enable local DNS capture and fake-IP TCP redirect. This is default.
  --no-dns    Skip local DNS capture and fake-IP TCP redirect.

DNS/fake-IP rules are automatically removed when this script exits.
OWNER_UID overrides [local_record] owner filtering from the config file.
EOF
}

ENABLE_DNS=1
CONFIG="recorder.example.toml"
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

load_local_record_config() {
  if [ ! -f "$CONFIG" ]; then
    return
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required to read [local_record] from $CONFIG" >&2
    exit 1
  fi

  mapfile -t local_record_values < <(python3 - "$CONFIG" <<'PY'
import sys

try:
    import tomllib
except ModuleNotFoundError:
    sys.stderr.write("tomllib is required; use Python 3.11+ to read recorder TOML config.\n")
    raise SystemExit(1)

path = sys.argv[1]
with open(path, "rb") as fh:
    config = tomllib.load(fh)
local_record = config.get("local_record", {})

def value(name, default=""):
    item = local_record.get(name, default)
    if isinstance(item, bool):
        return "1" if item else "0"
    return str(item)

print(value("enabled", False))
print(value("record_user"))
print(value("owner_uid"))
PY
)

  LOCAL_RECORD_ENABLED="${local_record_values[0]}"
  LOCAL_RECORD_USER="${local_record_values[1]}"
  LOCAL_RECORD_OWNER_UID="${local_record_values[2]}"
}

resolve_owner_uid() {
  LOCAL_RECORD_ENABLED=0
  LOCAL_RECORD_USER=""
  LOCAL_RECORD_OWNER_UID=""
  load_local_record_config

  if [ -n "${OWNER_UID:-}" ]; then
    export OWNER_UID
    return
  fi

  if [ "$LOCAL_RECORD_ENABLED" != "1" ]; then
    export OWNER_UID=""
    return
  fi

  if [ -n "$LOCAL_RECORD_OWNER_UID" ]; then
    export OWNER_UID="$LOCAL_RECORD_OWNER_UID"
    return
  fi

  if [ -z "$LOCAL_RECORD_USER" ]; then
    echo "[local_record] is enabled but neither record_user nor owner_uid is set in $CONFIG" >&2
    exit 1
  fi

  if ! OWNER_UID="$(id -u "$LOCAL_RECORD_USER" 2>/dev/null)"; then
    cat >&2 <<EOF
record user not found: $LOCAL_RECORD_USER
Create it with:
  sudo useradd --system --create-home --shell /bin/bash $LOCAL_RECORD_USER
EOF
    exit 1
  fi
  export OWNER_UID
}

if [ "$ENABLE_DNS" -eq 1 ]; then
  resolve_owner_uid
else
  export OWNER_UID="${OWNER_UID:-}"
fi

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
      "OWNER_UID=$OWNER_UID" \
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
  if [ -n "$OWNER_UID" ]; then
    echo "local recording owner filter enabled: OWNER_UID=$OWNER_UID" >&2
  fi
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
