#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CALLER_CWD="$(pwd)"

usage() {
  cat >&2 <<EOF
Usage:
  $0 [--intercept|--no-intercept] [replay-config.toml] [-- extra replay args...]

Options:
  --intercept     Enable local DNS capture and fake-IP TCP redirect. This is default.
  --no-intercept  Start replay listeners without changing local DNS/iptables.

The config file defaults to replay.example.toml in the current directory.
Ensure the traffic-recorder-proxy command is available on PATH before starting.
TRAFFIC_RECORDER_PROXY_BIN is accepted as an explicit fallback override.
DNS/fake-IP rules are removed when this script exits.
EOF
}

ENABLE_INTERCEPT=""
CONFIG="replay.example.toml"
CONFIG_SET=0
APP_ARGS=()

while [ "$#" -gt 0 ]; do
  case "$1" in
    --intercept)
      ENABLE_INTERCEPT=1
      shift
      ;;
    --no-intercept)
      ENABLE_INTERCEPT=0
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

resolve_path() {
  local path="$1"
  local base="${2:-$CALLER_CWD}"
  if [ -z "$path" ]; then
    printf '\n'
  elif [[ "$path" = /* ]]; then
    printf '%s\n' "$path"
  else
    printf '%s\n' "$base/$path"
  fi
}

CONFIG_PATH="$(resolve_path "$CONFIG")"
if [ ! -f "$CONFIG_PATH" ]; then
  echo "replay config not found: $CONFIG" >&2
  exit 1
fi
CONFIG_DIR="$(cd "$(dirname "$CONFIG_PATH")" && pwd)"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required to read $CONFIG_PATH" >&2
  exit 1
fi

find_proxy_binary() {
  local repo_candidate="$SCRIPT_DIR/../../../target/debug/traffic-recorder-proxy"
  local cwd_candidate="$CALLER_CWD/target/debug/traffic-recorder-proxy"

  if command -v traffic-recorder-proxy >/dev/null 2>&1; then
    command -v traffic-recorder-proxy
    return
  fi

  if [ -n "${TRAFFIC_RECORDER_PROXY_BIN:-}" ]; then
    if [ ! -x "$TRAFFIC_RECORDER_PROXY_BIN" ]; then
      echo "TRAFFIC_RECORDER_PROXY_BIN is not executable: $TRAFFIC_RECORDER_PROXY_BIN" >&2
      exit 1
    fi
    printf '%s\n' "$TRAFFIC_RECORDER_PROXY_BIN"
    return
  fi

  if [ -x "$cwd_candidate" ]; then
    printf '%s\n' "$cwd_candidate"
    return
  fi

  if [ -x "$repo_candidate" ]; then
    printf '%s\n' "$(cd "$(dirname "$repo_candidate")" && pwd)/$(basename "$repo_candidate")"
    return
  fi

  echo "traffic-recorder-proxy command not found on PATH. Add it to PATH, for example ~/.local/bin/traffic-recorder-proxy, or set TRAFFIC_RECORDER_PROXY_BIN=/path/to/traffic-recorder-proxy." >&2
  exit 1
}

PROXY_BIN="$(find_proxy_binary)"

mapfile -t replay_values < <(python3 - "$CONFIG_PATH" <<'PY'
import sys

try:
    import tomllib
except ModuleNotFoundError:
    sys.stderr.write("tomllib is required; use Python 3.11+ to read replay TOML config.\n")
    raise SystemExit(1)

path = sys.argv[1]
with open(path, "rb") as fh:
    config = tomllib.load(fh)
replay = config.get("replay", {})

def value(name, default=""):
    item = replay.get(name, default)
    if isinstance(item, bool):
        return "1" if item else "0"
    return str(item)

print(value("case"))
print(value("dns_listen", "127.0.0.153:15353"))
print(value("tcp_listen", "127.0.0.1:15001"))
print(value("fake_cidr", "198.18.0.0/15"))
print(value("report"))
print(value("enable_intercept", True))
print(value("upstream_dns", "10.10.10.10:53"))
print(value("owner_uid"))
PY
)

CASE_DIR="${replay_values[0]}"
DNS_LISTEN="${replay_values[1]}"
TCP_LISTEN="${replay_values[2]}"
FAKE_CIDR="${replay_values[3]}"
REPORT_PATH="${replay_values[4]}"
CONFIG_ENABLE_INTERCEPT="${replay_values[5]}"
UPSTREAM_DNS_VALUE="${replay_values[6]}"
OWNER_UID_VALUE="${replay_values[7]}"

if [ -z "$CASE_DIR" ]; then
  echo "replay.case must be set in $CONFIG_PATH" >&2
  exit 1
fi
CASE_DIR="$(resolve_path "$CASE_DIR" "$CONFIG_DIR")"
REPORT_PATH="$(resolve_path "$REPORT_PATH" "$CONFIG_DIR")"

if [ "$ENABLE_INTERCEPT" = "" ]; then
  ENABLE_INTERCEPT="$CONFIG_ENABLE_INTERCEPT"
fi

split_host_port() {
  local value="$1"
  local host="${value%:*}"
  local port="${value##*:}"
  host="${host#[}"
  host="${host%]}"
  printf '%s\n%s\n' "$host" "$port"
}

mapfile -t dns_parts < <(split_host_port "$DNS_LISTEN")
DNS_IP_VALUE="${dns_parts[0]}"
DNS_PORT_VALUE="${dns_parts[1]}"
mapfile -t tcp_parts < <(split_host_port "$TCP_LISTEN")
GATEWAY_PORT_VALUE="${tcp_parts[1]}"

run_as_root() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  else
    if ! command -v sudo >/dev/null 2>&1; then
      echo "sudo not found; intercept setup requires root privileges" >&2
      exit 1
    fi
    sudo env \
      "DNS_IP=$DNS_IP_VALUE" \
      "DNS_PORT=$DNS_PORT_VALUE" \
      "UPSTREAM_DNS=$UPSTREAM_DNS_VALUE" \
      "FAKE_CIDR=$FAKE_CIDR" \
      "GATEWAY_PORT=$GATEWAY_PORT_VALUE" \
      "OWNER_UID=$OWNER_UID_VALUE" \
      "$@"
  fi
}

DNS_CAPTURE_UP=0
FAKE_REDIRECT_UP=0

cleanup_intercept() {
  local exit_code=$?
  trap - EXIT
  if [ "$ENABLE_INTERCEPT" = "1" ]; then
    set +e
    if [ "$FAKE_REDIRECT_UP" -eq 1 ]; then
      run_as_root "$SCRIPT_DIR/setup_fake_ip_redirect.sh" down
    fi
    if [ "$DNS_CAPTURE_UP" -eq 1 ]; then
      run_as_root "$SCRIPT_DIR/setup_local_dns.sh" down
    fi
  fi
  exit "$exit_code"
}

if [ "$ENABLE_INTERCEPT" = "1" ]; then
  trap cleanup_intercept EXIT
  run_as_root "$SCRIPT_DIR/setup_local_dns.sh" up
  DNS_CAPTURE_UP=1
  run_as_root "$SCRIPT_DIR/setup_fake_ip_redirect.sh" up
  FAKE_REDIRECT_UP=1
fi

args=(replay --case "$CASE_DIR" --dns-listen "$DNS_LISTEN" --tcp-listen "$TCP_LISTEN" --fake-cidr "$FAKE_CIDR")
if [ -n "$REPORT_PATH" ]; then
  args+=(--report "$REPORT_PATH")
fi
args+=("${APP_ARGS[@]}")

export RUST_LOG="${RUST_LOG:-info}"
"$PROXY_BIN" "${args[@]}"
