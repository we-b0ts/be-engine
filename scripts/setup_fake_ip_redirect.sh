#!/usr/bin/env bash
set -euo pipefail

SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
source "$SCRIPT_DIR/intercept-user.sh"

ACTION="${1:-up}"
FAKE_CIDR="${FAKE_CIDR:-198.18.0.0/15}"
GATEWAY_PORT="${GATEWAY_PORT:-15001}"
UDP_GATEWAY_PORT="${UDP_GATEWAY_PORT:-15002}"
ENABLE_TCP="${ENABLE_TCP:-1}"
ENABLE_UDP="${ENABLE_UDP:-1}"
INTERCEPT_UID=""

usage() {
  cat >&2 <<EOF
Usage:
  sudo FAKE_CIDR=$FAKE_CIDR GATEWAY_PORT=$GATEWAY_PORT UDP_GATEWAY_PORT=$UDP_GATEWAY_PORT $0 up
  sudo FAKE_CIDR=$FAKE_CIDR GATEWAY_PORT=$GATEWAY_PORT UDP_GATEWAY_PORT=$UDP_GATEWAY_PORT $0 down

This redirects TCP and UDP traffic whose destination is inside FAKE_CIDR.
Redirects are always limited to the fixed Unix user $TRAFFIC_INTERCEPT_USER.
Set ENABLE_TCP=0 or ENABLE_UDP=0 to skip either protocol.
EOF
}

if [ "$ACTION" != "up" ] && [ "$ACTION" != "down" ]; then
  usage
  exit 2
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "this script must be run as root" >&2
  exit 1
fi

route_exists() {
  ip route show table local | grep -Fq "local $FAKE_CIDR dev lo"
}

rule_exists() {
  local protocol="$1"
  local port="$2"
  local owner_args=()
  mapfile -t owner_args < <(owner_match_args)
  iptables -t nat -C OUTPUT \
    -p "$protocol" \
    "${owner_args[@]}" \
    -d "$FAKE_CIDR" \
    -j REDIRECT --to-ports "$port" >/dev/null 2>&1
}

add_rule() {
  local protocol="$1"
  local port="$2"
  if rule_exists "$protocol" "$port"; then
    return
  fi
  owner_args=()
  mapfile -t owner_args < <(owner_match_args)
  iptables -t nat -A OUTPUT \
    -p "$protocol" \
    "${owner_args[@]}" \
    -d "$FAKE_CIDR" \
    -j REDIRECT --to-ports "$port"
}

delete_rules() {
  local protocol="$1"
  local port="$2"
  local protocol_number
  local rule_number
  case "$protocol" in
    tcp) protocol_number=6 ;;
    udp) protocol_number=17 ;;
    *) echo "unsupported redirect protocol: $protocol" >&2; return 2 ;;
  esac
  while true; do
    rule_number="$(
      iptables -t nat -L OUTPUT --line-numbers -n \
        | awk -v protocol="$protocol_number" -v cidr="$FAKE_CIDR" -v port="$port" \
          '$2 == "REDIRECT" && $3 == protocol && $6 == cidr && $0 ~ ("redir ports " port "$") { print $1; exit }'
    )"
    if [ -z "$rule_number" ]; then
      break
    fi
    iptables -t nat -D OUTPUT "$rule_number"
  done
}

owner_match_args() {
  printf '%s\n' -m owner --uid-owner "$INTERCEPT_UID"
}

if [ "$ACTION" = "up" ]; then
  INTERCEPT_UID="$(traffic_intercept_uid)"
  delete_rules tcp "$GATEWAY_PORT"
  delete_rules udp "$UDP_GATEWAY_PORT"
  if ! route_exists; then
    ip route add local "$FAKE_CIDR" dev lo
  fi

  if [ "$ENABLE_TCP" = "1" ]; then
    add_rule tcp "$GATEWAY_PORT"
  fi
  if [ "$ENABLE_UDP" = "1" ]; then
    add_rule udp "$UDP_GATEWAY_PORT"
  fi

  echo "fake IP redirect enabled: $FAKE_CIDR tcp=$ENABLE_TCP:$GATEWAY_PORT udp=$ENABLE_UDP:$UDP_GATEWAY_PORT"
  echo "owner scope: $TRAFFIC_INTERCEPT_USER (uid $INTERCEPT_UID)"
else
  if [ "$ENABLE_TCP" = "1" ]; then
    delete_rules tcp "$GATEWAY_PORT"
  fi
  if [ "$ENABLE_UDP" = "1" ]; then
    delete_rules udp "$UDP_GATEWAY_PORT"
  fi

  if route_exists; then
    ip route del local "$FAKE_CIDR" dev lo
  fi

  echo "fake IP redirect disabled: $FAKE_CIDR"
fi
