#!/usr/bin/env bash
set -euo pipefail

ACTION="${1:-up}"
FAKE_CIDR="${FAKE_CIDR:-198.18.0.0/15}"
GATEWAY_PORT="${GATEWAY_PORT:-15001}"
UDP_GATEWAY_PORT="${UDP_GATEWAY_PORT:-15002}"
OWNER_UID="${OWNER_UID:-}"
ENABLE_TCP="${ENABLE_TCP:-1}"
ENABLE_UDP="${ENABLE_UDP:-1}"

usage() {
  cat >&2 <<EOF
Usage:
  sudo FAKE_CIDR=$FAKE_CIDR GATEWAY_PORT=$GATEWAY_PORT UDP_GATEWAY_PORT=$UDP_GATEWAY_PORT OWNER_UID=$OWNER_UID $0 up
  sudo FAKE_CIDR=$FAKE_CIDR GATEWAY_PORT=$GATEWAY_PORT UDP_GATEWAY_PORT=$UDP_GATEWAY_PORT OWNER_UID=$OWNER_UID $0 down

This redirects TCP and UDP traffic whose destination is inside FAKE_CIDR.
Set OWNER_UID to limit redirect to one Unix user.
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
  while rule_exists "$protocol" "$port"; do
    owner_args=()
    mapfile -t owner_args < <(owner_match_args)
    iptables -t nat -D OUTPUT \
      -p "$protocol" \
      "${owner_args[@]}" \
      -d "$FAKE_CIDR" \
      -j REDIRECT --to-ports "$port"
  done
}

owner_match_args() {
  if [ -n "$OWNER_UID" ]; then
    printf '%s\n' -m owner --uid-owner "$OWNER_UID"
  fi
}

if [ "$ACTION" = "up" ]; then
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
  if [ -n "$OWNER_UID" ]; then
    echo "owner UID scope: $OWNER_UID"
  fi
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
