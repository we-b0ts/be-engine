#!/usr/bin/env bash
set -euo pipefail

ACTION="${1:-up}"
FAKE_CIDR="${FAKE_CIDR:-198.18.0.0/15}"
GATEWAY_PORT="${GATEWAY_PORT:-15001}"
OWNER_UID="${OWNER_UID:-}"

usage() {
  cat >&2 <<EOF
Usage:
  sudo FAKE_CIDR=$FAKE_CIDR GATEWAY_PORT=$GATEWAY_PORT OWNER_UID=$OWNER_UID $0 up
  sudo FAKE_CIDR=$FAKE_CIDR GATEWAY_PORT=$GATEWAY_PORT OWNER_UID=$OWNER_UID $0 down

This only redirects TCP traffic whose destination is inside FAKE_CIDR.
Set OWNER_UID to limit redirect to one Unix user.
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
  local owner_args=()
  mapfile -t owner_args < <(owner_match_args)
  iptables -t nat -C OUTPUT \
    -p tcp \
    "${owner_args[@]}" \
    -d "$FAKE_CIDR" \
    -j REDIRECT --to-ports "$GATEWAY_PORT" >/dev/null 2>&1
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

  if ! rule_exists; then
    owner_args=()
    mapfile -t owner_args < <(owner_match_args)
    iptables -t nat -A OUTPUT \
      -p tcp \
      "${owner_args[@]}" \
      -d "$FAKE_CIDR" \
      -j REDIRECT --to-ports "$GATEWAY_PORT"
  fi

  echo "fake IP redirect enabled: $FAKE_CIDR -> local TCP port $GATEWAY_PORT"
  if [ -n "$OWNER_UID" ]; then
    echo "owner UID scope: $OWNER_UID"
  fi
else
  while rule_exists; do
    owner_args=()
    mapfile -t owner_args < <(owner_match_args)
    iptables -t nat -D OUTPUT \
      -p tcp \
      "${owner_args[@]}" \
      -d "$FAKE_CIDR" \
      -j REDIRECT --to-ports "$GATEWAY_PORT"
  done

  if route_exists; then
    ip route del local "$FAKE_CIDR" dev lo
  fi

  echo "fake IP redirect disabled: $FAKE_CIDR"
fi
