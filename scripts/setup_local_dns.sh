#!/usr/bin/env bash
set -euo pipefail

ACTION="${1:-up}"
DNS_IP="${DNS_IP:-127.0.0.153}"
DNS_PORT="${DNS_PORT:-15353}"
UPSTREAM_DNS="${UPSTREAM_DNS:-10.10.10.10:53}"
OWNER_UID="${OWNER_UID:-}"
CHAIN="${CHAIN:-TRP_DNS}"

usage() {
  cat >&2 <<EOF
Usage:
  sudo DNS_IP=$DNS_IP DNS_PORT=$DNS_PORT UPSTREAM_DNS=$UPSTREAM_DNS OWNER_UID=$OWNER_UID $0 up
  sudo DNS_IP=$DNS_IP DNS_PORT=$DNS_PORT UPSTREAM_DNS=$UPSTREAM_DNS OWNER_UID=$OWNER_UID $0 down

This captures local UDP/TCP DNS traffic on port 53 and sends it to
DNS_IP:DNS_PORT. UPSTREAM_DNS is excluded so the recorder can forward DNS
queries upstream without recursively hitting itself. For multiple upstreams,
use a comma-separated list. IPv4 values may include an optional :53 suffix.
Set OWNER_UID to limit capture to one Unix user.
EOF
}

if [ "$ACTION" != "up" ] && [ "$ACTION" != "down" ] && [ "$ACTION" != "status" ]; then
  usage
  exit 2
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "this script must be run as root" >&2
  exit 1
fi

split_upstreams() {
  echo "$UPSTREAM_DNS" | tr ',' '\n' | sed -E 's/:53$//'
}

chain_exists() {
  iptables -t nat -L "$CHAIN" >/dev/null 2>&1
}

owner_match_args() {
  if [ -n "$OWNER_UID" ]; then
    printf '%s\n' -m owner --uid-owner "$OWNER_UID"
  fi
}

ensure_chain() {
  if ! chain_exists; then
    iptables -t nat -N "$CHAIN"
  fi
  iptables -t nat -F "$CHAIN"
}

output_rule_exists() {
  local proto="$1"
  local owner_args=()
  mapfile -t owner_args < <(owner_match_args)
  iptables -t nat -C OUTPUT \
    -p "$proto" \
    "${owner_args[@]}" \
    --dport 53 \
    -j "$CHAIN" >/dev/null 2>&1
}

add_output_rule() {
  local proto="$1"
  local owner_args=()
  mapfile -t owner_args < <(owner_match_args)
  if ! output_rule_exists "$proto"; then
    iptables -t nat -A OUTPUT \
      -p "$proto" \
      "${owner_args[@]}" \
      --dport 53 \
      -j "$CHAIN"
  fi
}

delete_output_rule() {
  local proto="$1"
  local owner_args=()
  mapfile -t owner_args < <(owner_match_args)
  while output_rule_exists "$proto"; do
    iptables -t nat -D OUTPUT \
      -p "$proto" \
      "${owner_args[@]}" \
      --dport 53 \
      -j "$CHAIN"
  done
}

populate_chain() {
  local proto
  local upstream
  for proto in udp tcp; do
    for upstream in $(split_upstreams); do
      if [ -z "$upstream" ]; then
        continue
      fi
      iptables -t nat -A "$CHAIN" \
        -p "$proto" \
        -d "$upstream" \
        --dport 53 \
        -j RETURN
    done
    iptables -t nat -A "$CHAIN" \
      -p "$proto" \
      --dport 53 \
      -j DNAT --to-destination "$DNS_IP:$DNS_PORT"
  done
}

print_status() {
  echo "DNS listener expected at $DNS_IP:$DNS_PORT"
  echo "DNS upstream exclusion: $UPSTREAM_DNS"
  if [ -n "$OWNER_UID" ]; then
    echo "Owner UID scope: $OWNER_UID"
  else
    echo "Owner UID scope: all local processes"
  fi
  echo
  echo "iptables DNS capture rules:"
  iptables -t nat -S OUTPUT | grep -F -- "-j $CHAIN" || true
  if chain_exists; then
    iptables -t nat -S "$CHAIN" || true
  fi
}

case "$ACTION" in
  up)
    ensure_chain
    populate_chain
    add_output_rule udp
    add_output_rule tcp
    echo "local DNS capture enabled: *:53 -> $DNS_IP:$DNS_PORT, excluding $UPSTREAM_DNS"
    ;;
  down)
    delete_output_rule udp
    delete_output_rule tcp
    if chain_exists; then
      iptables -t nat -F "$CHAIN"
      iptables -t nat -X "$CHAIN"
    fi
    echo "local DNS capture disabled: *:53 -> $DNS_IP:$DNS_PORT"
    ;;
  status)
    print_status
    ;;
esac
