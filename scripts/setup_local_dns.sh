#!/usr/bin/env bash
set -euo pipefail

SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
source "$SCRIPT_DIR/intercept-user.sh"

ACTION="${1:-up}"
DNS_IP="${DNS_IP:-127.0.0.153}"
DNS_PORT="${DNS_PORT:-15353}"
UPSTREAM_DNS="${UPSTREAM_DNS:-10.10.10.10:53}"
CHAIN="${CHAIN:-TRP_DNS}"
INTERCEPT_UID=""

usage() {
  cat >&2 <<EOF
Usage:
  sudo DNS_IP=$DNS_IP DNS_PORT=$DNS_PORT UPSTREAM_DNS=$UPSTREAM_DNS $0 up
  sudo DNS_IP=$DNS_IP DNS_PORT=$DNS_PORT UPSTREAM_DNS=$UPSTREAM_DNS $0 down

This captures local UDP/TCP DNS traffic on port 53 and sends it to
DNS_IP:DNS_PORT. UPSTREAM_DNS is excluded so the recorder can forward DNS
queries upstream without recursively hitting itself. For multiple upstreams,
use a comma-separated list. IPv4 values may include an optional :53 suffix.
Capture is always limited to the fixed Unix user $TRAFFIC_INTERCEPT_USER.
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
  printf '%s\n' -m owner --uid-owner "$INTERCEPT_UID"
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

delete_output_rules() {
  local rule_number
  while true; do
    rule_number="$(
      iptables -t nat -L OUTPUT --line-numbers -n \
        | awk -v chain="$CHAIN" '$2 == chain { print $1; exit }'
    )"
    if [ -z "$rule_number" ]; then
      break
    fi
    iptables -t nat -D OUTPUT "$rule_number"
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
  echo "Owner scope: $TRAFFIC_INTERCEPT_USER (uid $INTERCEPT_UID)"
  echo
  echo "iptables DNS capture rules:"
  iptables -t nat -S OUTPUT | grep -F -- "-j $CHAIN" || true
  if chain_exists; then
    iptables -t nat -S "$CHAIN" || true
  fi
}

case "$ACTION" in
  up)
    INTERCEPT_UID="$(traffic_intercept_uid)"
    delete_output_rules
    ensure_chain
    populate_chain
    add_output_rule udp
    add_output_rule tcp
    echo "local DNS capture enabled: *:53 -> $DNS_IP:$DNS_PORT, excluding $UPSTREAM_DNS"
    ;;
  down)
    delete_output_rules
    if chain_exists; then
      iptables -t nat -F "$CHAIN"
      iptables -t nat -X "$CHAIN"
    fi
    echo "local DNS capture disabled: *:53 -> $DNS_IP:$DNS_PORT"
    ;;
  status)
    INTERCEPT_UID="$(traffic_intercept_uid)"
    print_status
    ;;
esac
