#!/usr/bin/env bash

readonly TRAFFIC_INTERCEPT_USER="trp-record"

traffic_intercept_uid() {
  local uid
  if ! uid="$(id -u "$TRAFFIC_INTERCEPT_USER" 2>/dev/null)"; then
    cat >&2 <<EOF
traffic interception user not found: $TRAFFIC_INTERCEPT_USER
Create it with:
  sudo useradd --system --create-home --shell /bin/bash $TRAFFIC_INTERCEPT_USER
EOF
    return 1
  fi
  printf '%s\n' "$uid"
}
