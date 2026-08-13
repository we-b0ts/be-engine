#!/bin/sh
set -eu

mesh_switch_enabled=${TRAFFIC_E2E_BREEZE_NO_FALLBACK:-true}
unset TRAFFIC_E2E_BREEZE_NO_FALLBACK

case "$mesh_switch_enabled" in
    true)
        /usr/local/bin/mesh_switch_task.sh &
        ;;
    false)
        ;;
    *)
        printf 'error: TRAFFIC_E2E_BREEZE_NO_FALLBACK must be true or false\n' >&2
        exit 2
        ;;
esac

exec "$@"
