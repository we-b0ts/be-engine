#!/usr/bin/env bash

record_preflight_readiness() {
    [[ "$operation" == preflight ]] || return 0
    "$http_recording_enabled" || {
        printf 'error: initialization preflight requires HTTP readiness recording\n' >&2
        return 1
    }

    local status
    status=$(curl --silent --show-error \
        --noproxy '*' \
        --connect-timeout 10 --max-time 15 \
        --output /dev/null --write-out '%{http_code}' \
        "${TRAFFIC_E2E_RECORDING_ORIGIN}${TRAFFIC_E2E_SOURCE_READY_PATH}") || {
        printf 'error: initialization readiness request failed\n' >&2
        return 1
    }
    [[ "$status" == "$TRAFFIC_E2E_SOURCE_READY_STATUS" ]] || {
        printf 'error: initialization readiness request returned HTTP %s, expected %s\n' \
            "$status" "$TRAFFIC_E2E_SOURCE_READY_STATUS" >&2
        return 1
    }
    jq -cn \
        --arg origin "$TRAFFIC_E2E_RECORDING_ORIGIN" \
        --arg path "$TRAFFIC_E2E_SOURCE_READY_PATH" \
        --arg status "$status" \
        '{
            phase: "preflight-readiness-recorded",
            ready: true,
            request: {
                method: "GET",
                origin: $origin,
                path: $path,
                response_status: ($status | tonumber)
            }
        }'
}
