announce_preflight_business_input() {
    [[ "$operation" == preflight ]] || return 0
    if [[ "${TRAFFIC_E2E_PREFLIGHT_MOTAN_ENABLED-false}" == true ]]; then
        jq -cn \
            --arg recording_origin "$TRAFFIC_E2E_RECORDING_ORIGIN" \
            --arg source_port "$TRAFFIC_E2E_MOTAN_SOURCE_PORT" \
            --arg gateway_port "$TRAFFIC_E2E_MOTAN_GATEWAY_PORT" \
            --arg command "$TRAFFIC_E2E_MOTAN_REPLAY_COMMAND" \
            '{
                phase: "preflight-business-input-required",
                ready: true,
                recording_origin: $recording_origin,
                motan: {
                    validation: "optional_when_no_request_is_observed",
                    source_port: ($source_port | tonumber),
                    gateway_port: ($gateway_port | tonumber),
                    required_action: "Run motan-replay in the host or network namespace that observes source Motan traffic; replace 127.0.0.1 with this preflight host when capturing remotely.",
                    command: $command
                }
            }'
        return 0
    fi
    jq -cn \
        --arg recording_origin "$TRAFFIC_E2E_RECORDING_ORIGIN" \
        '{
            phase: "preflight-business-input-required",
            ready: true,
            recording_origin: $recording_origin
        }'
}
