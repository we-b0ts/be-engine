#!/usr/bin/env bash

recorder_config_mounts=(
    --volume "$TRAFFIC_E2E_RECORDER_CONFIG:/workspace/project.yaml:ro"
    --volume "$TRAFFIC_E2E_SOURCE_TRAFFIC_POLICY:/workspace/source-traffic-policy.yaml:ro"
)

report_recorder_startup_failure() {
    printf 'error: Recorder exited before its listeners became ready\n' >&2
    docker logs "$recorder_name" >&2 || true
}

wait_for_recorder_listeners() {
    local control_socket=$1
    docker exec "$recorder_name" /usr/local/bin/traffic-e2e \
        recording wait-listeners --control-socket "$control_socket" || {
        report_recorder_startup_failure
        return 1
    }
}

finalize_recorder() {
    local exit_code
    "$recorder_started" || return 0
    "$recorder_finalized" && return 0
    if [[ "$(docker inspect -f '{{.State.Running}}' "$recorder_name" 2>/dev/null || true)" == true ]]; then
        docker kill --signal=INT "$recorder_name" >/dev/null
        exit_code=$(timeout 90 docker wait "$recorder_name") || return 1
    else
        exit_code=$(docker inspect -f '{{.State.ExitCode}}' "$recorder_name")
    fi
    [[ "$exit_code" == 0 ]] || return 1
    recorder_finalized=true
}

wait_for_recorder_or_duration() {
    local exit_code status
    if exit_code=$(timeout --foreground "$duration_seconds" docker wait "$recorder_name"); then
        [[ "$exit_code" == 0 ]] || {
            printf 'error: Recorder exited before the duration with status %s\n' "$exit_code" >&2
            return 1
        }
        recorder_finalized=true
        return 0
    fi
    status=$?
    [[ "$status" == 124 ]] || return "$status"
}
