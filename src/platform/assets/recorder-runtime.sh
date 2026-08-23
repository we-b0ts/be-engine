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

normalize_cache_snapshot_ownership() {
    [[ "$operation" == record-comparison && "$recorder_started" == true ]] || return 0
    [[ -d "$control_dir/cache-snapshot" ]] || return 0
    docker run --rm --platform linux/amd64 --network none --user 0:0 \
        --entrypoint /bin/sh --volume "$control_dir:/workspace/control" \
        "$recorder_image" -ec \
        'chown -hR "$1:$2" -- /workspace/control/cache-snapshot' \
        sh "$runtime_uid" "$runtime_gid"
}

start_cache_snapshot() {
    local control_socket=/workspace/control/cache-snapshot.sock
    docker pull "$recorder_image" >/dev/null
    TRAFFIC_E2E_ENCRYPTION_KEY_B64=$encryption_key_b64 docker run --detach \
        --name "$recorder_name" --platform linux/amd64 --network "container:${anchor_name}" \
        --user 0:0 --cap-add NET_ADMIN --cap-add NET_RAW --workdir /workspace \
        --label com.weibo.traffic-e2e.managed=true \
        --label com.weibo.traffic-e2e.role=cache-snapshot \
        --label "com.weibo.traffic-e2e.operation=${operation}" \
        --label "com.weibo.traffic-e2e.run-id=${run_id}" \
        --volume "$TRAFFIC_E2E_BIN:/usr/local/bin/traffic-e2e:ro" \
        "${recorder_config_mounts[@]}" \
        --volume "$control_dir:/workspace/control" \
        --env TRAFFIC_E2E_ENCRYPTION_KEY_B64 \
        --entrypoint /usr/local/bin/traffic-e2e \
        "$recorder_image" \
        internal cache-snapshot-run \
        --config /workspace/project.yaml \
        --output-dir /workspace/control/cache-snapshot \
        --run-id "$run_id" \
        --candidate-upstream "$target_origin" \
        --target-source-ip "$target_network_ip" \
        --interception-listen-ip "$target_network_gateway" \
        --control-socket "$control_socket" >/dev/null
    recorder_started=true
    wait_for_recorder_listeners "$control_socket"
}
