#!/usr/bin/env bash

start_comparison_target_network() {
    docker network create --driver bridge \
        --label com.weibo.traffic-e2e.managed=true \
        --label com.weibo.traffic-e2e.role=comparison-target-network \
        --label "com.weibo.traffic-e2e.operation=${operation}" \
        --label "com.weibo.traffic-e2e.run-id=${run_id}" \
        "$target_network_name" >/dev/null
    target_network_started=true
    docker run --detach --name "$target_anchor_name" --platform linux/amd64 \
        --network "$target_network_name" \
        --label com.weibo.traffic-e2e.managed=true \
        --label com.weibo.traffic-e2e.role=comparison-target-network-anchor \
        --label "com.weibo.traffic-e2e.operation=${operation}" \
        --label "com.weibo.traffic-e2e.run-id=${run_id}" \
        "$anchor_image" >/dev/null
    target_anchor_started=true
    target_network_ip=$(docker inspect --format \
        "{{with index .NetworkSettings.Networks \"${target_network_name}\"}}{{.IPAddress}}{{end}}" \
        "$target_anchor_name")
    [[ "$target_network_ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || {
        printf 'error: comparison target network did not allocate an IPv4 address\n' >&2
        return 1
    }
    target_network_gateway=$(docker network inspect --format \
        '{{(index .IPAM.Config 0).Gateway}}' "$target_network_name")
    [[ "$target_network_gateway" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || {
        printf 'error: comparison target network did not allocate an IPv4 gateway\n' >&2
        return 1
    }
    target_origin="http://${target_network_ip}:${TRAFFIC_E2E_TARGET_PORT}"
}

start_target() {
    local source target writable access
    local -a mounts=()
    while IFS=$'\t' read -r source target writable; do
        [[ -n "$source" && -n "$target" ]] || continue
        resolve_startup_mount_source target "$target" "$writable"
        if [[ "$writable" == true ]]; then access=""; else access=",readonly"; fi
        mounts+=(--mount "type=bind,source=${prepared_mount_source},target=${target}${access}")
    done <"$TRAFFIC_E2E_TARGET_STARTUP_MOUNTS_FILE"
    if "$breeze_enabled"; then
        mounts+=(
            --mount type=bind,source=/data1/breeze/socks,target=/data1/breeze/socks,readonly
            --mount type=bind,source=/data1/breeze/snapshot,target=/data1/breeze/snapshot,readonly
        )
    fi
    require_port_available "$target_network_ip" "$TRAFFIC_E2E_TARGET_PORT" target
    docker run --detach --name "$target_name" --platform linux/amd64 \
        --network "container:${target_anchor_name}" --user 998:998 \
        --label com.weibo.traffic-e2e.managed=true \
        --label com.weibo.traffic-e2e.role=target \
        --label "com.weibo.traffic-e2e.operation=${operation}" \
        --label "com.weibo.traffic-e2e.run-id=${run_id}" \
        --env-file "$TRAFFIC_E2E_TARGET_STARTUP_ENV_FILE" \
        "${mounts[@]}" "$TRAFFIC_E2E_TARGET_IMAGE_ID" >/dev/null
    target_started=true
}

stop_target() {
    local exit_code
    "$target_started" || return 0
    docker stop --time 15 "$target_name" >/dev/null
    exit_code=$(docker inspect -f '{{.State.ExitCode}}' "$target_name")
    docker rm "$target_name" >/dev/null
    target_started=false
    [[ "$exit_code" == 0 ]] || {
        printf 'error: target exited with status %s after SIGTERM\n' "$exit_code" >&2
        return 1
    }
}

remove_comparison_target_network() {
    "$target_anchor_started" && stop_container "$target_anchor_name"
    target_anchor_started=false
    if "$target_network_started"; then
        docker network rm "$target_network_name" >/dev/null
        target_network_started=false
    fi
}
