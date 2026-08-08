#!/usr/bin/env bash
set -Eeuo pipefail
exec 1>&2

operation=${1:?missing managed recording operation}
shift

required_environment=(
    TRAFFIC_E2E_BIN
    TRAFFIC_E2E_TARGET_ROOT
    TRAFFIC_E2E_SOURCE_CONTAINER
    TRAFFIC_E2E_TARGET_BOOT_DIR
    TRAFFIC_E2E_TARGET_ORIGIN
    TRAFFIC_E2E_TARGET_PORT
    TRAFFIC_E2E_TARGET_READY_PATH
    TRAFFIC_E2E_TARGET_READY_STATUS
    TRAFFIC_E2E_TARGET_STARTUP_TIMEOUT_SECONDS
    TRAFFIC_E2E_SOURCE_ORIGIN
    TRAFFIC_E2E_RECORDING_ORIGIN
    TRAFFIC_E2E_SOURCE_READY_PATH
    TRAFFIC_E2E_SOURCE_READY_STATUS
    TRAFFIC_E2E_RECORDER_CONFIG
    TRAFFIC_E2E_REPLAY_POLICY
    TRAFFIC_E2E_PLATFORM_ASSETS
)
for name in "${required_environment[@]}"; do
    [[ -n "${!name-}" ]] || {
        printf 'error: missing managed runtime environment %s\n' "$name" >&2
        exit 1
    }
done

case "$operation" in
    record|record-comparison|preflight) ;;
    *)
        printf 'error: unsupported managed recording operation %s\n' "$operation" >&2
        exit 1
        ;;
esac

encryption_key_b64=${TRAFFIC_E2E_ENCRYPTION_KEY_B64-}
unset TRAFFIC_E2E_ENCRYPTION_KEY_B64

run_id=""
duration_seconds=""
baseline_recheck=false
brz_no_fallback=""
per_api_case_limit=""
api_selectors=()
while (($# > 0)); do
    case "$1" in
        --run-id)
            [[ -z "$run_id" && $# -ge 2 ]] || exit 2
            run_id=$2
            shift 2
            ;;
        --duration-seconds)
            [[ -z "$duration_seconds" && $# -ge 2 ]] || exit 2
            duration_seconds=$2
            shift 2
            ;;
        --baseline-recheck)
            "$baseline_recheck" && exit 2
            baseline_recheck=true
            shift
            ;;
        --brz-no-fallback)
            [[ -z "$brz_no_fallback" && $# -ge 2 ]] || exit 2
            brz_no_fallback=$2
            shift 2
            ;;
        --api)
            (($# >= 2)) || exit 2
            api_selectors+=("$2")
            shift 2
            ;;
        --per-api-case-limit)
            [[ -z "$per_api_case_limit" && $# -ge 2 ]] || exit 2
            per_api_case_limit=$2
            shift 2
            ;;
        *)
            printf 'error: unsupported managed recording argument %s\n' "$1" >&2
            exit 2
            ;;
    esac
done

[[ "$duration_seconds" =~ ^[1-9][0-9]*$ ]] || {
    printf 'error: duration must be a positive integer\n' >&2
    exit 2
}
[[ "$brz_no_fallback" == true || "$brz_no_fallback" == false ]] || {
    printf 'error: brz-no-fallback must be true or false\n' >&2
    exit 2
}
if [[ -z "$run_id" ]]; then
    run_id=$(date -u +%Y%m%d%H%M%S)
fi
[[ "$run_id" =~ ^[0-9]{14}$ ]] || {
    printf 'error: run ID must contain 14 digits\n' >&2
    exit 2
}
if [[ "$operation" != record-comparison && "$baseline_recheck" == true ]]; then
    printf 'error: baseline recheck is comparison-only\n' >&2
    exit 2
fi

for command_name in docker jq curl nc timeout base64 id date find awk wc tr rm tar; do
    command -v "$command_name" >/dev/null 2>&1 || {
        printf 'error: required command not found: %s\n' "$command_name" >&2
        exit 1
    }
done
[[ -x "$TRAFFIC_E2E_BIN" ]] || {
    printf 'error: traffic-e2e binary is not executable\n' >&2
    exit 1
}
if [[ "$operation" == record-comparison ]]; then
    [[ "${TRAFFIC_E2E_TARGET_IMAGE_ID-}" =~ ^sha256:[0-9a-f]{64}$ ]] || {
        printf 'error: comparison requires an immutable target image ID\n' >&2
        exit 1
    }
fi
[[ -f "$TRAFFIC_E2E_RECORDER_CONFIG" ]] || {
    printf 'error: recorder config is missing\n' >&2
    exit 1
}
[[ -f "$TRAFFIC_E2E_REPLAY_POLICY" ]] || {
    printf 'error: replay policy is missing\n' >&2
    exit 1
}
valid_encryption_key() {
    local encoded=$1
    local decoded_length
    local canonical
    [[ "$encoded" =~ ^[A-Za-z0-9+/]{43}=$ ]] || return 1
    decoded_length=$(printf '%s' "$encoded" | base64 --decode 2>/dev/null | wc -c) || return 1
    ((decoded_length == 32)) || return 1
    canonical=$(printf '%s' "$encoded" | base64 --decode 2>/dev/null | base64 --wrap=0) || return 1
    [[ "$canonical" == "$encoded" ]]
}
valid_encryption_key "$encryption_key_b64" || {
    printf 'error: TRAFFIC_E2E_ENCRYPTION_KEY_B64 must be strict Base64 for exactly 32 bytes\n' >&2
    exit 1
}

docker info >/dev/null 2>&1 || {
    printf 'error: Docker daemon is unavailable\n' >&2
    exit 1
}
source_inspect=$(docker inspect "$TRAFFIC_E2E_SOURCE_CONTAINER")
[[ "$(jq 'length' <<<"$source_inspect")" == 1 ]] || exit 1
breeze_inspect=""
breeze_enabled=false
if [[ -n "${TRAFFIC_E2E_BREEZE_CONTAINER-}" ]]; then
    breeze_inspect=$(docker inspect "$TRAFFIC_E2E_BREEZE_CONTAINER")
    [[ "$(jq 'length' <<<"$breeze_inspect")" == 1 ]] || exit 1
    breeze_enabled=true
fi

anchor_image='registry.api.demo.test/weibo_rd_if/traffic-e2e-network-anchor:0.0.1@sha256:095f39e3b242e744ec8f7d85e732bb663af8a4a02bdef0d7a216d2e66e365a62'
recorder_image='registry.api.demo.test/weibo_rd_if/traffic-e2e-recorder-runtime:0.0.1-dev@sha256:c71fa374b229bc6fbf7ad34c5bb5cede1c27b2314a7b274b62ce2d44d3213107'
network_probe_image='registry.api.demo.test/weibo_rd_if/traffic-e2e-network-probe:0.0.1@sha256:6804ffe944eb4709c4f8387e984dfcf524be14241c571756a6b6b85a8cb13f8e'
breeze_image='registry.api.demo.test/weibo_rd_if/breeze:v0.1.21-e2e@sha256:5aba065755724d43c7da3f6b79ac82890a0a0a08c6ae3f43af12558b5e52462f'

repo_name=$(basename "$TRAFFIC_E2E_TARGET_ROOT" | tr -cs 'A-Za-z0-9_.-' '-')
repo_name=${repo_name#-}
repo_name=${repo_name%-}
[[ -n "$repo_name" ]] || {
    printf 'error: target repository name cannot form a Docker image name\n' >&2
    exit 1
}
recording_image_project=$(printf '%s' "$repo_name" | tr '[:upper:]' '[:lower:]')
token="${run_id}-$$"
prefix="traffic-e2e-${repo_name}-${operation}-${token}"
anchor_name="${prefix}-anchor"
recorder_name="${prefix}-recorder"
breeze_name="${prefix}-breeze"
source_name="${prefix}-source"
target_name="${prefix}-target"
adapter_image="traffic-e2e/${recording_image_project}-recording:cache"
adapter_image_id=""
source_uses_java=false
adapter_dockerfile="$TRAFFIC_E2E_TARGET_ROOT/.traffic-e2e/Dockerfile.recording"

runtime_root="$TRAFFIC_E2E_TARGET_ROOT/.traffic-e2e/local"
if [[ "$operation" == preflight ]]; then
    preflight_root="$runtime_root/preflight/$run_id"
    data_dir="$preflight_root/data"
    artifacts_dir="$preflight_root/artifacts"
else
    data_dir="$runtime_root/data"
    artifacts_dir="$runtime_root/artifacts"
fi
local_dir="$runtime_root/ai-forbidden/platform"
diagnostics_dir="$local_dir/diagnostics/${operation}-${token}"
control_dir="$local_dir/control/${token}"
mkdir -p "$data_dir" "$artifacts_dir" "$diagnostics_dir" "$control_dir"
chmod 0700 "$diagnostics_dir" "$control_dir"

anchor_started=false
recorder_started=false
breeze_started=false
source_started=false
target_started=false
recorder_finalized=false
comparison_pid=""
input_pid=""

container_exists() {
    docker container inspect "$1" >/dev/null 2>&1
}

stop_container() {
    local name=$1
    container_exists "$name" || return 0
    if [[ "$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null || true)" == true ]]; then
        docker stop --time 15 "$name" >/dev/null 2>&1 || true
    fi
    docker rm "$name" >/dev/null 2>&1 || true
}

start_target() {
    local -a mounts=(
        --mount "type=bind,source=${TRAFFIC_E2E_TARGET_BOOT_DIR},target=/traffic-e2e/config,readonly"
    )
    if "$breeze_enabled"; then
        mounts+=(
            --mount type=bind,source=/data1/breeze/socks,target=/data1/breeze/socks,readonly
            --mount type=bind,source=/data1/breeze/snapshot,target=/data1/breeze/snapshot,readonly
        )
    fi
    docker run --detach --name "$target_name" --platform linux/amd64 \
        --network "container:${anchor_name}" --user 998:998 \
        --label com.weibo.traffic-e2e.managed=true \
        --label com.weibo.traffic-e2e.role=target \
        --label "com.weibo.traffic-e2e.operation=${operation}" \
        --label "com.weibo.traffic-e2e.run-id=${run_id}" \
        --env TRAFFIC_E2E_CONFIG_DIR=/traffic-e2e/config \
        --env "TRAFFIC_E2E_TARGET_PORT=${TRAFFIC_E2E_TARGET_PORT}" \
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

capture_diagnostics() {
    local name
    for name in "$recorder_name" "$breeze_name" "$source_name" "$target_name"; do
        if container_exists "$name"; then
            docker logs "$name" >"$diagnostics_dir/${name}.log" 2>&1 || true
        fi
    done
}

remove_private_runtime_dir() {
    local path=$1
    local parent=$2
    [[ "$path" == "$parent/"* && "$path" != "$parent" ]] || {
        printf 'error: refusing to remove unexpected runtime path %s\n' "$path" >&2
        return 1
    }
    rm -rf -- "$path"
}

cleanup() {
    local status=$?
    trap - EXIT INT TERM
    if [[ -n "$comparison_pid" ]] && kill -0 "$comparison_pid" >/dev/null 2>&1; then
        kill -INT "$comparison_pid" >/dev/null 2>&1 || true
        wait "$comparison_pid" || true
    fi
    if [[ -n "$input_pid" ]] && kill -0 "$input_pid" >/dev/null 2>&1; then
        kill -TERM "$input_pid" >/dev/null 2>&1 || true
        wait "$input_pid" || status=1
        input_pid=""
    fi
    if [[ "$operation" == record-comparison ]]; then
        if "$target_started"; then
            stop_target || status=1
        fi
        if "$source_started"; then
            stop_container "$source_name"
            source_started=false
        fi
    fi
    if "$recorder_started" && ! "$recorder_finalized"; then
        finalize_recorder || status=1
    fi
    if "$target_started"; then
        stop_target || status=1
    fi
    capture_diagnostics
    "$source_started" && stop_container "$source_name"
    "$breeze_started" && stop_container "$breeze_name"
    "$recorder_started" && stop_container "$recorder_name"
    "$target_started" && stop_container "$target_name"
    "$anchor_started" && stop_container "$anchor_name"
    remove_private_runtime_dir "$control_dir" "$local_dir/control" || status=1
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

wait_port() {
    local port=$1
    local label=$2
    local owner=${3-}
    local deadline=$((SECONDS + 300))
    while ((SECONDS < deadline)); do
        if nc -z -w 1 127.0.0.1 "$port" >/dev/null 2>&1; then
            return 0
        fi
        if [[ -n "$owner" ]] && container_exists "$owner" &&
            [[ "$(docker inspect -f '{{.State.Running}}' "$owner")" != true ]]; then
            printf 'error: %s exited before port %s became ready\n' "$label" "$port" >&2
            return 1
        fi
        sleep 1
    done
    printf 'error: timed out waiting for %s on port %s\n' "$label" "$port" >&2
    return 1
}

wait_http() {
    local origin=$1
    local path=$2
    local expected=$3
    local label=$4
    local owner=${5-}
    local timeout_seconds=${6:-300}
    local deadline=$((SECONDS + timeout_seconds))
    local status
    while ((SECONDS < deadline)); do
        status=$(curl -sS -o /dev/null -w '%{http_code}' "${origin}${path}" 2>/dev/null || true)
        [[ "$status" == "$expected" ]] && return 0
        if [[ -n "$owner" ]] && container_exists "$owner" &&
            [[ "$(docker inspect -f '{{.State.Running}}' "$owner")" != true ]]; then
            printf 'error: %s exited before HTTP readiness\n' "$label" >&2
            return 1
        fi
        sleep 1
    done
    printf 'error: timed out waiting for %s HTTP readiness\n' "$label" >&2
    return 1
}

load_runtime_spec() {
    local inspect_json=$1
    local mount_mode=$2
    local environment_mode=$3
    local launch_mode=$4
    [[ "$launch_mode" == exact || "$launch_mode" == image ]] || {
        printf 'error: unsupported container launch mode %s\n' "$launch_mode" >&2
        return 1
    }
    runtime_args=(--platform linux/amd64)
    runtime_command=()
    if [[ "$launch_mode" == exact ]]; then
        local workdir configured_user
        workdir=$(jq -r '.[0].Config.WorkingDir // empty' <<<"$inspect_json")
        [[ -z "$workdir" ]] || runtime_args+=(--workdir "$workdir")
        configured_user=$(jq -r '.[0].Config.User // empty' <<<"$inspect_json")
        [[ -z "$configured_user" ]] || runtime_args+=(--user "$configured_user")
        [[ "$(jq -r '.[0].HostConfig.Privileged // false' <<<"$inspect_json")" != true ]] || runtime_args+=(--privileged)
    fi
    [[ "$(jq -r '.[0].HostConfig.ReadonlyRootfs // false' <<<"$inspect_json")" != true ]] || runtime_args+=(--read-only)
    [[ "$(jq -r '.[0].HostConfig.Init // false' <<<"$inspect_json")" != true ]] || runtime_args+=(--init)

    local -a entries=()
    mapfile -d '' -t entries < <(jq -j '.[0].Config.Env[]? | ., "\u0000"' <<<"$inspect_json")
    local entry name
    for entry in "${entries[@]}"; do
        name=${entry%%=*}
        [[ "$name" == HOSTNAME ]] && continue
        if [[ "$environment_mode" == recording ]] &&
            [[ "$name" == RUN_COMMAND || "$name" == MESH_CONNECT_HOST || "$name" == JAVA_TOOL_OPTIONS ]]; then
            continue
        fi
        runtime_args+=(--env "$entry")
    done

    entries=()
    mapfile -d '' -t entries < <(jq -j '.[0].HostConfig.Ulimits[]? | (.Name + "=" + (.Soft|tostring) + ":" + (.Hard|tostring)), "\u0000"' <<<"$inspect_json")
    for entry in "${entries[@]}"; do runtime_args+=(--ulimit "$entry"); done
    entries=()
    mapfile -d '' -t entries < <(jq -j '.[0].HostConfig.CapAdd[]? | ., "\u0000"' <<<"$inspect_json")
    for entry in "${entries[@]}"; do runtime_args+=(--cap-add "$entry"); done
    entries=()
    mapfile -d '' -t entries < <(jq -j '.[0].HostConfig.CapDrop[]? | ., "\u0000"' <<<"$inspect_json")
    for entry in "${entries[@]}"; do runtime_args+=(--cap-drop "$entry"); done
    entries=()
    mapfile -d '' -t entries < <(jq -j '.[0].HostConfig.GroupAdd[]? | ., "\u0000"' <<<"$inspect_json")
    for entry in "${entries[@]}"; do runtime_args+=(--group-add "$entry"); done
    entries=()
    mapfile -d '' -t entries < <(jq -j '.[0].HostConfig.SecurityOpt[]? | ., "\u0000"' <<<"$inspect_json")
    for entry in "${entries[@]}"; do runtime_args+=(--security-opt "$entry"); done
    entries=()
    mapfile -d '' -t entries < <(jq -j '.[0].Config.Labels // {} | to_entries[] | (.key + "=" + .value), "\u0000"' <<<"$inspect_json")
    for entry in "${entries[@]}"; do runtime_args+=(--label "$entry"); done
    entries=()
    mapfile -d '' -t entries < <(jq -j '.[0].HostConfig.Sysctls // {} | to_entries[] | (.key + "=" + .value), "\u0000"' <<<"$inspect_json")
    for entry in "${entries[@]}"; do runtime_args+=(--sysctl "$entry"); done

    local source destination writable volume translated first remainder
    while IFS=$'\t' read -r source destination writable volume; do
        [[ -n "$destination" ]] || continue
        if [[ -n "$volume" && "$volume" != null ]]; then source=$volume; fi
        if [[ "$mount_mode" == recording && "$source" == /data1/* && "$source" != /data1/breeze/* ]]; then
            remainder=${source#/data1/}
            first=${remainder%%/*}
            translated="/data1/${first}-recording"
            [[ "$remainder" == "$first" ]] || translated+="/${remainder#*/}"
            source=$translated
            docker run --rm --platform linux/amd64 --network none \
                --entrypoint /bin/sh --volume /data1:/host-data1 \
                "$(jq -r '.[0].Config.Image' <<<"$source_inspect")" \
                -ec 'mkdir -p "$1"; chown -hR 998:998 -- "$1"; chmod -R u+rwX -- "$1"' \
                sh "/host-data1/${source#/data1/}"
        fi
        if [[ "$writable" == true ]]; then
            runtime_args+=(--volume "${source}:${destination}:rw")
        else
            runtime_args+=(--volume "${source}:${destination}:ro")
        fi
    done < <(jq -r '.[0].Mounts[]? | [.Source, .Destination, .RW, (.Name // "")] | @tsv' <<<"$inspect_json")

    if [[ "$launch_mode" == exact ]]; then
        entries=()
        mapfile -d '' -t entries < <(jq -j '.[0].Config.Entrypoint[]? | ., "\u0000"' <<<"$inspect_json")
        if ((${#entries[@]} > 0)); then
            runtime_args+=(--entrypoint "${entries[0]}")
            ((${#entries[@]} == 1)) || runtime_command+=("${entries[@]:1}")
        fi
        entries=()
        mapfile -d '' -t entries < <(jq -j '.[0].Config.Cmd[]? | ., "\u0000"' <<<"$inspect_json")
        runtime_command+=("${entries[@]}")
    fi
}

normalize_breeze_directories() {
    local helper_image
    helper_image=$(jq -r '.[0].Config.Image' <<<"$source_inspect")
    docker run --rm --platform linux/amd64 --network none --entrypoint /bin/sh \
        --volume /data1:/host-data1 "$helper_image" -ec '
            mkdir -p /host-data1/breeze/socks /host-data1/breeze/snapshot /host-data1/breeze/logs
            chown -hR 998:998 -- /host-data1/breeze/socks /host-data1/breeze/snapshot /host-data1/breeze/logs
            chmod -R u+rwX -- /host-data1/breeze/socks /host-data1/breeze/snapshot /host-data1/breeze/logs
            chmod 2775 /host-data1/breeze/socks
            chmod 0775 /host-data1/breeze/snapshot /host-data1/breeze/logs
        '
}

start_breeze() {
    local network=$1
    load_runtime_spec "$breeze_inspect" exact exact exact
    docker run --detach --name "$breeze_name" --network "$network" \
        "${runtime_args[@]}" "$breeze_image" "${runtime_command[@]}" >/dev/null
    breeze_started=true
    wait_port 9984 Breeze "$breeze_name"
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
        --volume "$TRAFFIC_E2E_RECORDER_CONFIG:/workspace/recorder.toml:ro" \
        --volume "$control_dir:/workspace/control" \
        --env TRAFFIC_E2E_ENCRYPTION_KEY_B64 \
        --entrypoint /usr/local/bin/traffic-e2e \
        "$recorder_image" \
        internal cache-snapshot-run \
        --config /workspace/recorder.toml \
        --output-dir /workspace/control/cache-snapshot \
        --run-id "$run_id" \
        --control-socket "$control_socket" >/dev/null
    recorder_started=true
    docker exec "$recorder_name" /usr/local/bin/traffic-e2e \
        recording wait-listeners --control-socket "$control_socket"
}

start_comparison_source() {
    local network=$1
    load_runtime_spec "$source_inspect" recording recording image
    if "$breeze_enabled"; then
        runtime_args+=(--env MESH_CONNECT_HOST=breeze.recording)
    fi
    docker run --detach --name "$source_name" --network "$network" \
        "${runtime_args[@]}" "$adapter_image_id" >/dev/null
    source_started=true
    wait_http "$TRAFFIC_E2E_SOURCE_ORIGIN" "$TRAFFIC_E2E_SOURCE_READY_PATH" \
        "$TRAFFIC_E2E_SOURCE_READY_STATUS" source "$source_name"
    docker exec "$source_name" /bin/sh -ec '
        test "$(awk "/^Uid:/{print \$2}" /proc/1/status)" = 998
        test "$(awk "/^Gid:/{print \$2}" /proc/1/status)" = 998
    ' || {
        printf 'error: adapted comparison source entrypoint must run as 998:998\n' >&2
        return 1
    }
}

build_recording_adapter() {
    local source_image source_image_id resolved_source_image_id
    local adapter_iid_file
    source_image=$(jq -r '.[0].Config.Image' <<<"$source_inspect")
    source_image_id=$(jq -r '.[0].Image' <<<"$source_inspect")
    [[ "$source_image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || {
        printf 'error: source container has an invalid image ID\n' >&2
        return 1
    }
    resolved_source_image_id=$(docker image inspect --format '{{.Id}}' "$source_image")
    [[ "$resolved_source_image_id" == "$source_image_id" ]] || {
        printf 'error: source image reference no longer resolves to the inspected container image\n' >&2
        return 1
    }
    [[ -f "$adapter_dockerfile" && ! -L "$adapter_dockerfile" ]] || {
        printf 'error: recording source adaptor Dockerfile is missing or not a regular file: %s\n' \
            "$adapter_dockerfile" >&2
        return 1
    }
    adapter_iid_file="$control_dir/adapter-image-id"
    rm -f "$adapter_iid_file"
    (
        cd "$TRAFFIC_E2E_TARGET_ROOT/.traffic-e2e"
        find . -mindepth 1 -maxdepth 1 -type f -print0 | \
            tar --create --file - --null --files-from -
    ) | docker build --platform linux/amd64 --network none \
        --iidfile "$adapter_iid_file" \
        --build-arg "SOURCE_IMAGE=${source_image_id}" \
        --tag "$adapter_image" --file Dockerfile.recording -
    adapter_image_id=$(<"$adapter_iid_file")
    [[ "$adapter_image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || {
        printf 'error: adapter build did not publish an image ID\n' >&2
        return 1
    }
}

resolve_or_build_recording_adapter() {
    adapter_image_id=$(docker image inspect --format '{{.Id}}' "$adapter_image" 2>/dev/null || true)
    if [[ "$adapter_image_id" =~ ^sha256:[0-9a-f]{64}$ ]]; then
        printf 'reusing initialized recording source image %s (%s)\n' \
            "$adapter_image" "$adapter_image_id" >&2
        return 0
    fi
    printf 'initialized recording source image %s is missing; building it once\n' \
        "$adapter_image" >&2
    build_recording_adapter
}

require_initialized_recording_adapter() {
    adapter_image_id=$(docker image inspect --format '{{.Id}}' "$adapter_image" 2>/dev/null || true)
    [[ "$adapter_image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || {
        printf 'error: initialization must build recording source image %s before preflight\n' \
            "$adapter_image" >&2
        return 1
    }
    printf 'using initialized recording source image %s (%s) for preflight\n' \
        "$adapter_image" "$adapter_image_id" >&2
}

detect_source_java_runtime() {
    source_uses_java=false
    if docker run --rm --platform linux/amd64 --network none --user 998:998 \
        --cap-drop ALL --cap-add NET_BIND_SERVICE \
        --entrypoint java "$adapter_image_id" -version >/dev/null 2>&1; then
        source_uses_java=true
        printf 'detected runnable Java environment in recording source image; using Java 8 truststore probe\n' >&2
    else
        printf 'recording source image has no runnable Java environment; using system network probe\n' >&2
    fi
}

start_recording_source() {
    local truststore=$1
    load_runtime_spec "$source_inspect" recording recording image
    if "$source_uses_java"; then
        runtime_args+=(
            --env 'JAVA_TOOL_OPTIONS=-Djavax.net.ssl.trustStore=/traffic-e2e/source-truststore.jks -Djavax.net.ssl.trustStorePassword=changeit'
            --volume "$data_dir/traffic-recorder-ca.pem:/traffic-e2e/traffic-recorder-ca.pem:ro"
            --volume "$truststore:/traffic-e2e/source-truststore.jks:ro"
        )
        if [[ "$operation" == preflight ]]; then
            runtime_args+=(
                --volume "$TRAFFIC_E2E_PLATFORM_ASSETS/HttpsProbe.class:/traffic-e2e/HttpsProbe.class:ro"
            )
        fi
    fi
    if "$breeze_enabled"; then
        runtime_args+=(--env MESH_CONNECT_HOST=breeze.recording)
    fi
    docker run --detach --name "$source_name" --network "container:${anchor_name}" \
        "${runtime_args[@]}" "$adapter_image_id" >/dev/null
    source_started=true
    wait_port 880 source "$source_name"
    docker exec "$source_name" /bin/sh -ec '
        test "$(awk "/^Uid:/{print \$2}" /proc/1/status)" = 998
        test "$(awk "/^Gid:/{print \$2}" /proc/1/status)" = 998
    ' || {
        printf 'error: adapted source entrypoint must run as 998:998\n' >&2
        return 1
    }
}

run_no_fallback() {
    "$breeze_enabled" || return 0
    "$brz_no_fallback" || return 0
    env -u TRAFFIC_E2E_ENCRYPTION_KEY_B64 -u BASH_ENV \
        "$TRAFFIC_E2E_PLATFORM_ASSETS/brz-no-fallback.sh"
}

run_preflight_https_probe() {
    [[ "$operation" == preflight ]] || return 0
    if "$source_uses_java"; then
        docker exec "$source_name" /bin/sh -ec '
            command -v java >/dev/null
            java -Djava.net.preferIPv4Stack=true -cp /traffic-e2e \
                HttpsProbe https://demo.test/
        ' || {
            printf 'error: Java truststore HTTPS probe failed\n' >&2
            return 1
        }
    else
        docker run --rm --platform linux/amd64 \
            --network "container:${anchor_name}" --user 998:998 \
            --cap-drop ALL --security-opt no-new-privileges \
            --mount "type=bind,source=${data_dir}/traffic-recorder-ca.pem,target=/traffic-e2e/trust/recorder-ca.pem,readonly" \
            "$network_probe_image" \
            --silent --show-error --connect-timeout 10 --max-time 15 \
            --cacert /traffic-e2e/trust/recorder-ca.pem \
            --user-agent traffic-e2e-system-network-preflight \
            --output /dev/null --write-out 'system network HTTPS probe returned %{http_code}\n' \
            https://demo.test/ || {
                printf 'error: system network HTTPS probe failed\n' >&2
                return 1
            }
    fi
}

announce_preflight_business_input() {
    [[ "$operation" == preflight ]] || return 0
    jq -cn \
        --arg recording_origin "$TRAFFIC_E2E_RECORDING_ORIGIN" \
        '{
            phase: "preflight-business-input-required",
            ready: true,
            recording_origin: $recording_origin
        }'
}

start_recording_input() {
    [[ -n "${TRAFFIC_E2E_REQUEST_SOURCE-}" ]] || return 0
    [[ -d "$TRAFFIC_E2E_REQUEST_SOURCE" ]] || {
        printf 'error: managed recording request source is missing\n' >&2
        return 1
    }
    TRAFFIC_E2E_ENCRYPTION_KEY_B64=$encryption_key_b64 \
        "$TRAFFIC_E2E_BIN" internal recording-input \
        --case-source "$TRAFFIC_E2E_REQUEST_SOURCE" \
        --origin "$TRAFFIC_E2E_RECORDING_ORIGIN" &
    input_pid=$!
}

stop_recording_input() {
    local status=0
    [[ -n "$input_pid" ]] || return 0
    if kill -0 "$input_pid" >/dev/null 2>&1; then
        kill -TERM "$input_pid" >/dev/null 2>&1 || true
    fi
    wait "$input_pid" || status=$?
    input_pid=""
    ((status == 0))
}

run_standard_recording() {
    local artifact_owner control_socket truststore
    artifact_owner="$(id -u):$(id -g)"
    control_socket=/workspace/control/recorder.sock
    truststore="$data_dir/source-truststore.jks"
    [[ ! -e "$artifacts_dir/recordings/$run_id" ]] || {
        printf 'error: recording run already exists: %s\n' "$run_id" >&2
        return 1
    }
    if [[ "$operation" == preflight ]]; then
        require_initialized_recording_adapter
    else
        resolve_or_build_recording_adapter
    fi
    detect_source_java_runtime
    if "$breeze_enabled"; then
        normalize_breeze_directories
        docker pull "$breeze_image" >/dev/null
    fi
    docker pull "$anchor_image" >/dev/null
    docker pull "$recorder_image" >/dev/null
    if [[ "$operation" == preflight ]] && ! "$source_uses_java"; then
        docker pull "$network_probe_image" >/dev/null
    fi
    docker run --detach --name "$anchor_name" --platform linux/amd64 --network host \
        "$anchor_image" >/dev/null
    anchor_started=true
    local -a recorder_command=(internal recorder-run --config /workspace/recorder.toml --control-socket "$control_socket" --artifact-owner "$artifact_owner" --dns --run-id "$run_id")
    if [[ "$operation" == preflight ]]; then
        if "$source_uses_java"; then
            recorder_command+=(--preflight-probe java-truststore)
        else
            recorder_command+=(--preflight-probe system-network)
        fi
    fi
    local -a recorder_mounts=()
    if "$breeze_enabled"; then
        recorder_mounts+=(
            --volume /data1/breeze/socks:/data1/breeze/socks:ro
            --volume /data1/breeze/snapshot:/data1/breeze/snapshot:ro
        )
    fi
    local selector
    for selector in "${api_selectors[@]}"; do recorder_command+=(--api "$selector"); done
    [[ -z "$per_api_case_limit" ]] || recorder_command+=(--per-api-case-limit "$per_api_case_limit")
    TRAFFIC_E2E_ENCRYPTION_KEY_B64=$encryption_key_b64 docker run --detach \
        --name "$recorder_name" --platform linux/amd64 --network "container:${anchor_name}" \
        --user 0:0 --cap-add NET_ADMIN --cap-add NET_RAW --workdir /workspace \
        --volume "$TRAFFIC_E2E_BIN:/usr/local/bin/traffic-e2e:ro" \
        --volume "$TRAFFIC_E2E_RECORDER_CONFIG:/workspace/recorder.toml:ro" \
        --volume "$data_dir:/workspace/.traffic-e2e/local/data" \
        --volume "$artifacts_dir:/workspace/.traffic-e2e/local/artifacts" \
        --volume "$control_dir:/workspace/control" \
        "${recorder_mounts[@]}" \
        --env TRAFFIC_E2E_ENCRYPTION_KEY_B64 \
        --entrypoint /usr/local/bin/traffic-e2e \
        "$recorder_image" \
        "${recorder_command[@]}" >/dev/null
    recorder_started=true
    docker exec "$recorder_name" /usr/local/bin/traffic-e2e recording wait-listeners --control-socket "$control_socket"
    if "$source_uses_java"; then
        docker run --rm --platform linux/amd64 --network none --user 0:0 --entrypoint /bin/sh \
            --volume "$data_dir:/workspace/data" "$adapter_image_id" -ec '
                test -s /workspace/data/traffic-recorder-ca.pem
                rm -f /workspace/data/source-truststore.jks
                keytool -importcert -noprompt -alias traffic-recorder-ca \
                    -file /workspace/data/traffic-recorder-ca.pem \
                    -keystore /workspace/data/source-truststore.jks -storetype JKS \
                    -storepass changeit >/dev/null
                chmod 0644 /workspace/data/traffic-recorder-ca.pem /workspace/data/source-truststore.jks
            '
    else
        chmod 0644 "$data_dir/traffic-recorder-ca.pem"
    fi
    if "$breeze_enabled"; then
        start_breeze "container:${anchor_name}"
    fi
    start_recording_source "$truststore"
    run_no_fallback
    docker exec "$recorder_name" /usr/local/bin/traffic-e2e recording wait-ready --control-socket "$control_socket"
    run_preflight_https_probe
    announce_preflight_business_input
    start_recording_input
    wait_for_recorder_or_duration
    stop_recording_input
    finalize_recorder
    local manifest_filter='.status == "completed" and .failed_cases == 0 and (.errors | length == 0)'
    if [[ "$operation" == preflight ]]; then
        manifest_filter+=' and .published_cases > 0'
    fi
    jq -e "$manifest_filter" "$artifacts_dir/recordings/$run_id/recording-run.json" >/dev/null
}

run_comparison_recording() {
    [[ ! -e "$artifacts_dir/comparison-recordings/$run_id" ]] || {
        printf 'error: comparison run already exists: %s\n' "$run_id" >&2
        return 1
    }
    resolve_or_build_recording_adapter
    docker pull "$anchor_image" >/dev/null
    docker run --detach --name "$anchor_name" --platform linux/amd64 --network host \
        --label com.weibo.traffic-e2e.managed=true \
        --label com.weibo.traffic-e2e.role=target-network-anchor \
        --label "com.weibo.traffic-e2e.operation=${operation}" \
        --label "com.weibo.traffic-e2e.run-id=${run_id}" \
        "$anchor_image" >/dev/null
    anchor_started=true
    start_cache_snapshot
    if "$breeze_enabled"; then
        normalize_breeze_directories
        docker pull "$breeze_image" >/dev/null
        start_breeze "container:${anchor_name}"
    fi
    start_comparison_source "container:${anchor_name}"
    run_no_fallback
    start_target
    wait_http "$TRAFFIC_E2E_TARGET_ORIGIN" "$TRAFFIC_E2E_TARGET_READY_PATH" \
        "$TRAFFIC_E2E_TARGET_READY_STATUS" target "$target_name" \
        "$TRAFFIC_E2E_TARGET_STARTUP_TIMEOUT_SECONDS"
    local -a comparison_command=(internal comparison-run --config "$TRAFFIC_E2E_RECORDER_CONFIG" --policy "$TRAFFIC_E2E_REPLAY_POLICY" --run-id "$run_id" --duration-seconds "$duration_seconds")
    "$baseline_recheck" && comparison_command+=(--baseline-recheck)
    local selector
    for selector in "${api_selectors[@]}"; do comparison_command+=(--api "$selector"); done
    [[ -z "$per_api_case_limit" ]] || comparison_command+=(--per-api-case-limit "$per_api_case_limit")
    (
        cd "$TRAFFIC_E2E_TARGET_ROOT"
        export TRAFFIC_E2E_ENCRYPTION_KEY_B64="$encryption_key_b64"
        exec "$TRAFFIC_E2E_BIN" "${comparison_command[@]}"
    ) &
    comparison_pid=$!
    start_recording_input
    local status=0
    wait "$comparison_pid" || status=$?
    comparison_pid=""
    stop_recording_input || status=1
    ((status == 0)) || return "$status"
    stop_target
    stop_container "$source_name"
    source_started=false
    finalize_recorder
    jq -e '.status == "completed"' \
        "$artifacts_dir/comparison-recordings/$run_id/comparison-recording-run.json" >/dev/null
}

case "$operation" in
    record) run_standard_recording ;;
    record-comparison) run_comparison_recording ;;
    preflight) run_standard_recording ;;
esac
