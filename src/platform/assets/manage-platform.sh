#!/usr/bin/env bash
set -Eeuo pipefail
exec 1>&2

operation=${1:?missing managed recording operation}
shift

required_environment=(
    TRAFFIC_E2E_BIN
    TRAFFIC_E2E_TARGET_ROOT
    TRAFFIC_E2E_SOURCE_CONTAINER
    TRAFFIC_E2E_PROJECT_CLI
    TRAFFIC_E2E_TARGET_BOOT_DIR
    TRAFFIC_E2E_TARGET_ORIGIN
    TRAFFIC_E2E_TARGET_PORT
    TRAFFIC_E2E_TARGET_READY_PATH
    TRAFFIC_E2E_TARGET_READY_STATUS
    TRAFFIC_E2E_TARGET_STARTUP_TIMEOUT_SECONDS
    TRAFFIC_E2E_SOURCE_ORIGIN
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
    record|record-comparison) ;;
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
case_limit=""
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
        --case-limit)
            [[ -z "$case_limit" && $# -ge 2 ]] || exit 2
            case_limit=$2
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
if [[ "$operation" == record && "$baseline_recheck" == true ]]; then
    printf 'error: baseline recheck is comparison-only\n' >&2
    exit 2
fi

for command_name in docker jq curl nc timeout base64 readlink id date find sort sed grep awk wc tr rm; do
    command -v "$command_name" >/dev/null 2>&1 || {
        printf 'error: required command not found: %s\n' "$command_name" >&2
        exit 1
    }
done
[[ -x "$TRAFFIC_E2E_BIN" ]] || {
    printf 'error: traffic-e2e binary is not executable\n' >&2
    exit 1
}
[[ -x "$TRAFFIC_E2E_PROJECT_CLI" ]] || {
    printf 'error: project CLI is not executable\n' >&2
    exit 1
}
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
breeze_image='registry.api.demo.test/weibo_rd_if/breeze:v0.1.21-e2e@sha256:5aba065755724d43c7da3f6b79ac82890a0a0a08c6ae3f43af12558b5e52462f'

repo_name=$(basename "$TRAFFIC_E2E_TARGET_ROOT" | tr -cs 'A-Za-z0-9_.-' '-')
token="${run_id}-$$"
prefix="traffic-e2e-${repo_name}-${operation}-${token}"
anchor_name="${prefix}-anchor"
recorder_name="${prefix}-recorder"
breeze_name="${prefix}-breeze"
source_name="${prefix}-source"
adapter_image="traffic-e2e/${repo_name}-recording-source:${token}"

runtime_root="$TRAFFIC_E2E_TARGET_ROOT/.traffic-e2e"
data_dir="$runtime_root/data"
artifacts_dir="$runtime_root/artifacts"
local_dir="$runtime_root/local/platform"
diagnostics_dir="$local_dir/diagnostics/${operation}-${token}"
control_dir="$local_dir/control/${token}"
adapter_context="$local_dir/adapters/${token}"
mkdir -p "$data_dir" "$artifacts_dir" "$diagnostics_dir" "$control_dir" "$adapter_context"
chmod 0700 "$diagnostics_dir" "$control_dir" "$adapter_context"

anchor_started=false
recorder_started=false
breeze_started=false
source_started=false
target_started=false
recorder_finalized=false
comparison_pid=""

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

run_target() {
    env -u TRAFFIC_E2E_ENCRYPTION_KEY_B64 -u BASH_ENV \
        -u TRAFFIC_E2E_BIN -u TRAFFIC_E2E_TARGET_ROOT \
        -u TRAFFIC_E2E_SOURCE_CONTAINER -u TRAFFIC_E2E_BREEZE_CONTAINER \
        -u TRAFFIC_E2E_PROJECT_CLI -u TRAFFIC_E2E_TARGET_BOOT_DIR \
        -u TRAFFIC_E2E_TARGET_ORIGIN -u TRAFFIC_E2E_TARGET_PORT \
        -u TRAFFIC_E2E_TARGET_READY_PATH -u TRAFFIC_E2E_TARGET_READY_STATUS \
        -u TRAFFIC_E2E_TARGET_STARTUP_TIMEOUT_SECONDS \
        -u TRAFFIC_E2E_SOURCE_ORIGIN -u TRAFFIC_E2E_SOURCE_READY_PATH \
        -u TRAFFIC_E2E_SOURCE_READY_STATUS -u TRAFFIC_E2E_RECORDER_CONFIG \
        -u TRAFFIC_E2E_REPLAY_POLICY -u TRAFFIC_E2E_PLATFORM_ASSETS \
        "$TRAFFIC_E2E_PROJECT_CLI" "$@"
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

capture_diagnostics() {
    local name
    for name in "$recorder_name" "$breeze_name" "$source_name"; do
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
    if "$recorder_started" && ! "$recorder_finalized"; then
        finalize_recorder || status=1
    fi
    if "$target_started"; then
        run_target stop || status=1
    fi
    capture_diagnostics
    "$source_started" && stop_container "$source_name"
    "$breeze_started" && stop_container "$breeze_name"
    "$recorder_started" && stop_container "$recorder_name"
    "$anchor_started" && stop_container "$anchor_name"
    docker image rm "$adapter_image" >/dev/null 2>&1 || true
    remove_private_runtime_dir "$control_dir" "$local_dir/control" || status=1
    remove_private_runtime_dir "$adapter_context" "$local_dir/adapters" || status=1
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
    runtime_args=(--platform linux/amd64)
    runtime_command=()
    local workdir
    workdir=$(jq -r '.[0].Config.WorkingDir // empty' <<<"$inspect_json")
    [[ -z "$workdir" ]] || runtime_args+=(--workdir "$workdir")
    local configured_user
    configured_user=$(jq -r '.[0].Config.User // empty' <<<"$inspect_json")
    [[ -z "$configured_user" ]] || runtime_args+=(--user "$configured_user")
    [[ "$(jq -r '.[0].HostConfig.Privileged // false' <<<"$inspect_json")" != true ]] || runtime_args+=(--privileged)
    [[ "$(jq -r '.[0].HostConfig.ReadonlyRootfs // false' <<<"$inspect_json")" != true ]] || runtime_args+=(--read-only)
    [[ "$(jq -r '.[0].HostConfig.Init // false' <<<"$inspect_json")" != true ]] || runtime_args+=(--init)

    local -a entries=()
    mapfile -d '' -t entries < <(jq -j '.[0].Config.Env[]? | ., "\u0000"' <<<"$inspect_json")
    local entry name
    for entry in "${entries[@]}"; do
        name=${entry%%=*}
        [[ "$name" == HOSTNAME ]] && continue
        if [[ "$environment_mode" == recording ]] &&
            [[ "$name" == RUN_COMMAND || "$name" == MESH_CONNECT_HOST || "$name" == JAVA_TOOL_OPTIONS || "$name" == TRAFFIC_E2E_SOURCE_RUN_COMMAND || "$name" == TRAFFIC_E2E_SOURCE_WORKDIR ]]; then
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

    entries=()
    mapfile -d '' -t entries < <(jq -j '.[0].Config.Entrypoint[]? | ., "\u0000"' <<<"$inspect_json")
    if ((${#entries[@]} > 0)); then
        runtime_args+=(--entrypoint "${entries[0]}")
        ((${#entries[@]} == 1)) || runtime_command+=("${entries[@]:1}")
    fi
    entries=()
    mapfile -d '' -t entries < <(jq -j '.[0].Config.Cmd[]? | ., "\u0000"' <<<"$inspect_json")
    runtime_command+=("${entries[@]}")
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
    load_runtime_spec "$breeze_inspect" exact exact
    docker run --detach --name "$breeze_name" --network "$network" \
        "${runtime_args[@]}" "$breeze_image" "${runtime_command[@]}" >/dev/null
    breeze_started=true
    wait_port 9984 Breeze "$breeze_name"
}

start_genuine_source() {
    local network=$1
    load_runtime_spec "$source_inspect" exact exact
    local image
    image=$(jq -r '.[0].Config.Image' <<<"$source_inspect")
    docker run --detach --name "$source_name" --network "$network" \
        "${runtime_args[@]}" "$image" "${runtime_command[@]}" >/dev/null
    source_started=true
    wait_http "$TRAFFIC_E2E_SOURCE_ORIGIN" "$TRAFFIC_E2E_SOURCE_READY_PATH" \
        "$TRAFFIC_E2E_SOURCE_READY_STATUS" source "$source_name"
}

build_recording_adapter() {
    local source_image source_launcher_path source_run_command source_workdir
    source_image=$(jq -r '.[0].Config.Image' <<<"$source_inspect")
    source_run_command=$(jq -r '.[0].Config.Env[]? | select(startswith("RUN_COMMAND=")) | sub("^RUN_COMMAND="; "")' <<<"$source_inspect" | tail -n 1)
    source_workdir=$(jq -r '.[0].Config.WorkingDir // "/"' <<<"$source_inspect")
    [[ -n "$source_run_command" ]] || {
        printf 'error: Breeze source adapter requires the source container to expose its final application command through RUN_COMMAND\n' >&2
        return 1
    }
    case "$source_run_command" in
        /* | ./* | ../*) ;;
        *) source_run_command="./${source_run_command}" ;;
    esac
    [[ "$source_workdir" == /* && "$source_workdir" != *[[:space:]\\\"]* ]] || {
        printf 'error: Breeze source adapter requires an absolute source working directory without whitespace, quotes, or backslashes\n' >&2
        return 1
    }
    source_launcher_path="${source_workdir%/}/traffic-e2e-source-root-launcher"
    cp "$TRAFFIC_E2E_PLATFORM_ASSETS/MeshConnectUtil.java" "$adapter_context/MeshConnectUtil.java"
    cp "$TRAFFIC_E2E_PLATFORM_ASSETS/apply-breeze-sdk-patch" "$adapter_context/apply-breeze-sdk-patch"
    chmod 0700 "$adapter_context/apply-breeze-sdk-patch"
    printf '%s' "$source_run_command" >"$adapter_context/source-run-command"
    printf '%s' "$source_workdir" >"$adapter_context/source-workdir"
    cat >"$adapter_context/source-java-launcher" <<'LAUNCHER'
#!/bin/sh
set -eu
cd "${TRAFFIC_E2E_SOURCE_WORKDIR:?}"
exec /bin/sh -c "${TRAFFIC_E2E_SOURCE_RUN_COMMAND:?}"
LAUNCHER
    cat >"$adapter_context/source-root-launcher" <<'LAUNCHER'
#!/bin/sh
set -eu
exec /usr/sbin/chroot --userspec=998:998 --groups=0 / /usr/local/bin/traffic-e2e-source-java-launcher
LAUNCHER
    chmod 0700 "$adapter_context/source-java-launcher" "$adapter_context/source-root-launcher"
    cat >"$adapter_context/Dockerfile" <<DOCKERFILE
FROM ${source_image}
COPY MeshConnectUtil.java /usr/local/share/traffic-e2e/MeshConnectUtil.java
COPY apply-breeze-sdk-patch /usr/local/bin/apply-breeze-sdk-patch
RUN chmod 0755 /usr/local/bin/apply-breeze-sdk-patch \\
    && /usr/local/bin/apply-breeze-sdk-patch \\
    && chown -R 998:998 /data1/weibo
COPY source-java-launcher /usr/local/bin/traffic-e2e-source-java-launcher
COPY source-root-launcher ${source_launcher_path}
RUN chmod 0755 /usr/local/bin/traffic-e2e-source-java-launcher ${source_launcher_path} \\
    && java_bin="\$(readlink -f "\$(command -v java)")" \\
    && java_jli_path="\$(ldd "\${java_bin}" | awk '\$1 == "libjli.so" { print \$3 }')" \\
    && java_jli_dir="\$(dirname "\$(readlink -f "\${java_jli_path}")")" \\
    && printf '%s\\n' "\${java_jli_dir}" >/etc/ld.so.conf.d/traffic-e2e-java.conf \\
    && ldconfig \\
    && setcap cap_net_bind_service=+ep "\${java_bin}" \\
    && getcap "\${java_bin}" | grep -F 'cap_net_bind_service+ep'
DOCKERFILE
    docker build --platform linux/amd64 --network none --tag "$adapter_image" "$adapter_context"
}

start_recording_source() {
    local truststore=$1
    load_runtime_spec "$source_inspect" recording recording
    local source_run_command source_workdir
    source_run_command=$(<"$adapter_context/source-run-command")
    source_workdir=$(<"$adapter_context/source-workdir")
    runtime_args+=(
        --user 0:0
        --env RUN_COMMAND=traffic-e2e-source-root-launcher
        --env MESH_CONNECT_HOST=breeze.recording
        --env "TRAFFIC_E2E_SOURCE_RUN_COMMAND=${source_run_command}"
        --env "TRAFFIC_E2E_SOURCE_WORKDIR=${source_workdir}"
        --env 'JAVA_TOOL_OPTIONS=-Djavax.net.ssl.trustStore=/traffic-e2e/source-truststore.jks -Djavax.net.ssl.trustStorePassword=changeit'
        --volume "$data_dir/traffic-recorder-ca.pem:/traffic-e2e/traffic-recorder-ca.pem:ro"
        --volume "$truststore:/traffic-e2e/source-truststore.jks:ro"
    )
    docker run --detach --name "$source_name" --network "container:${anchor_name}" \
        "${runtime_args[@]}" "$adapter_image" "${runtime_command[@]}" >/dev/null
    source_started=true
    wait_port 880 source "$source_name"
    docker exec "$source_name" /bin/sh -ec '
        pid=
        for process_dir in /proc/[0-9]*; do
            name=$(awk "/^Name:/{print \$2}" "$process_dir/status" 2>/dev/null || true)
            if [ "$name" = java ]; then
                pid=${process_dir#/proc/}
                break
            fi
        done
        test -n "$pid"
        test "$(awk "/^Uid:/{print \$2}" "/proc/$pid/status")" = 998
        test "$(awk "/^Gid:/{print \$2}" "/proc/$pid/status")" = 998
    '
}

run_no_fallback() {
    "$breeze_enabled" || return 0
    "$brz_no_fallback" || return 0
    env -u TRAFFIC_E2E_ENCRYPTION_KEY_B64 -u BASH_ENV \
        "$TRAFFIC_E2E_PLATFORM_ASSETS/brz-no-fallback.sh"
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
    if "$breeze_enabled"; then
        build_recording_adapter
        normalize_breeze_directories
        docker pull "$breeze_image" >/dev/null
    fi
    docker pull "$anchor_image" >/dev/null
    docker pull "$recorder_image" >/dev/null
    docker run --detach --name "$anchor_name" --platform linux/amd64 --network host \
        "$anchor_image" >/dev/null
    anchor_started=true
    local -a recorder_command=(internal recorder-run --config /workspace/recorder.toml --control-socket "$control_socket" --artifact-owner "$artifact_owner" --dns --run-id "$run_id")
    local -a recorder_mounts=()
    if "$breeze_enabled"; then
        recorder_mounts+=(
            --volume /data1/breeze/socks:/data1/breeze/socks:ro
            --volume /data1/breeze/snapshot:/data1/breeze/snapshot:ro
        )
    fi
    local selector
    for selector in "${api_selectors[@]}"; do recorder_command+=(--api "$selector"); done
    [[ -z "$case_limit" ]] || recorder_command+=(--case-limit "$case_limit")
    TRAFFIC_E2E_ENCRYPTION_KEY_B64=$encryption_key_b64 docker run --detach \
        --name "$recorder_name" --platform linux/amd64 --network "container:${anchor_name}" \
        --user 0:0 --cap-add NET_ADMIN --cap-add NET_RAW --workdir /workspace \
        --volume "$TRAFFIC_E2E_BIN:/usr/local/bin/traffic-e2e:ro" \
        --volume "$TRAFFIC_E2E_RECORDER_CONFIG:/workspace/recorder.toml:ro" \
        --volume "$data_dir:/workspace/data" \
        --volume "$artifacts_dir:/workspace/.traffic-e2e/artifacts" \
        --volume "$control_dir:/workspace/control" \
        "${recorder_mounts[@]}" \
        --env TRAFFIC_E2E_ENCRYPTION_KEY_B64 \
        --entrypoint /usr/local/bin/traffic-e2e \
        "$recorder_image" \
        "${recorder_command[@]}" >/dev/null
    recorder_started=true
    docker exec "$recorder_name" /usr/local/bin/traffic-e2e recording wait-listeners --control-socket "$control_socket"
    if "$breeze_enabled"; then
        docker run --rm --platform linux/amd64 --network none --entrypoint /bin/sh \
            --volume "$data_dir:/workspace/data" "$adapter_image" -ec '
                test -s /workspace/data/traffic-recorder-ca.pem
                rm -f /workspace/data/source-truststore.jks
                keytool -importcert -noprompt -alias traffic-recorder-ca \
                    -file /workspace/data/traffic-recorder-ca.pem \
                    -keystore /workspace/data/source-truststore.jks -storepass changeit >/dev/null
                chmod 0644 /workspace/data/traffic-recorder-ca.pem /workspace/data/source-truststore.jks
            '
        start_breeze "container:${anchor_name}"
        start_recording_source "$truststore"
    else
        start_genuine_source "container:${anchor_name}"
    fi
    run_no_fallback
    docker exec "$recorder_name" /usr/local/bin/traffic-e2e recording wait-ready --control-socket "$control_socket"
    sleep "$duration_seconds"
    finalize_recorder
    jq -e '.status == "completed" and .failed_cases == 0 and (.errors | length == 0)' \
        "$artifacts_dir/recordings/$run_id/recording-run.json" >/dev/null
}

run_comparison_recording() {
    [[ ! -e "$artifacts_dir/comparison-recordings/$run_id" ]] || {
        printf 'error: comparison run already exists: %s\n' "$run_id" >&2
        return 1
    }
    if "$breeze_enabled"; then
        normalize_breeze_directories
        docker pull "$breeze_image" >/dev/null
        start_breeze host
    fi
    start_genuine_source host
    run_no_fallback
    run_target stop
    run_target start --e2e --start-breeze off --boot-dir "$TRAFFIC_E2E_TARGET_BOOT_DIR" --port "$TRAFFIC_E2E_TARGET_PORT"
    target_started=true
    wait_http "$TRAFFIC_E2E_TARGET_ORIGIN" "$TRAFFIC_E2E_TARGET_READY_PATH" \
        "$TRAFFIC_E2E_TARGET_READY_STATUS" target "" \
        "$TRAFFIC_E2E_TARGET_STARTUP_TIMEOUT_SECONDS"
    local -a comparison_command=(internal comparison-run --config "$TRAFFIC_E2E_RECORDER_CONFIG" --policy "$TRAFFIC_E2E_REPLAY_POLICY" --run-id "$run_id" --duration-seconds "$duration_seconds")
    "$baseline_recheck" && comparison_command+=(--baseline-recheck)
    local selector
    for selector in "${api_selectors[@]}"; do comparison_command+=(--api "$selector"); done
    [[ -z "$case_limit" ]] || comparison_command+=(--case-limit "$case_limit")
    (
        cd "$TRAFFIC_E2E_TARGET_ROOT"
        export TRAFFIC_E2E_ENCRYPTION_KEY_B64="$encryption_key_b64"
        exec "$TRAFFIC_E2E_BIN" "${comparison_command[@]}"
    ) &
    comparison_pid=$!
    local status=0
    wait "$comparison_pid" || status=$?
    comparison_pid=""
    ((status == 0)) || return "$status"
    run_target stop
    target_started=false
    jq -e '.status == "completed"' \
        "$artifacts_dir/comparison-recordings/$run_id/comparison-recording-run.json" >/dev/null
}

case "$operation" in
    record) run_standard_recording ;;
    record-comparison) run_comparison_recording ;;
esac
