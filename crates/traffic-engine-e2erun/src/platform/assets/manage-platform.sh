#!/usr/bin/env bash
set -Eeuo pipefail
exec 1>&2

operation=${1:?missing managed recording operation}
shift

required_environment=(
    TRAFFIC_E2E_BIN
    TRAFFIC_E2E_TARGET_ROOT
    TRAFFIC_E2E_SOURCE_RUNTIME
    TRAFFIC_E2E_TARGET_STARTUP_MOUNTS_FILE
    TRAFFIC_E2E_TARGET_RUNTIME_OUTPUTS_FILE
    TRAFFIC_E2E_HTTP_RECORDING_ENABLED
    TRAFFIC_E2E_RECORDING_ORIGIN
    TRAFFIC_E2E_SOURCE_READY_PATH
    TRAFFIC_E2E_SOURCE_READY_STATUS
    TRAFFIC_E2E_RECORDER_CONFIG
    TRAFFIC_E2E_SOURCE_TRAFFIC_POLICY
    TRAFFIC_E2E_PLATFORM_ASSETS
)
for name in "${required_environment[@]}"; do
    [[ -n "${!name-}" ]] || {
        printf 'error: missing managed runtime environment %s\n' "$name" >&2
        exit 1
    }
done
case "$TRAFFIC_E2E_HTTP_RECORDING_ENABLED" in
    true|false) ;;
    *)
        printf 'error: TRAFFIC_E2E_HTTP_RECORDING_ENABLED must be true or false\n' >&2
        exit 1
        ;;
esac
http_recording_enabled=$TRAFFIC_E2E_HTTP_RECORDING_ENABLED
source "$TRAFFIC_E2E_PLATFORM_ASSETS/preflight-readiness.sh"

case "$operation" in
    preflight) ;;
    *)
        printf 'error: unsupported managed recording operation %s\n' "$operation" >&2
        exit 1
        ;;
esac

encryption_key_b64=${TRAFFIC_E2E_ENCRYPTION_KEY_B64-}
unset TRAFFIC_E2E_ENCRYPTION_KEY_B64

run_id=""
duration_seconds=""

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
if [[ -z "$run_id" ]]; then
    run_id=$(date -u +%Y%m%d%H%M%S)
fi
[[ "$run_id" =~ ^[0-9]{14}$ ]] || {
    printf 'error: run ID must contain 14 digits\n' >&2
    exit 2
}

for command_name in docker jq curl timeout base64 id date find awk wc tr rm tar mktemp chown; do
    command -v "$command_name" >/dev/null 2>&1 || {
        printf 'error: required command not found: %s\n' "$command_name" >&2
        exit 1
    }
done
[[ -x "$TRAFFIC_E2E_BIN" ]] || {
    printf 'error: traffic-e2e binary is not executable\n' >&2
    exit 1
}

[[ -f "$TRAFFIC_E2E_RECORDER_CONFIG" ]] || {
    printf 'error: recorder config is missing\n' >&2
    exit 1
}
[[ -f "$TRAFFIC_E2E_SOURCE_TRAFFIC_POLICY" ]] || {
    printf 'error: source traffic policy is missing\n' >&2
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
[[ -f "$TRAFFIC_E2E_SOURCE_RUNTIME" && ! -L "$TRAFFIC_E2E_SOURCE_RUNTIME" ]] || {
    printf 'error: source runtime snapshot is missing or invalid\n' >&2
    exit 1
}
source_image_id=$(jq -er '.image_id' "$TRAFFIC_E2E_SOURCE_RUNTIME") || {
    printf 'error: source runtime snapshot has no image ID\n' >&2
    exit 1
}
[[ "$source_image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    printf 'error: source runtime snapshot has an invalid image ID\n' >&2
    exit 1
}
[[ "$(docker image inspect --format '{{.Id}}' "$source_image_id" 2>/dev/null || true)" == "$source_image_id" ]] || {
    printf 'error: snapshotted source image %s is unavailable locally\n' \
        "$source_image_id" >&2
    exit 1
}

anchor_image='registry.api.demo.test/weibo_rd_if/traffic-e2e-network-anchor:0.0.1@sha256:095f39e3b242e744ec8f7d85e732bb663af8a4a02bdef0d7a216d2e66e365a62'
recorder_image='registry.api.demo.test/weibo_rd_if/traffic-e2e-recorder-runtime:0.0.1-dev@sha256:c71fa374b229bc6fbf7ad34c5bb5cede1c27b2314a7b274b62ce2d44d3213107'
network_probe_image='registry.api.demo.test/weibo_rd_if/traffic-e2e-network-probe:0.0.1@sha256:6804ffe944eb4709c4f8387e984dfcf524be14241c571756a6b6b85a8cb13f8e'

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
source_name="${prefix}-source"
adapter_image="traffic-e2e/${recording_image_project}-recording:cache"
adapter_image_id=""
adapter_contract_revision=""
source_uses_java=false
adapter_dockerfile="$TRAFFIC_E2E_TARGET_ROOT/.traffic-e2e/Dockerfile.source"

effective_uid=$(id -u)
effective_gid=$(id -g)
runtime_uid=$effective_uid
runtime_gid=$effective_gid
if ((effective_uid == 0)) && [[ -n "${SUDO_UID-}" && -n "${SUDO_GID-}" ]]; then
    runtime_uid=$SUDO_UID
    runtime_gid=$SUDO_GID
fi
[[ "$runtime_uid" =~ ^[0-9]+$ && "$runtime_gid" =~ ^[0-9]+$ ]] || {
    printf 'error: invoking UID and GID must be numeric\n' >&2
    exit 1
}

runtime_root="$TRAFFIC_E2E_TARGET_ROOT/.traffic-e2e/local"
if [[ "$operation" == preflight ]]; then
    preflight_root="$runtime_root/preflight/$run_id"
    data_dir="$preflight_root/data"
    artifacts_dir="$preflight_root/artifacts"
else
    data_dir="$runtime_root/data"
    artifacts_dir="$runtime_root/artifacts"
fi
local_dir="$runtime_root/runtime/platform"
diagnostics_dir="$local_dir/diagnostics/${operation}-${token}"
control_dir="$local_dir/control/${token}"
platform_mounts_parent="$local_dir/mounts"
platform_mounts_root="$platform_mounts_parent/${operation}-${token}"
runtime_outputs_root="$TRAFFIC_E2E_TARGET_ROOT/.traffic-e2e/local/runtime-outputs/${operation}/${run_id}"
startup_snapshot_mounts_root="$TRAFFIC_E2E_TARGET_ROOT/.traffic-e2e/local/startup/mounts"
mkdir -p "$data_dir" "$artifacts_dir" "$diagnostics_dir" "$control_dir"
mkdir -p "$platform_mounts_parent"
chmod 0700 "$diagnostics_dir" "$control_dir"
if [[ "$operation" == preflight ]]; then
    chmod 0700 "$preflight_root" "$data_dir" "$artifacts_dir"
fi

anchor_started=false
recorder_started=false
source_started=false

recorder_finalized=false

source "$TRAFFIC_E2E_PLATFORM_ASSETS/platform-mounts.sh"
source "$TRAFFIC_E2E_PLATFORM_ASSETS/container-runtime.sh"

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

source "$TRAFFIC_E2E_PLATFORM_ASSETS/recorder-runtime.sh"

capture_diagnostics() {
    local name
    for name in "$recorder_name" "$source_name"; do
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

normalize_retained_ownership() {
    local recording_result_dir path mismatched
    recording_result_dir="$artifacts_dir/recordings/$run_id"
    local -a retained_paths=("$data_dir" "$recording_result_dir" "$diagnostics_dir")
    [[ "$operation" != preflight ]] || retained_paths+=("$preflight_root")
    for path in "${retained_paths[@]}"; do
        [[ -e "$path" ]] || continue
        mismatched=$(find "$path" \( ! -user "$runtime_uid" -o ! -group "$runtime_gid" \) \
            -print -quit 2>/dev/null || true)
        [[ -n "$mismatched" ]] || continue
        if ((effective_uid == 0)); then
            chown -hR "$runtime_uid:$runtime_gid" -- "$path"
        else
            docker run --rm --platform linux/amd64 --network none --user 0:0 \
                --entrypoint /bin/sh --volume "$path:/workspace/retained" \
                "$recorder_image" -ec \
                'chown -hR "$1:$2" -- /workspace/retained' \
                sh "$runtime_uid" "$runtime_gid"
        fi
    done
}

cleanup() {
    local status=$?
    trap - EXIT INT TERM

    if "$recorder_started" && ! "$recorder_finalized"; then
        finalize_recorder || status=1
    fi
    capture_diagnostics
    "$source_started" && stop_container "$source_name"
    "$recorder_started" && stop_container "$recorder_name"
    "$anchor_started" && stop_container "$anchor_name"
    normalize_retained_ownership || status=1

    remove_private_runtime_dir "$control_dir" "$local_dir/control" || status=1
    remove_platform_mounts || status=1
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

recording_adapter_contract_revision() {
    (
        cd "$TRAFFIC_E2E_TARGET_ROOT/.traffic-e2e"
        find . -mindepth 1 -maxdepth 1 -type f -print0 | sort -z | \
            while IFS= read -r -d '' path; do
                printf '%s\0' "$path"
                sha256sum -- "$path" | cut -c1-64
                printf '\0'
            done
    ) | sha256sum | cut -c1-64
}

build_recording_adapter() {
    local adapter_iid_file build_status source_image_alias
    [[ -f "$adapter_dockerfile" && ! -L "$adapter_dockerfile" ]] || {
        printf 'error: recording source adaptor Dockerfile is missing or not a regular file: %s\n' \
            "$adapter_dockerfile" >&2
        return 1
    }
    adapter_iid_file="$control_dir/adapter-image-id"
    source_image_alias="traffic-e2e/${recording_image_project}-recording-source:${source_image_id#sha256:}"
    rm -f "$adapter_iid_file"
    docker image tag "$source_image_id" "$source_image_alias"
    (
        cd "$TRAFFIC_E2E_TARGET_ROOT/.traffic-e2e"
        find . -mindepth 1 -maxdepth 1 -type f -print0 | \
            tar --create --file - --null --files-from -
    ) | docker build --platform linux/amd64 --network none \
        --iidfile "$adapter_iid_file" \
        --build-arg "SOURCE_IMAGE=${source_image_alias}" \
        --label com.weibo.traffic-e2e.managed=true \
        --label com.weibo.traffic-e2e.role=source-adapter \
        --label "com.weibo.traffic-e2e.source-image-id=${source_image_id}" \
        --label "com.weibo.traffic-e2e.adapter-contract-revision=${adapter_contract_revision}" \
        --tag "$adapter_image" --file Dockerfile.source - \
        && build_status=0 || build_status=$?
    docker image rm "$source_image_alias" >/dev/null 2>&1 || true
    ((build_status == 0)) || return "$build_status"
    adapter_image_id=$(<"$adapter_iid_file")
    [[ "$adapter_image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || {
        printf 'error: adapter build did not publish an image ID\n' >&2
        return 1
    }
}

load_initialized_recording_adapter() {
    local cached_contract_revision cached_source_image_id
    adapter_image_id=$(docker image inspect --format '{{.Id}}' "$adapter_image" 2>/dev/null || true)
    [[ "$adapter_image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
    cached_source_image_id=$(docker image inspect --format \
        '{{ index .Config.Labels "com.weibo.traffic-e2e.source-image-id" }}' \
        "$adapter_image" 2>/dev/null || true)
    cached_contract_revision=$(docker image inspect --format \
        '{{ index .Config.Labels "com.weibo.traffic-e2e.adapter-contract-revision" }}' \
        "$adapter_image" 2>/dev/null || true)
    [[ "$cached_source_image_id" == "$source_image_id" &&
        "$cached_contract_revision" == "$adapter_contract_revision" ]]
}

resolve_or_build_recording_adapter() {
    local status
    adapter_contract_revision=$(recording_adapter_contract_revision)
    [[ "$adapter_contract_revision" =~ ^[0-9a-f]{64}$ ]] || {
        printf 'error: recording source adaptor build contract has an invalid revision\n' >&2
        return 1
    }
    if load_initialized_recording_adapter; then
        printf 'reusing initialized recording source adaptor %s (%s)\n' \
            "$adapter_image" "$adapter_image_id" >&2
        return 0
    else
        status=$?
    fi
    ((status == 1)) || return "$status"
    printf 'recording source adaptor cache does not match the snapshotted source image or build contract; building it from %s\n' \
        "$source_image_id" >&2
    build_recording_adapter
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
    load_source_runtime_spec "$TRAFFIC_E2E_SOURCE_RUNTIME"
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
    docker run --detach --name "$source_name" --network "container:${anchor_name}" \
        "${runtime_args[@]}" "$adapter_image_id" "${runtime_command[@]}" >/dev/null
    source_started=true
    docker exec "$source_name" /bin/sh -ec '
        test "$(awk "/^Uid:/{print \$2}" /proc/1/status)" = 998
        test "$(awk "/^Gid:/{print \$2}" /proc/1/status)" = 998
    ' || {
        printf 'error: adapted source entrypoint must run as 998:998\n' >&2
        return 1
    }
}

run_preflight_https_probe() {
    [[ "$operation" == preflight ]] || return 0
    if "$source_uses_java"; then
        timeout --foreground 10 docker exec "$source_name" /bin/sh -ec '
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
            --header 'X-Traffic-E2E-Probe-Origin: source' \
            --output /dev/null --write-out 'system network HTTPS probe returned %{http_code}\n' \
            https://demo.test/ || {
                printf 'error: system network HTTPS probe failed\n' >&2
                return 1
            }
    fi
}

run_preflight() {
    local artifact_owner control_socket truststore
    artifact_owner="$runtime_uid:$runtime_gid"
    control_socket=/workspace/control/recorder.sock
    truststore="$data_dir/source-truststore.jks"
    [[ ! -e "$artifacts_dir/recordings/$run_id" ]] || {
        printf 'error: recording run already exists: %s\n' "$run_id" >&2
        return 1
    }
    resolve_or_build_recording_adapter
    detect_source_java_runtime
    docker pull "$anchor_image" >/dev/null
    docker pull "$recorder_image" >/dev/null
    if ! "$source_uses_java"; then
        docker pull "$network_probe_image" >/dev/null
    fi
    docker run --detach --name "$anchor_name" --platform linux/amd64 --network host \
        "$anchor_image" >/dev/null
    anchor_started=true
    local -a recorder_command=(internal recorder-run --config /workspace/project.yaml --control-socket "$control_socket" --artifact-owner "$artifact_owner" --dns --run-id "$run_id")
    if "$source_uses_java"; then
        recorder_command+=(--preflight-probe java-truststore)
    else
        recorder_command+=(--preflight-probe system-network)
    fi
    local selector
    for selector in "${api_selectors[@]}"; do recorder_command+=(--api "$selector"); done
    [[ -z "$per_api_case_limit" ]] || recorder_command+=(--per-api-case-limit "$per_api_case_limit")
    TRAFFIC_E2E_ENCRYPTION_KEY_B64=$encryption_key_b64 docker run --detach \
        --name "$recorder_name" --platform linux/amd64 --network "container:${anchor_name}" \
        --user 0:0 --cap-add NET_ADMIN --cap-add NET_RAW --workdir /workspace \
        --volume "$TRAFFIC_E2E_BIN:/usr/local/bin/traffic-e2e:ro" \
        "${recorder_config_mounts[@]}" \
        --volume "$data_dir:/workspace/.traffic-e2e/local/data" \
        --volume "$artifacts_dir:/workspace/.traffic-e2e/local/artifacts" \
        --volume "$control_dir:/workspace/control" \
        --env TRAFFIC_E2E_ENCRYPTION_KEY_B64 \
        --entrypoint /usr/local/bin/traffic-e2e \
        "$recorder_image" \
        "${recorder_command[@]}" >/dev/null
    recorder_started=true
    wait_for_recorder_listeners "$control_socket"
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
    fi
    start_recording_source "$truststore"
    docker exec "$recorder_name" /usr/local/bin/traffic-e2e recording wait-ready --control-socket "$control_socket"
    run_preflight_https_probe
    record_preflight_readiness

    wait_for_recorder_or_duration

    finalize_recorder

    local manifest_filter='.status == "completed" and .failed_cases == 0 and (.errors | length == 0) and .published_cases > 0'
    jq -e "$manifest_filter" "$artifacts_dir/recordings/$run_id/recording-run.json" >/dev/null
}

case "$operation" in

    preflight) run_preflight ;;
esac
