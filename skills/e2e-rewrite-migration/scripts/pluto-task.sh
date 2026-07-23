#!/usr/bin/env bash

set -Eeuo pipefail

API_URL="${API_URL:-http://127.0.0.1:9090}"
API_URL="${API_URL%/}"
START_VERIFY_SECONDS="${START_VERIFY_SECONDS:-10}"

PLUTO_RS_DIR="${PLUTO_RS_DIR:-$PWD}"
KUBE_NAMESPACE="${KUBE_NAMESPACE:-}"
KUBE_POD="${KUBE_POD:-}"
KUBE_CONTAINER="${KUBE_CONTAINER:-}"
DOWNLOAD_TMP=""
SYNC_NAMESPACE=""
SYNC_POD=""
SYNC_CONTAINER=""
SYNC_REMOTE_DIR=""

usage() {
  cat <<'EOF'
Usage:
  pluto-task.sh record [--redeploy-interval-seconds SECONDS] [-- PLUTO_ARG ...]
  pluto-task.sh compare [--redeploy-interval-seconds SECONDS] [-- PLUTO_ARG ...]
  pluto-task.sh stop [TASK_ID]
  pluto-task.sh tasks [LIMIT]
  pluto-task.sh recordings [LIMIT] [BEFORE_ID]
  pluto-task.sh download RECORDING_ID [OUTPUT_FILE]

Commands:
  record      Start a Pluto recording, optionally redeploying it at a fixed interval.
  compare     Start a Pluto/pluto-rs online comparison with the same option.
  stop        Stop TASK_ID, or the currently active Pluto task if omitted.
  tasks       Show recent Pluto tasks (default: 20).
  recordings  Show recent recording/comparison artifacts (default: 20).
  download    Download a terminal artifact as a tar.gz archive.

Environment overrides:
  API_URL               Admin API base URL (default: http://127.0.0.1:9090)
  START_VERIFY_SECONDS  Seconds to observe a new task (default: 10)
  PLUTO_RS_DIR           pluto-rs source directory (default: current working directory)
  KUBE_NAMESPACE         Target Pod namespace; use with KUBE_POD
  KUBE_POD               Target Pod name; use with KUBE_NAMESPACE
  KUBE_CONTAINER         Target container (auto-detected from port 9090)

Examples:
  API_URL=http://POD_IP:9090 ./scripts/pluto-task.sh record
  API_URL=http://POD_IP:9090 ./scripts/pluto-task.sh compare
  API_URL=http://POD_IP:9090 ./scripts/pluto-task.sh stop
  API_URL=http://POD_IP:9090 ./scripts/pluto-task.sh recordings 50
  API_URL=http://POD_IP:9090 ./scripts/pluto-task.sh download 20260721153045
EOF
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  [[ -z "$DOWNLOAD_TMP" ]] || rm -f -- "$DOWNLOAD_TMP"
  if [[ -n "$SYNC_REMOTE_DIR" && -n "$SYNC_NAMESPACE" && -n "$SYNC_POD" ]]; then
    target_exec -- rm -rf -- "$SYNC_REMOTE_DIR" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command is unavailable: $1"
}

validate_limit() {
  [[ "$1" =~ ^[0-9]+$ ]] && ((1 <= 10#$1 && 10#$1 <= 200)) ||
    die "limit must be an integer between 1 and 200: $1"
}

validate_redeploy_interval() {
  [[ "$1" =~ ^[0-9]+$ ]] &&
    ((1 <= 10#$1 && 10#$1 <= 31536000)) ||
    die "redeploy interval must be an integer between 1 and 31536000 seconds: $1"
}

validate_id() {
  [[ "$1" =~ ^[0-9]{14}$ ]] ||
    die "ID must contain exactly 14 digits: $1"
}

api() {
  local method=$1
  local path=$2
  shift 2
  curl --silent --show-error --fail-with-body \
    --connect-timeout 5 --max-time 30 \
    --request "$method" "${API_URL}${path}" "$@"
}

check_api() {
  api GET /healthz >/dev/null ||
    die "admin API is unavailable: ${API_URL}"
}

api_host() {
  local authority="${API_URL#*://}"
  authority="${authority%%/*}"
  if [[ "$authority" == \[*\]* ]]; then
    die "automatic Pod discovery does not support IPv6 API_URL; set KUBE_NAMESPACE and KUBE_POD"
  fi
  printf '%s\n' "${authority%%:*}"
}

select_container_for_pod() {
  local pod_json=$1
  local -a containers
  mapfile -t containers < <(
    jq --raw-output '
      .spec.containers[]
      | select(any(.ports[]?; .containerPort == 9090))
      | .name
    ' <<<"$pod_json"
  )
  ((${#containers[@]} == 1)) ||
    die "expected exactly one container exposing port 9090 in ${SYNC_NAMESPACE}/${SYNC_POD}; set KUBE_CONTAINER"
  SYNC_CONTAINER="${containers[0]}"
}

resolve_sync_target() {
  local pod_json host
  if [[ -n "$KUBE_NAMESPACE" || -n "$KUBE_POD" ]]; then
    [[ -n "$KUBE_NAMESPACE" && -n "$KUBE_POD" ]] ||
      die "KUBE_NAMESPACE and KUBE_POD must be set together"
    SYNC_NAMESPACE="$KUBE_NAMESPACE"
    SYNC_POD="$KUBE_POD"
    SYNC_CONTAINER="$KUBE_CONTAINER"
    if [[ -z "$SYNC_CONTAINER" ]]; then
      pod_json="$(kubectl --namespace "$SYNC_NAMESPACE" get pod "$SYNC_POD" --output json)"
      select_container_for_pod "$pod_json"
    fi
    return
  fi

  host="$(api_host)"
  [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
    die "automatic Pod discovery requires API_URL to use a Pod IPv4 address; set KUBE_NAMESPACE and KUBE_POD"

  local -a targets
  mapfile -t targets < <(
    kubectl get pods --all-namespaces \
      --field-selector "status.podIP=${host}" --output json |
      jq --raw-output '
        .items[]
        | select(.status.phase == "Running" and .metadata.deletionTimestamp == null)
        | . as $pod
        | $pod.spec.containers[]
        | select(any(.ports[]?; .containerPort == 9090))
        | [$pod.metadata.namespace, $pod.metadata.name, .name]
        | @tsv
      '
  )
  ((${#targets[@]} == 1)) ||
    die "expected exactly one Running Pod container exposing port 9090 at ${host}; set KUBE_NAMESPACE, KUBE_POD, and optionally KUBE_CONTAINER"
  IFS=$'\t' read -r SYNC_NAMESPACE SYNC_POD SYNC_CONTAINER <<<"${targets[0]}"
}

target_exec() {
  kubectl --namespace "$SYNC_NAMESPACE" exec "$SYNC_POD" \
    --container "$SYNC_CONTAINER" "$@"
}

local_sha256() {
  local digest _
  read -r digest _ < <(sha256sum "$1")
  printf '%s\n' "$digest"
}

remote_sha256() {
  local output
  if output="$(target_exec -- sha256sum "$1" 2>/dev/null)"; then
    printf '%s\n' "${output%% *}"
  fi
}

prepare_pluto_rs() {
  require_command cargo
  require_command gzip
  require_command kubectl
  require_command sha256sum

  local source_dir="$PLUTO_RS_DIR"
  local binary="${source_dir}/target/debug/pluto-rs"
  local config="${source_dir}/config/default.yaml"
  local config_env="${source_dir}/config/.env"
  [[ -f "${source_dir}/Cargo.toml" ]] ||
    die "pluto-rs Cargo.toml is unavailable: ${source_dir}/Cargo.toml"
  [[ -f "$config" ]] || die "pluto-rs configuration is unavailable: $config"
  [[ -f "$config_env" ]] ||
    die "pluto-rs environment configuration is unavailable: $config_env"

  printf 'Building pluto-rs (debug) from %s\n' "$source_dir" >&2
  (cd "$source_dir" && cargo build --bin pluto-rs)
  [[ -x "$binary" ]] || die "built pluto-rs executable is unavailable: $binary"

  resolve_sync_target
  printf 'Preparing pluto-rs in %s/%s (container %s)\n' \
    "$SYNC_NAMESPACE" "$SYNC_POD" "$SYNC_CONTAINER" >&2

  local remote_binary="/opt/pluto-rs/bin/pluto-rs"
  local remote_config="/opt/pluto-rs/config/default.yaml"
  local remote_config_env="/opt/pluto-rs/config/.env"
  local binary_hash config_hash config_env_hash
  local current_binary_hash current_config_hash current_config_env_hash
  binary_hash="$(local_sha256 "$binary")"
  config_hash="$(local_sha256 "$config")"
  config_env_hash="$(local_sha256 "$config_env")"
  current_binary_hash="$(remote_sha256 "$remote_binary")"
  current_config_hash="$(remote_sha256 "$remote_config")"
  current_config_env_hash="$(remote_sha256 "$remote_config_env")"

  SYNC_REMOTE_DIR="/tmp/pluto-task-sync-$$"
  target_exec -- install -d -m 0700 "$SYNC_REMOTE_DIR"

  local install_binary=0
  local install_config=0
  local install_config_env=0
  if [[ "$binary_hash" != "$current_binary_hash" ]]; then
    printf 'Uploading pluto-rs executable\n' >&2
    gzip --stdout "$binary" |
      target_exec --stdin -- sh -c \
        'umask 077; gzip -dc > "$1"' sh "${SYNC_REMOTE_DIR}/pluto-rs"
    install_binary=1
  fi
  if [[ "$config_hash" != "$current_config_hash" ]]; then
    printf 'Uploading pluto-rs configuration\n' >&2
    target_exec --stdin -- sh -c \
      'umask 077; cat > "$1"' sh "${SYNC_REMOTE_DIR}/default.yaml" <"$config"
    install_config=1
  fi
  if [[ "$config_env_hash" != "$current_config_env_hash" ]]; then
    printf 'Uploading pluto-rs environment configuration\n' >&2
    target_exec --stdin -- sh -c \
      'umask 077; cat > "$1"' sh "${SYNC_REMOTE_DIR}/.env" <"$config_env"
    install_config_env=1
  fi

  target_exec -- sh -c '
    set -eu
    install -d -m 0755 /opt/pluto-rs/bin /opt/pluto-rs/config
    if [ "$1" = 1 ]; then
      install -o trp-record -g trp-record -m 0500 "$4/pluto-rs" "$5"
    fi
    if [ "$2" = 1 ]; then
      install -o trp-record -g trp-record -m 0400 "$4/default.yaml" "$6"
    fi
    if [ "$3" = 1 ]; then
      install -o trp-record -g trp-record -m 0400 "$4/.env" "$7"
    fi
  ' sh "$install_binary" "$install_config" "$install_config_env" \
    "$SYNC_REMOTE_DIR" "$remote_binary" "$remote_config" "$remote_config_env"

  [[ "$(remote_sha256 "$remote_binary")" == "$binary_hash" ]] ||
    die "uploaded pluto-rs executable failed checksum verification"
  [[ "$(remote_sha256 "$remote_config")" == "$config_hash" ]] ||
    die "uploaded pluto-rs configuration failed checksum verification"
  [[ "$(remote_sha256 "$remote_config_env")" == "$config_env_hash" ]] ||
    die "uploaded pluto-rs environment configuration failed checksum verification"
  target_exec -- runuser -u trp-record -- \
    sh -c 'test -x "$1" && test -r "$2" && test -r "$3"' \
    sh "$remote_binary" "$remote_config" "$remote_config_env"
  target_exec -- rm -rf -- "$SYNC_REMOTE_DIR"
  SYNC_REMOTE_DIR=""
  printf 'pluto-rs is ready in the target Pod\n' >&2
}

start_task() {
  local script_id=$1
  shift
  local redeploy_interval=""
  if [[ "${1:-}" == "--redeploy-interval-seconds" ]]; then
    (($# >= 2)) || die "--redeploy-interval-seconds requires SECONDS"
    redeploy_interval=$2
    validate_redeploy_interval "$redeploy_interval"
    shift 2
  fi
  if [[ "${1:-}" == "--" ]]; then
    shift
  fi

  local pluto_args payload response
  pluto_args="$(jq --compact-output --null-input --args '$ARGS.positional' -- "$@")"
  if [[ -n "$redeploy_interval" ]]; then
    payload="$(jq --compact-output --null-input --argjson args "$pluto_args" \
      --arg script_id "$script_id" --argjson interval "$redeploy_interval" \
      '{script_id:$script_id, parameters:{pluto_args:$args},
        redeploy_interval_seconds:$interval}')"
  else
    payload="$(jq --compact-output --null-input --argjson args "$pluto_args" \
      --arg script_id "$script_id" \
      '{script_id:$script_id, parameters:{pluto_args:$args}}')"
  fi
  response="$(api POST /v1/tasks \
    --header 'content-type: application/json' --data "$payload")"

  printf '%s\n' "$response" | jq .
  verify_started_task "$(jq --raw-output '.task_id' <<<"$response")"
}

verify_started_task() {
  local task_id=$1
  local response status deadline

  [[ "$START_VERIFY_SECONDS" =~ ^[1-9][0-9]*$ ]] ||
    die "START_VERIFY_SECONDS must be a positive integer: $START_VERIFY_SECONDS"

  # A child process can fail just after the start API returns. Observe the task
  # briefly so callers do not receive a false-positive "started" result.
  deadline=$((SECONDS + START_VERIFY_SECONDS))
  while ((SECONDS < deadline)); do
    sleep 0.25
    response="$(api GET "/v1/tasks/${task_id}")"
    status="$(jq --raw-output '.status' <<<"$response")"
    case "$status" in
      starting | running)
        ;;
      *)
        printf '%s\n' "$response" | jq . >&2
        die "Pluto task did not remain active; task_id=${task_id}, status=${status}"
        ;;
    esac
  done

  printf 'Pluto task is running; task_id=%s\n' "$task_id" >&2
}

find_active_task_id() {
  api GET '/v1/tasks?limit=200' | jq --raw-output '
    [.tasks[] | select(
      (.script_id == "record_pluto" or .script_id == "compare_pluto") and
      (.status == "starting" or .status == "running" or .status == "stopping")
    )][0].task_id // empty
  '
}

stop_recording() {
  (($# <= 1)) || die "stop accepts at most one TASK_ID"
  local task_id="${1:-}"
  if [[ -z "$task_id" ]]; then
    task_id="$(find_active_task_id)"
    [[ -n "$task_id" ]] || die "there is no active Pluto task"
  fi
  validate_id "$task_id"
  api POST "/v1/tasks/${task_id}/stop" | jq .
  printf 'Stop requested; task_id=%s\n' "$task_id" >&2
}

list_tasks() {
  (($# <= 1)) || die "tasks accepts at most one LIMIT"
  local limit="${1:-20}"
  validate_limit "$limit"
  api GET "/v1/tasks?limit=${limit}" | jq .
}

list_recordings() {
  (($# <= 2)) || die "recordings accepts at most LIMIT and BEFORE_ID"
  local limit="${1:-20}"
  local before="${2:-}"
  validate_limit "$limit"
  if [[ -n "$before" ]]; then
    validate_id "$before"
    api GET "/v1/recordings?limit=${limit}&before=${before}" | jq .
  else
    api GET "/v1/recordings?limit=${limit}" | jq .
  fi
}

download_recording() {
  (($# <= 2)) || die "download accepts RECORDING_ID and optional OUTPUT_FILE"
  local recording_id="${1:-}"
  [[ -n "$recording_id" ]] || die "download requires RECORDING_ID"
  validate_id "$recording_id"

  local output="${2:-${recording_id}.tar.gz}"
  [[ ! -e "$output" ]] || die "output file already exists: $output"
  DOWNLOAD_TMP="${output}.part.$$"

  curl --silent --show-error --fail-with-body \
    --connect-timeout 5 \
    --output "$DOWNLOAD_TMP" \
    "${API_URL}/v1/recordings/${recording_id}/download"
  mv -- "$DOWNLOAD_TMP" "$output"
  DOWNLOAD_TMP=""
  printf 'Downloaded artifact %s to %s\n' "$recording_id" "$output"
}

main() {
  local command="${1:-}"
  case "$command" in
    -h | --help | help)
      usage
      return
      ;;
    '')
      usage >&2
      die "a command is required"
      ;;
    record | compare | stop | tasks | recordings | download)
      shift
      ;;
    *)
      usage >&2
      die "unknown command: $command"
      ;;
  esac

  require_command curl
  require_command jq
  check_api

  case "$command" in
    record) start_task record_pluto "$@" ;;
    compare)
      prepare_pluto_rs
      start_task compare_pluto "$@"
      ;;
    stop) stop_recording "$@" ;;
    tasks) list_tasks "$@" ;;
    recordings) list_recordings "$@" ;;
    download) download_recording "$@" ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
