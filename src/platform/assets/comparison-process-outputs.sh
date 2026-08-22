validate_comparison_process_output_environment() {
    case "$TRAFFIC_E2E_COMPARISON_PROCESS_OUTPUTS_ENABLED" in
        true|false) ;;
        *)
            printf 'error: TRAFFIC_E2E_COMPARISON_PROCESS_OUTPUTS_ENABLED must be true or false\n' >&2
            return 1
            ;;
    esac
    [[ "$TRAFFIC_E2E_COMPARISON_PROCESS_OUTPUT_FLUSH_AFTER_LAST_CASE_MS" =~ ^[1-9][0-9]*$ ]] || {
        printf 'error: comparison process output flush must be a positive integer in milliseconds\n' >&2
        return 1
    }
}

comparison_process_output_completion_args() {
    local command_name=$1
    local completion_control_socket=$2
    [[ -n "$completion_control_socket" ]] || return 0
    [[ "$TRAFFIC_E2E_COMPARISON_PROCESS_OUTPUTS_ENABLED" == true ]] || return 0
    local -n command=$command_name
    command+=(
        --completion-quiet-period-ms
        "$TRAFFIC_E2E_COMPARISON_PROCESS_OUTPUT_FLUSH_AFTER_LAST_CASE_MS"
    )
}

wait_for_comparison_process_output_flush() {
    local manifest=$1
    local completion_reason
    completion_reason=$(jq -r '.completion_reason // ""' "$manifest")
    [[ "$completion_reason" != input_exhausted ]] || return 0
    local flush_ms=$TRAFFIC_E2E_COMPARISON_PROCESS_OUTPUT_FLUSH_AFTER_LAST_CASE_MS
    local flush_seconds
    printf -v flush_seconds '%d.%03d' "$((flush_ms / 1000))" "$((flush_ms % 1000))"
    sleep "$flush_seconds"
}

capture_comparison_process_outputs() {
    [[ "$TRAFFIC_E2E_COMPARISON_PROCESS_OUTPUTS_ENABLED" == true ]] || return 0
    local run_root="$artifacts_dir/comparison-recordings/$run_id"
    wait_for_comparison_process_output_flush "$run_root/comparison-recording-run.json"
    "$TRAFFIC_E2E_BIN" internal process-output-capture \
        --target-root "$TRAFFIC_E2E_TARGET_ROOT" \
        --container "$source_name" --side source \
        --observation comparison \
        --output-root "$run_root/process-outputs/source"
    "$TRAFFIC_E2E_BIN" internal process-output-capture \
        --target-root "$TRAFFIC_E2E_TARGET_ROOT" \
        --container "$target_name" --side target \
        --observation comparison \
        --output-root "$run_root/process-outputs/target"
}
