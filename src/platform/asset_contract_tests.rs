use std::process::Command as StdCommand;

use super::*;

fn assert_in_order(content: &str, markers: &[&str]) {
    let mut remainder = content;
    for marker in markers {
        let offset = remainder
            .find(marker)
            .unwrap_or_else(|| panic!("missing marker {marker:?}"));
        remainder = &remainder[offset + marker.len()..];
    }
}

#[test]
fn embedded_platform_manager_is_valid_bash() {
    let temp = tempfile::tempdir().unwrap();
    let script = temp.path().join("manage-platform.sh");
    let process_outputs = temp.path().join("comparison-process-outputs.sh");
    let mounts = temp.path().join("platform-mounts.sh");
    let target_network = temp.path().join("comparison-target-network.sh");
    let recorder_runtime = temp.path().join("recorder-runtime.sh");
    let container_runtime = temp.path().join("container-runtime.sh");
    write_asset(&script, MANAGER, 0o700).unwrap();
    write_asset(&process_outputs, COMPARISON_PROCESS_OUTPUTS, 0o600).unwrap();
    write_asset(&mounts, PLATFORM_MOUNTS, 0o600).unwrap();
    write_asset(&target_network, COMPARISON_TARGET_NETWORK, 0o600).unwrap();
    write_asset(&recorder_runtime, RECORDER_RUNTIME, 0o600).unwrap();
    write_asset(&container_runtime, CONTAINER_RUNTIME, 0o600).unwrap();

    for asset in [
        &script,
        &process_outputs,
        &mounts,
        &target_network,
        &recorder_runtime,
        &container_runtime,
    ] {
        let status = StdCommand::new("bash")
            .arg("-n")
            .arg(asset)
            .status()
            .unwrap();
        assert!(status.success());
    }
    assert!(MANAGER.contains("comparison-target-network.sh"));
    assert!(MANAGER.contains("comparison-process-outputs.sh"));
    assert!(MANAGER.contains("recorder-runtime.sh"));
    assert!(MANAGER.contains("container-runtime.sh"));
    assert!(MANAGER.contains("TRAFFIC_E2E_SOURCE_TRAFFIC_POLICY"));
    assert!(COMPARISON_PROCESS_OUTPUTS.contains("--observation comparison"));
    assert!(COMPARISON_PROCESS_OUTPUTS.contains("completion_reason"));
    assert!(
        RECORDER_RUNTIME
            .contains("--volume \"$TRAFFIC_E2E_RECORDER_CONFIG:/workspace/project.yaml:ro\"")
    );
    assert!(RECORDER_RUNTIME.contains(
        "--volume \"$TRAFFIC_E2E_SOURCE_TRAFFIC_POLICY:/workspace/source-traffic-policy.yaml:ro\""
    ));
    assert_eq!(
        RECORDER_RUNTIME
            .matches("$TRAFFIC_E2E_SOURCE_TRAFFIC_POLICY:/workspace/source-traffic-policy.yaml:ro")
            .count(),
        1
    );
    assert_eq!(
        MANAGER.matches("\"${recorder_config_mounts[@]}\"").count(),
        1
    );
    assert_eq!(
        RECORDER_RUNTIME
            .matches("\"${recorder_config_mounts[@]}\"")
            .count(),
        1
    );
    assert!(RECORDER_RUNTIME.contains("docker logs \"$recorder_name\" >&2"));
    assert!(COMPARISON_TARGET_NETWORK.contains("start_target()"));
    assert!(
        COMPARISON_TARGET_NETWORK
            .contains("--network \"container:${target_anchor_name}\" --user 998:998")
    );
    assert!(COMPARISON_TARGET_NETWORK.contains("TRAFFIC_E2E_TARGET_STARTUP_MOUNTS_FILE"));
    assert!(MANAGER.contains("TRAFFIC_E2E_TARGET_RUNTIME_OUTPUTS_FILE"));
    assert!(CONTAINER_RUNTIME.contains("append_source_runtime_output_args"));
    assert!(PLATFORM_MOUNTS.contains("prepare_runtime_outputs"));
    assert!(PLATFORM_MOUNTS.contains("append_source_runtime_output_args"));
    assert!(PLATFORM_MOUNTS.contains("chmod 2770"));
    assert!(COMPARISON_TARGET_NETWORK.contains("prepare_runtime_outputs target"));
    assert!(COMPARISON_TARGET_NETWORK.contains("target runtime output %s"));
    assert!(
        COMPARISON_TARGET_NETWORK.contains("--env-file \"$TRAFFIC_E2E_TARGET_STARTUP_ENV_FILE\"")
    );
    assert!(!MANAGER.contains("TRAFFIC_E2E_CONFIG_DIR"));
    assert!(COMPARISON_TARGET_NETWORK.contains("\"$TRAFFIC_E2E_TARGET_IMAGE_ID\" >/dev/null"));
    assert!(!MANAGER.contains("TRAFFIC_E2E_PROJECT_CLI"));
    assert!(!MANAGER.contains("start --e2e"));
    assert!(MANAGER.contains(
        "adapter_dockerfile=\"$TRAFFIC_E2E_TARGET_ROOT/.traffic-e2e/Dockerfile.source\""
    ));
    assert!(MANAGER.contains("--build-arg \"SOURCE_IMAGE=${source_image_alias}\""));
    assert!(MANAGER.contains("docker image tag \"$source_image_id\" \"$source_image_alias\""));
    assert!(MANAGER.contains("com.weibo.traffic-e2e.source-image-id=${source_image_id}"));
    assert!(
        MANAGER.contains(
            "com.weibo.traffic-e2e.adapter-contract-revision=${adapter_contract_revision}"
        )
    );
    assert!(MANAGER.contains("recording_adapter_contract_revision"));
    assert!(MANAGER.contains("find . -mindepth 1 -maxdepth 1 -type f -print0"));
    assert!(MANAGER.contains("--file Dockerfile.source -"));
    assert!(!MANAGER.contains("MeshConnectUtil.class"));
    assert!(MANAGER.contains(
        "recording_image_project=$(printf '%s' \"$repo_name\" | tr '[:upper:]' '[:lower:]')"
    ));
    assert!(
        MANAGER
            .contains("adapter_image=\"traffic-e2e/${recording_image_project}-recording:cache\"")
    );
    assert!(MANAGER.contains("build_recording_adapter"));
    assert!(MANAGER.contains("resolve_or_build_recording_adapter"));
    assert!(MANAGER.contains("load_initialized_recording_adapter"));
    assert!(MANAGER.contains("reusing initialized recording source adaptor"));
    assert!(
        MANAGER.contains("cache does not match the snapshotted source image or build contract")
    );
    assert!(!MANAGER.contains("TRAFFIC_E2E_SOURCE_CONTAINER"));
    assert!(MANAGER.contains("TRAFFIC_E2E_SOURCE_RUNTIME"));
    let before_adapter_build = MANAGER.split_once("build_recording_adapter()").unwrap().0;
    assert!(before_adapter_build.contains("source runtime snapshot has no image ID"));
    assert!(!MANAGER.contains("recording-adapter.fingerprint"));
    assert!(MANAGER.contains("--iidfile \"$adapter_iid_file\""));
    assert!(MANAGER.contains("load_source_runtime_spec \"$TRAFFIC_E2E_SOURCE_RUNTIME\""));
    assert!(CONTAINER_RUNTIME.contains(".pod_command[]?"));
    assert!(CONTAINER_RUNTIME.contains(".pod_args != null"));
    assert!(CONTAINER_RUNTIME.contains("resolve_snapshotted_source_mount"));
    assert!(!MANAGER.contains("source-adapter-runtime"));
    assert!(!MANAGER.contains("recording-runtime-cache"));
    assert!(MANAGER.contains(
        "\"${runtime_args[@]}\" \"$adapter_image_id\" \"${runtime_command[@]}\" >/dev/null"
    ));
    assert!(MANAGER.contains("docker run --rm --platform linux/amd64 --network none --user 0:0"));
    let adapted_source = MANAGER
        .split_once("start_recording_source()")
        .unwrap()
        .1
        .split_once("run_preflight_https_probe()")
        .unwrap()
        .0;
    assert!(!adapted_source.contains("--user"));
    assert!(!adapted_source.contains("--privileged"));
    assert!(!adapted_source.contains("MESH_CONNECT_HOST"));
    assert!(!adapted_source.contains("TRAFFIC_E2E_BREEZE_NO_FALLBACK"));
    let comparison_source = MANAGER
        .split_once("start_comparison_source()")
        .unwrap()
        .1
        .split_once("build_recording_adapter()")
        .unwrap()
        .0;
    assert!(comparison_source.contains("load_source_runtime_spec \"$TRAFFIC_E2E_SOURCE_RUNTIME\""));
    assert!(comparison_source.contains("\"${runtime_args[@]}\" \"$adapter_image_id\""));
    assert!(!comparison_source.contains(".[0].Config.Image"));
    assert!(!comparison_source.contains("MESH_CONNECT_HOST"));
    assert!(!comparison_source.contains("TRAFFIC_E2E_BREEZE_NO_FALLBACK"));
    let comparison_runtime = MANAGER
        .split_once("run_comparison_recording()")
        .unwrap()
        .1
        .split_once("case \"$operation\"")
        .unwrap()
        .0;
    assert!(comparison_runtime.contains("resolve_or_build_recording_adapter"));
    assert!(comparison_runtime.contains("start_comparison_source"));
    assert!(MANAGER.contains("if \"$http_recording_enabled\"; then"));
    assert_in_order(
        comparison_source,
        &[
            "require_port_available \"$TRAFFIC_E2E_SOURCE_HOST\"",
            "docker run --detach --name \"$source_name\"",
            "wait_http \"$TRAFFIC_E2E_SOURCE_ORIGIN\"",
            "require_container_running \"$source_name\" source",
            "require_port_open \"$TRAFFIC_E2E_SOURCE_HOST\"",
        ],
    );
    let target_start = COMPARISON_TARGET_NETWORK
        .split_once("start_target()")
        .unwrap()
        .1
        .split_once("stop_target()")
        .unwrap()
        .0;
    assert_in_order(
        target_start,
        &[
            "require_port_available \"$target_network_ip\"",
            "docker run --detach --name \"$target_name\"",
        ],
    );
    assert_in_order(
        comparison_runtime,
        &[
            "start_comparison_target_network",
            "start_cache_snapshot",
            "start_comparison_source",
            "start_target",
            "wait_http \"$target_origin\"",
            "require_container_running \"$target_name\" target",
            "require_port_open \"$target_network_ip\"",
        ],
    );
    assert!(!comparison_runtime.contains(
        "require_port_open \"$target_network_ip\" \"$TRAFFIC_E2E_TARGET_MOTAN_PORT\" target-motan"
    ));
    assert_in_order(
        comparison_runtime,
        &[
            "start_target",
            "require_container_running \"$target_name\" target",
            "recording wait-ready --control-socket /workspace/control/cache-snapshot.sock",
            "internal comparison-run --config",
            "wait_for_comparison_ready \"$comparison_control_socket\"",
            "start_recording_input \"$comparison_control_socket\"",
        ],
    );
    assert!(COMPARISON_TARGET_NETWORK.contains("docker network create --driver bridge"));
    assert!(
        COMPARISON_TARGET_NETWORK
            .contains("target_origin=\"http://${target_network_ip}:${TRAFFIC_E2E_TARGET_PORT}\"")
    );
    assert!(MANAGER.contains("--candidate-upstream \"$target_origin\""));
    assert!(!MANAGER.contains("run_no_fallback"));
    assert!(!MANAGER.contains("brz-no-fallback.sh"));
    assert!(!MANAGER.contains("wait_port 880 source"));
    let preflight_runtime = MANAGER
        .split_once("run_preflight()")
        .unwrap()
        .1
        .split_once("wait_for_comparison_ready()")
        .unwrap()
        .0;
    assert_in_order(
        preflight_runtime,
        &[
            "start_recording_source \"$truststore\"",
            "recording wait-ready",
            "run_preflight_https_probe",
        ],
    );
    assert!(MANAGER.contains(
            "[[ -z \"${TRAFFIC_E2E_MANAGED_COMPARISON_LISTEN-}\" ]] || comparison_command+=(--listen \"$TRAFFIC_E2E_MANAGED_COMPARISON_LISTEN\")"
        ));
    assert!(MANAGER.contains(
            "[[ -z \"${TRAFFIC_E2E_MANAGED_COMPARISON_MOTAN_LISTEN-}\" ]] || comparison_command+=(--motan-listen \"$TRAFFIC_E2E_MANAGED_COMPARISON_MOTAN_LISTEN\")"
        ));
    assert!(RECORDER_RUNTIME.contains("--target-source-ip \"$target_network_ip\""));
    assert!(RECORDER_RUNTIME.contains("--interception-listen-ip \"$target_network_gateway\""));
    assert!(!MANAGER.contains("start_genuine_source"));
    assert!(MANAGER.contains(
        "docker run --rm --platform linux/amd64 --network none --user 0:0 --entrypoint /bin/sh"
    ));
    assert!(!MANAGER.contains("cat >\"$adapter_context/Dockerfile\""));
    assert!(!MANAGER.contains("apply-breeze-sdk-patch"));
    assert!(!MANAGER.contains("TRAFFIC_E2E_SOURCE_RUN_COMMAND"));
    assert!(!MANAGER.contains("docker image rm \"$adapter_image\""));
    assert!(MANAGER.contains("[[ \"$operation\" == preflight ]]"));
    assert!(!MANAGER.contains("TRAFFIC_E2E_BREEZE_CONTAINER"));
    assert!(MANAGER.contains("internal recorder-run --config"));
    assert!(MANAGER.contains("internal comparison-run --config"));
    assert!(RECORDER_RUNTIME.contains("internal cache-snapshot-run"));
    assert!(
        MANAGER.contains(
            "recording wait-ready --control-socket /workspace/control/cache-snapshot.sock"
        )
    );
    assert!(
        comparison_runtime.contains("comparison_socket_dir=$(mktemp -d /tmp/trp-e2e-cmp.XXXXXX)")
    );
    assert!(
        comparison_runtime
            .contains("comparison_control_socket=\"$comparison_socket_dir/control.sock\"")
    );
    assert!(!comparison_runtime.contains("$control_dir/comparison.sock"));
    let comparison_ready = MANAGER
        .split_once("wait_for_comparison_ready()")
        .unwrap()
        .1
        .split_once("run_comparison_recording()")
        .unwrap()
        .0;
    assert!(comparison_ready.contains("kill -0 \"$comparison_pid\""));
    assert!(comparison_ready.contains("kill -0 \"$readiness_pid\""));
    assert!(comparison_ready.contains("comparison recording exited before readiness"));
    assert!(
        comparison_runtime.contains("wait_for_comparison_ready \"$comparison_control_socket\"")
    );
    assert!(!comparison_runtime.contains(
        "\"$TRAFFIC_E2E_BIN\" recording wait-ready --control-socket \"$comparison_control_socket\""
    ));
    assert!(MANAGER.contains("start_recording_input \"$comparison_control_socket\""));
    assert!(MANAGER.contains("TRAFFIC_E2E_MAX_FAILED_CASES_PER_API"));
    assert!(MANAGER.contains("--max-failed-cases-per-api"));
    assert!(
        MANAGER.contains(
            "input_command+=(--completion-control-socket \"$completion_control_socket\")"
        )
    );
    assert!(MANAGER.contains(
        "for selector in \"${api_selectors[@]}\"; do input_command+=(--api \"$selector\"); done"
    ));
    assert!(RECORDER_RUNTIME.contains("com.weibo.traffic-e2e.role=cache-snapshot"));
    assert!(MANAGER.contains("normalize_cache_snapshot_ownership"));
    assert!(MANAGER.contains("if ((effective_uid == 0))"));
    assert!(MANAGER.contains("runtime_uid=$SUDO_UID"));
    assert!(MANAGER.contains("runtime_gid=$SUDO_GID"));
    assert!(MANAGER.contains("artifact_owner=\"$runtime_uid:$runtime_gid\""));
    assert!(MANAGER.contains("normalize_retained_ownership"));
    assert!(MANAGER.contains("chown -hR \"$runtime_uid:$runtime_gid\" -- \"$path\""));
    assert!(
        RECORDER_RUNTIME.contains("'chown -hR \"$1:$2\" -- /workspace/control/cache-snapshot'")
    );
    let cleanup = MANAGER.split("cleanup() {").nth(1).unwrap();
    assert_in_order(
        cleanup,
        &[
            "stop_container \"$recorder_name\"",
            "normalize_cache_snapshot_ownership",
            "normalize_retained_ownership",
            "remove_private_runtime_dir \"$comparison_socket_dir\" /tmp",
            "remove_private_runtime_dir \"$control_dir\"",
            "remove_platform_mounts",
        ],
    );
    assert!(MANAGER.contains("record-comparison|preflight"));
    assert!(MANAGER.contains("preflight_root=\"$runtime_root/preflight/$run_id\""));
    assert!(MANAGER.contains("[[ \"$operation\" == preflight ]]"));
    assert!(MANAGER.contains("and .published_cases > 0'"));
    assert!(MANAGER.contains("run_preflight_https_probe"));
    assert!(!MANAGER.contains("recorder_command+=(--full-traffic-jsonl)"));
    assert!(!MANAGER.contains("recorder_command+=(--breeze)"));
    assert!(MANAGER.contains("recorder_command+=(--preflight-probe java-truststore)"));
    assert!(MANAGER.contains("recorder_command+=(--preflight-probe system-network)"));
    assert!(!MANAGER.contains("chmod 0644 \"$data_dir/traffic-recorder-ca.pem\""));
    assert!(MANAGER.contains("detect_source_java_runtime"));
    assert!(MANAGER.contains("--entrypoint java \"$adapter_image_id\" -version"));
    assert!(!MANAGER.contains("TRAFFIC_E2E_SOURCE_LANGUAGE"));
    assert!(MANAGER.contains("traffic-e2e-network-probe:0.0.1"));
    assert!(MANAGER.contains("X-Traffic-E2E-Probe-Origin: source"));
    assert!(String::from_utf8_lossy(HTTPS_PROBE).contains("X-Traffic-E2E-Probe-Origin"));
    assert!(MANAGER.contains(
        "$TRAFFIC_E2E_PLATFORM_ASSETS/HttpsProbe.class:/traffic-e2e/HttpsProbe.class:ro"
    ));
    assert!(MANAGER.contains("java -Djava.net.preferIPv4Stack=true -cp /traffic-e2e"));
    assert!(MANAGER.contains("timeout --foreground 10 docker exec \"$source_name\""));
    assert!(!MANAGER.contains("command -v javac"));
    assert!(!MANAGER.contains("getent ahostsv4 demo.test"));
    assert!(PREFLIGHT_READINESS.contains("phase: \"preflight-readiness-recorded\""));
    assert!(PREFLIGHT_READINESS.contains("TRAFFIC_E2E_SOURCE_READY_PATH"));
    assert!(PREFLIGHT_READINESS.contains("TRAFFIC_E2E_SOURCE_READY_STATUS"));
    assert!(MANAGER.contains("record_preflight_readiness"));
    assert!(!MANAGER.contains("TRAFFIC_E2E_PREFLIGHT_MOTAN_ENABLED"));
    assert!(!PREFLIGHT_READINESS.contains("business"));
    assert!(MANAGER.contains("wait_for_recorder_or_duration"));
    let preflight_runtime = MANAGER
        .split("run_preflight() {")
        .nth(1)
        .unwrap()
        .split("wait_for_comparison_ready() {")
        .next()
        .unwrap();
    assert_in_order(
        preflight_runtime,
        &[
            "finalize_recorder",
            "internal process-output-capture",
            "--container \"$source_name\" --side source",
            "manifest_filter=",
        ],
    );
    assert!(
        RECORDER_RUNTIME
            .contains("timeout --foreground \"$duration_seconds\" docker wait \"$recorder_name\"")
    );
    assert!(!MANAGER.contains("sleep \"$duration_seconds\""));
}

#[test]
fn comparison_process_output_flush_extends_finite_input_completion() {
    let temp = tempfile::tempdir().unwrap();
    let asset = temp.path().join("comparison-process-outputs.sh");
    write_asset(&asset, COMPARISON_PROCESS_OUTPUTS, 0o600).unwrap();

    let output = StdCommand::new("bash")
        .arg("-c")
        .arg(
            "source \"$1\"; input_command=(recording-input); \
             comparison_process_output_completion_args input_command /tmp/control.sock; \
             printf '%s\\n' \"${input_command[@]}\"",
        )
        .arg("bash")
        .arg(&asset)
        .env("TRAFFIC_E2E_COMPARISON_PROCESS_OUTPUTS_ENABLED", "true")
        .env(
            "TRAFFIC_E2E_COMPARISON_PROCESS_OUTPUT_FLUSH_AFTER_LAST_CASE_MS",
            "15000",
        )
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "recording-input\n--completion-quiet-period-ms\n15000\n"
    );
}

#[test]
fn stages_private_executable_assets() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path();
    let assets = stage_assets(target).unwrap();

    assert_eq!(
        fs::metadata(assets.join("manage-platform.sh"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(assets.join("comparison-target-network.sh"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(assets.join("comparison-process-outputs.sh"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(assets.join("recorder-runtime.sh"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(!assets.join("brz-no-fallback.sh").exists());
    assert_eq!(
        fs::metadata(assets.join("preflight-readiness.sh"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(assets.join("HttpsProbe.class"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
    assert_eq!(&HTTPS_PROBE[..4], b"\xca\xfe\xba\xbe");
    assert_eq!(u16::from_be_bytes([HTTPS_PROBE[6], HTTPS_PROBE[7]]), 52);
    assert!(!assets.join("MeshConnectUtil.java").exists());
    assert!(!assets.join("apply-breeze-sdk-patch").exists());
}

#[test]
fn resolves_http_origin_endpoints() {
    assert_eq!(
        http_origin_endpoint("http://127.0.0.1:8080", "source").unwrap(),
        ("127.0.0.1".to_string(), 8080)
    );
    assert_eq!(
        http_origin_endpoint("https://example.test", "source").unwrap(),
        ("example.test".to_string(), 443)
    );
    assert!(http_origin_endpoint("file:///tmp/source", "source").is_err());
}
