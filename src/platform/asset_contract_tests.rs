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
    let mounts = temp.path().join("platform-mounts.sh");
    let target_network = temp.path().join("comparison-target-network.sh");
    let recorder_runtime = temp.path().join("recorder-runtime.sh");
    write_asset(&script, MANAGER, 0o700).unwrap();
    write_asset(&mounts, PLATFORM_MOUNTS, 0o600).unwrap();
    write_asset(&target_network, COMPARISON_TARGET_NETWORK, 0o600).unwrap();
    write_asset(&recorder_runtime, RECORDER_RUNTIME, 0o600).unwrap();

    for asset in [&script, &mounts, &target_network, &recorder_runtime] {
        let status = StdCommand::new("bash")
            .arg("-n")
            .arg(asset)
            .status()
            .unwrap();
        assert!(status.success());
    }
    assert!(MANAGER.contains("comparison-target-network.sh"));
    assert!(MANAGER.contains("recorder-runtime.sh"));
    assert!(MANAGER.contains("TRAFFIC_E2E_COORDINATOR_RULES"));
    assert!(
        RECORDER_RUNTIME
            .contains("--volume \"$TRAFFIC_E2E_RECORDER_CONFIG:/workspace/project.yaml:ro\"")
    );
    assert!(RECORDER_RUNTIME.contains(
        "--volume \"$TRAFFIC_E2E_COORDINATOR_RULES:/workspace/coordinator-rules.yaml:ro\""
    ));
    assert_eq!(
        RECORDER_RUNTIME
            .matches("$TRAFFIC_E2E_COORDINATOR_RULES:/workspace/coordinator-rules.yaml:ro")
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
    assert!(
        COMPARISON_TARGET_NETWORK.contains("--env-file \"$TRAFFIC_E2E_TARGET_STARTUP_ENV_FILE\"")
    );
    assert!(!MANAGER.contains("TRAFFIC_E2E_CONFIG_DIR"));
    assert!(COMPARISON_TARGET_NETWORK.contains("\"$TRAFFIC_E2E_TARGET_IMAGE_ID\" >/dev/null"));
    assert!(!MANAGER.contains("TRAFFIC_E2E_PROJECT_CLI"));
    assert!(!MANAGER.contains("start --e2e"));
    assert!(MANAGER.contains(
        "adapter_dockerfile=\"$TRAFFIC_E2E_TARGET_ROOT/.traffic-e2e/Dockerfile.recording\""
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
    assert!(MANAGER.contains("--file Dockerfile.recording -"));
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
    assert!(MANAGER.contains("cache does not match the source image or build contract"));
    assert_eq!(
        MANAGER
            .matches("docker container inspect \"$TRAFFIC_E2E_SOURCE_CONTAINER\"")
            .count(),
        1
    );
    let before_adapter_build = MANAGER.split_once("build_recording_adapter()").unwrap().0;
    assert!(
        before_adapter_build.contains("docker container inspect \"$TRAFFIC_E2E_SOURCE_CONTAINER\"")
    );
    assert!(before_adapter_build.contains(
            "configured source container %s must be stopped; the managed source adaptor owns its recording ports"
        ));
    assert!(!MANAGER.contains("recording-adapter.fingerprint"));
    assert!(MANAGER.contains("--iidfile \"$adapter_iid_file\""));
    assert!(MANAGER.contains("load_runtime_spec \"$source_inspect\" recording recording image"));
    assert!(!MANAGER.contains("source-adapter-runtime"));
    assert!(!MANAGER.contains("recording-runtime-cache"));
    assert!(MANAGER.contains("\"${runtime_args[@]}\" \"$adapter_image_id\" >/dev/null"));
    assert!(MANAGER.contains("docker run --rm --platform linux/amd64 --network none --user 0:0"));
    let adapted_source = MANAGER
        .split_once("start_recording_source()")
        .unwrap()
        .1
        .split_once("run_no_fallback()")
        .unwrap()
        .0;
    assert!(!adapted_source.contains("--user"));
    assert!(!adapted_source.contains("--privileged"));
    let comparison_source = MANAGER
        .split_once("start_comparison_source()")
        .unwrap()
        .1
        .split_once("build_recording_adapter()")
        .unwrap()
        .0;
    assert!(
        comparison_source
            .contains("load_runtime_spec \"$source_inspect\" recording recording image")
    );
    assert!(comparison_source.contains("\"${runtime_args[@]}\" \"$adapter_image_id\""));
    assert!(!comparison_source.contains(".[0].Config.Image"));
    assert!(comparison_source.contains("MESH_CONNECT_HOST=${target_network_ip}"));
    let comparison_runtime = MANAGER
        .split_once("run_comparison_recording()")
        .unwrap()
        .1
        .split_once("case \"$operation\"")
        .unwrap()
        .0;
    assert!(comparison_runtime.contains("resolve_or_build_recording_adapter"));
    assert!(comparison_runtime.contains("start_comparison_source"));
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
            "enable_comparison_target_loopback_ingress",
            "start_breeze \"container:${target_anchor_name}\" \"$target_network_ip\"",
            "start_comparison_source",
            "start_target",
            "wait_http \"$target_origin\"",
            "require_container_running \"$target_name\" target",
            "require_port_open \"$target_network_ip\"",
        ],
    );
    assert!(COMPARISON_TARGET_NETWORK.contains("docker network create --driver bridge"));
    assert!(COMPARISON_TARGET_NETWORK.contains("net.ipv4.conf.all.route_localnet=1"));
    assert!(COMPARISON_TARGET_NETWORK.contains("enable_comparison_target_loopback_ingress()"));
    assert!(COMPARISON_TARGET_NETWORK.contains("--to-destination 127.0.0.1"));
    assert!(
        COMPARISON_TARGET_NETWORK
            .contains("target_origin=\"http://${target_network_ip}:${TRAFFIC_E2E_TARGET_PORT}\"")
    );
    assert!(MANAGER.contains("--candidate-upstream \"$target_origin\""));
    assert!(MANAGER.contains(
            "[[ -z \"${TRAFFIC_E2E_MANAGED_COMPARISON_LISTEN-}\" ]] || comparison_command+=(--listen \"$TRAFFIC_E2E_MANAGED_COMPARISON_LISTEN\")"
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
    assert!(MANAGER.contains(
            "registry.api.demo.test/weibo_rd_if/breeze:v0.1.21-e2e@sha256:5aba065755724d43c7da3f6b79ac82890a0a0a08c6ae3f43af12558b5e52462f"
        ));
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
    assert!(
        RECORDER_RUNTIME.contains("'chown -hR \"$1:$2\" -- /workspace/control/cache-snapshot'")
    );
    let cleanup = MANAGER.split("cleanup() {").nth(1).unwrap();
    assert_in_order(
        cleanup,
        &[
            "stop_container \"$recorder_name\"",
            "normalize_cache_snapshot_ownership",
            "remove_private_runtime_dir \"$comparison_socket_dir\" /tmp",
            "remove_private_runtime_dir \"$control_dir\"",
            "remove_platform_mounts",
        ],
    );
    assert!(MANAGER.contains("record|record-comparison|preflight"));
    assert!(MANAGER.contains("preflight_root=\"$runtime_root/preflight/$run_id\""));
    assert!(MANAGER.contains("[[ \"$operation\" == preflight ]]"));
    assert!(MANAGER.contains("manifest_filter+=' and .published_cases > 0'"));
    assert!(MANAGER.contains("run_preflight_https_probe"));
    assert!(!MANAGER.contains("recorder_command+=(--full-traffic-jsonl)"));
    assert!(MANAGER.contains("recorder_command+=(--preflight-probe java-truststore)"));
    assert!(MANAGER.contains("recorder_command+=(--preflight-probe system-network)"));
    assert!(MANAGER.contains("detect_source_java_runtime"));
    assert!(MANAGER.contains("--entrypoint java \"$adapter_image_id\" -version"));
    assert!(!MANAGER.contains("TRAFFIC_E2E_SOURCE_LANGUAGE"));
    assert!(MANAGER.contains("traffic-e2e-network-probe:0.0.1"));
    assert!(MANAGER.contains(
        "$TRAFFIC_E2E_PLATFORM_ASSETS/HttpsProbe.class:/traffic-e2e/HttpsProbe.class:ro"
    ));
    assert!(MANAGER.contains("java -Djava.net.preferIPv4Stack=true -cp /traffic-e2e"));
    assert!(!MANAGER.contains("command -v javac"));
    assert!(!MANAGER.contains("getent ahostsv4 demo.test"));
    assert!(PREFLIGHT_BUSINESS_INPUT.contains("phase: \"preflight-business-input-required\""));
    assert!(MANAGER.contains("TRAFFIC_E2E_PREFLIGHT_MOTAN_ENABLED"));
    assert!(PREFLIGHT_BUSINESS_INPUT.contains("TRAFFIC_E2E_MOTAN_REPLAY_COMMAND"));
    assert!(PREFLIGHT_BUSINESS_INPUT.contains("optional_when_no_request_is_observed"));
    assert!(
        PREFLIGHT_BUSINESS_INPUT
            .contains("replace 127.0.0.1 with this preflight host when capturing remotely")
    );
    assert!(MANAGER.contains("wait_for_recorder_or_duration"));
    assert!(
        RECORDER_RUNTIME
            .contains("timeout --foreground \"$duration_seconds\" docker wait \"$recorder_name\"")
    );
    assert!(!MANAGER.contains("sleep \"$duration_seconds\""));
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
        fs::metadata(assets.join("recorder-runtime.sh"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(assets.join("brz-no-fallback.sh"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(assets.join("preflight-business-input.sh"))
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
