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
    let recorder_runtime = temp.path().join("recorder-runtime.sh");
    let container_runtime = temp.path().join("container-runtime.sh");
    write_asset(&script, MANAGER, 0o700).unwrap();
    write_asset(&mounts, PLATFORM_MOUNTS, 0o600).unwrap();
    write_asset(&recorder_runtime, RECORDER_RUNTIME, 0o600).unwrap();
    write_asset(&container_runtime, CONTAINER_RUNTIME, 0o600).unwrap();

    for asset in [&script, &mounts, &recorder_runtime, &container_runtime] {
        let status = StdCommand::new("bash")
            .arg("-n")
            .arg(asset)
            .status()
            .unwrap();
        assert!(status.success());
    }
    assert!(MANAGER.contains("recorder-runtime.sh"));
    assert!(MANAGER.contains("container-runtime.sh"));
    assert!(MANAGER.contains("TRAFFIC_E2E_SOURCE_TRAFFIC_POLICY"));
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

    assert!(RECORDER_RUNTIME.contains("docker logs \"$recorder_name\" >&2"));
    assert!(MANAGER.contains("TRAFFIC_E2E_TARGET_RUNTIME_OUTPUTS_FILE"));
    assert!(CONTAINER_RUNTIME.contains("append_source_runtime_output_args"));
    assert!(PLATFORM_MOUNTS.contains("prepare_runtime_outputs"));
    assert!(PLATFORM_MOUNTS.contains("append_source_runtime_output_args"));
    assert!(PLATFORM_MOUNTS.contains("chmod 2770"));
    assert!(!MANAGER.contains("TRAFFIC_E2E_CONFIG_DIR"));
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
    assert!(!MANAGER.contains("run_no_fallback"));
    assert!(!MANAGER.contains("brz-no-fallback.sh"));
    assert!(!MANAGER.contains("wait_port 880 source"));
    let preflight_runtime = MANAGER.split_once("run_preflight()").unwrap().1;
    assert_in_order(
        preflight_runtime,
        &[
            "start_recording_source \"$truststore\"",
            "recording wait-ready",
            "run_preflight_https_probe",
        ],
    );
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
    assert!(MANAGER.contains("if ((effective_uid == 0))"));
    assert!(MANAGER.contains("runtime_uid=$SUDO_UID"));
    assert!(MANAGER.contains("runtime_gid=$SUDO_GID"));
    assert!(MANAGER.contains("artifact_owner=\"$runtime_uid:$runtime_gid\""));
    assert!(MANAGER.contains("normalize_retained_ownership"));
    assert!(MANAGER.contains("chown -hR \"$runtime_uid:$runtime_gid\" -- \"$path\""));
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
