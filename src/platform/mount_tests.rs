use std::os::unix::fs::PermissionsExt as _;
use std::process::Command as StdCommand;

use super::*;

#[test]
fn platform_mount_assets_expose_the_isolation_contract() {
    assert!(MANAGER.contains("source \"$TRAFFIC_E2E_PLATFORM_ASSETS/platform-mounts.sh\""));
    assert!(PLATFORM_MOUNTS.contains("prepare_writable_startup_mounts"));
    assert!(PLATFORM_MOUNTS.contains("append_source_runtime_output_args"));
    assert!(
        COMPARISON_TARGET_NETWORK
            .contains("resolve_startup_mount_source target \"$target\" \"$writable\"")
    );
    assert!(
        COMPARISON_TARGET_NETWORK
            .contains("type=bind,source=${prepared_mount_source},target=${target}${access}")
    );
    assert!(PLATFORM_MOUNTS.contains("partially overlaps startup mount"));
    assert!(PLATFORM_MOUNTS.contains("prepare_empty_runtime_mount source \"$destination\""));
    assert!(CONTAINER_RUNTIME.contains("/etc/resolv.conf|/etc/hosts|/etc/hostname"));
    assert!(!MANAGER.contains("translated=\"/data1/${first}-recording\""));

    let temp = tempfile::tempdir().unwrap();
    let assets = stage_assets(temp.path()).unwrap();
    assert_eq!(
        fs::metadata(assets.join("platform-mounts.sh"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
fn platform_mount_policy_preserves_access_and_rejects_ambiguous_overlap() {
    let temp = tempfile::tempdir().unwrap();
    let snapshot_root = temp.path().join("startup/mounts");
    let runtime_root = temp.path().join("runtime");
    let mounts_file = temp.path().join("mounts.tsv");
    let runtime_outputs_file = temp.path().join("runtime-outputs.tsv");
    let policy = temp.path().join("platform-mounts.sh");
    fs::create_dir_all(&snapshot_root).unwrap();
    fs::write(
        &mounts_file,
        format!(
            "{}/data1/openapi-config\t/data1/openapi-config\ttrue\n{}/data1/confs\t/data1/confs\tfalse\n",
            snapshot_root.display(),
            snapshot_root.display()
        ),
    )
    .unwrap();
    fs::write(
        &runtime_outputs_file,
        "application-logs\t/data1/weibo/logs\n",
    )
    .unwrap();
    write_asset(&policy, PLATFORM_MOUNTS, 0o600).unwrap();

    let status = StdCommand::new("bash")
        .args([
            "-ec",
            r#"
                source "$1"
                prepare_writable_startup_mounts() { mkdir -p "$platform_mounts_root/$1"; }
                prepare_runtime_outputs() { mkdir -p "$runtime_outputs_root/$1/application-logs"; }
                resolve_recording_mount_source /data1/openapi-config true /original/config
                [[ "$prepared_mount_source" == "$platform_mounts_root/source/data1/openapi-config" ]]
                resolve_recording_mount_source /data1/confs false /original/confs
                [[ "$prepared_mount_source" == "$startup_snapshot_mounts_root/data1/confs" ]]
                ! resolve_recording_mount_source /data1/openapi-config false /original/config
                ! resolve_recording_mount_source /data1/openapi-config/logs true /original/logs
                resolve_recording_mount_source /data1/weibo/logs false /original/logs
                [[ "$prepared_mount_source" == "$runtime_outputs_root/source/application-logs" ]]
                [[ "$prepared_mount_writable" == true ]]
                ! resolve_recording_mount_source /data1/weibo true /original/weibo
                runtime_args=()
                append_source_runtime_output_args
                ((${#runtime_args[@]} == 0))
                seen_source_runtime_outputs=()
                append_source_runtime_output_args
                [[ "${runtime_args[0]}" == --volume ]]
                [[ "${runtime_args[1]}" == "$runtime_outputs_root/source/application-logs:/data1/weibo/logs:rw" ]]
            "#,
            "sh",
        ])
        .arg(&policy)
        .env("TRAFFIC_E2E_TARGET_STARTUP_MOUNTS_FILE", &mounts_file)
        .env(
            "TRAFFIC_E2E_TARGET_RUNTIME_OUTPUTS_FILE",
            &runtime_outputs_file,
        )
        .env("startup_snapshot_mounts_root", &snapshot_root)
        .env("platform_mounts_root", &runtime_root)
        .env("runtime_outputs_root", temp.path().join("runtime-outputs"))
        .status()
        .unwrap();

    assert!(status.success());
}
