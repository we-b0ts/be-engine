use std::os::unix::fs::PermissionsExt as _;
use std::process::Command as StdCommand;

use super::*;

#[test]
fn platform_mount_assets_expose_the_isolation_contract() {
    assert!(MANAGER.contains("source \"$TRAFFIC_E2E_PLATFORM_ASSETS/platform-mounts.sh\""));
    assert!(PLATFORM_MOUNTS.contains("prepare_writable_startup_mounts"));
    assert!(MANAGER.contains("resolve_startup_mount_source target \"$target\" \"$writable\""));
    assert!(
        MANAGER.contains("type=bind,source=${prepared_mount_source},target=${target}${access}")
    );
    assert!(PLATFORM_MOUNTS.contains("partially overlaps startup mount"));
    assert!(PLATFORM_MOUNTS.contains("prepare_empty_runtime_mount source \"$destination\""));
    assert!(MANAGER.contains("/etc/resolv.conf|/etc/hosts|/etc/hostname"));
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
    write_asset(&policy, PLATFORM_MOUNTS, 0o600).unwrap();

    let status = StdCommand::new("bash")
        .args([
            "-ec",
            r#"
                source "$1"
                prepare_writable_startup_mounts() { mkdir -p "$platform_mounts_root/$1"; }
                resolve_recording_mount_source /data1/openapi-config true /original/config
                [[ "$prepared_mount_source" == "$platform_mounts_root/source/data1/openapi-config" ]]
                resolve_recording_mount_source /data1/confs false /original/confs
                [[ "$prepared_mount_source" == "$startup_snapshot_mounts_root/data1/confs" ]]
                ! resolve_recording_mount_source /data1/openapi-config false /original/config
                ! resolve_recording_mount_source /data1/openapi-config/logs true /original/logs
            "#,
            "sh",
        ])
        .arg(&policy)
        .env("TRAFFIC_E2E_TARGET_STARTUP_MOUNTS_FILE", &mounts_file)
        .env("startup_snapshot_mounts_root", &snapshot_root)
        .env("platform_mounts_root", &runtime_root)
        .status()
        .unwrap();

    assert!(status.success());
}
