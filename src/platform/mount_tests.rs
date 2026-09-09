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

#[test]
#[ignore = "requires Docker and TRAFFIC_E2E_TEST_CONTAINER_IMAGE with /bin/sh and GNU cp/chown"]
fn docker_provider_writable_mounts_leave_snapshot_immutable() {
    use std::os::unix::fs::MetadataExt;

    struct RestoreOwnership<'a> {
        path: &'a std::path::Path,
        image: &'a str,
        owner: String,
    }
    impl Drop for RestoreOwnership<'_> {
        fn drop(&mut self) {
            let _ = StdCommand::new("docker")
                .args([
                    "run",
                    "--rm",
                    "--network",
                    "none",
                    "--user",
                    "0:0",
                    "--entrypoint",
                    "/bin/sh",
                    "--volume",
                ])
                .arg(format!("{}:/cleanup", self.path.display()))
                .args([
                    self.image,
                    "-ec",
                    "chown -R \"$1\" /cleanup",
                    "sh",
                    &self.owner,
                ])
                .status();
        }
    }

    let image = std::env::var("TRAFFIC_E2E_TEST_CONTAINER_IMAGE")
        .expect("set TRAFFIC_E2E_TEST_CONTAINER_IMAGE");
    let temp = tempfile::tempdir().unwrap();
    let metadata = fs::metadata(temp.path()).unwrap();
    let _restore = RestoreOwnership {
        path: temp.path(),
        image: &image,
        owner: format!("{}:{}", metadata.uid(), metadata.gid()),
    };
    let source = temp.path().join("snapshot");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("seed"), "baseline").unwrap();
    std::os::unix::fs::symlink("/workspace/source/seed", source.join("seed-link")).unwrap();
    let empty = temp.path().join("empty.tsv");
    fs::write(&empty, "").unwrap();
    let policy = temp.path().join("platform-mounts.sh");
    fs::write(&policy, PLATFORM_MOUNTS).unwrap();
    let runtime = temp.path().join("runtime");
    let output = StdCommand::new("bash")
        .args([
            "-ec",
            r#"
            source "$1"
            resolve_snapshotted_source_mount "$2" /data true snapshot
            printf '%s' "$prepared_mount_source"
        "#,
            "sh",
        ])
        .arg(&policy)
        .arg(&source)
        .env("TRAFFIC_E2E_TARGET_STARTUP_MOUNTS_FILE", &empty)
        .env("TRAFFIC_E2E_TARGET_RUNTIME_OUTPUTS_FILE", &empty)
        .env("startup_snapshot_mounts_root", &source)
        .env("platform_mounts_root", &runtime)
        .env("anchor_image", &image)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mounted = String::from_utf8(output.stdout).unwrap();
    assert_eq!(mounted, runtime.join("source/data").to_str().unwrap());
    let status = StdCommand::new("docker")
        .args([
            "run",
            "--rm",
            "--network",
            "none",
            "--user",
            "998:998",
            "--entrypoint",
            "/bin/sh",
            "--volume",
        ])
        .arg(format!("{mounted}:/data:rw"))
        .args([
            &image,
            "-ec",
            "printf mutated >/data/seed; printf added >/data/new",
        ])
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(fs::read_to_string(source.join("seed")).unwrap(), "baseline");
    assert!(!source.join("new").exists());
    assert_eq!(
        fs::read_link(runtime.join("source/data/seed-link")).unwrap(),
        std::path::Path::new("/workspace/source/seed")
    );
    assert_eq!(
        fs::read_to_string(runtime.join("source/data/seed")).unwrap(),
        "mutated"
    );
}
