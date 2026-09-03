use std::fs;
use std::process::Command;

use super::*;

#[test]
fn source_runtime_preserves_pod_environment_security_and_launch_overrides() {
    let temp = tempfile::tempdir().unwrap();
    let runtime = temp.path().join("source-runtime.json");
    let script = temp.path().join("container-runtime.sh");
    fs::write(
        &runtime,
        serde_json::to_vec(&serde_json::json!({
            "image_id": format!("sha256:{}", "a".repeat(64)),
            "pod_command": ["/bin/sh", "-c"],
            "pod_args": ["exec application"],
            "image_command": ["image-default"],
            "security": {
                "privileged": false,
                "read_only_root_filesystem": true,
                "no_new_privileges": true,
                "capability_add": ["NET_BIND_SERVICE"],
                "capability_drop": ["MKNOD"]
            },
            "environment": {
                "DATABASE_URL": "mysql://source",
                "HOSTNAME": "pod-name",
                "JAVA_TOOL_OPTIONS": "source-value",
                "PORT": "8080"
            },
            "mounts": []
        }))
        .unwrap(),
    )
    .unwrap();
    write_asset(&script, CONTAINER_RUNTIME, 0o600).unwrap();

    let output = Command::new("bash")
        .args([
            "-ec",
            r#"
                append_source_runtime_output_args() { :; }
                resolve_snapshotted_source_mount() { return 99; }
                source "$1"
                load_source_runtime_spec "$2"
                printf 'arg=%s\n' "${runtime_args[@]}"
                printf 'command=%s\n' "${runtime_command[@]}"
            "#,
            "bash",
        ])
        .arg(&script)
        .arg(&runtime)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = String::from_utf8(output.stdout).unwrap();
    for expected in [
        "arg=--read-only",
        "arg=--security-opt",
        "arg=no-new-privileges",
        "arg=--cap-add",
        "arg=NET_BIND_SERVICE",
        "arg=--cap-drop",
        "arg=MKNOD",
        "arg=DATABASE_URL=mysql://source",
        "arg=PORT=8080",
        "arg=--entrypoint",
        "arg=/bin/sh",
        "command=-c",
        "command=exec application",
    ] {
        assert!(
            output.contains(expected),
            "missing {expected:?} in {output:?}"
        );
    }
    assert!(!output.contains("HOSTNAME=pod-name"));
    assert!(!output.contains("JAVA_TOOL_OPTIONS=source-value"));
    assert!(!output.contains("image-default"));
}
