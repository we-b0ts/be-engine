use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use uuid::Uuid;

use super::{
    COMPARISON_PROCESS_OUTPUTS, COMPARISON_TARGET_NETWORK, CONTAINER_RUNTIME, HTTPS_PROBE, MANAGER,
    PLATFORM_MOUNTS, PREFLIGHT_READINESS, RECORDER_RUNTIME,
};

pub(super) fn stage_assets(target_root: &Path) -> Result<PathBuf> {
    let root = crate::internal_runtime::root(target_root)
        .join("platform/assets")
        .join(Uuid::new_v4().to_string());
    fs::create_dir_all(&root)
        .with_context(|| format!("failed to create Platform asset root {}", root.display()))?;
    write_asset(&root.join("manage-platform.sh"), MANAGER, 0o700)?;
    write_asset(
        &root.join("comparison-process-outputs.sh"),
        COMPARISON_PROCESS_OUTPUTS,
        0o600,
    )?;
    write_asset(
        &root.join("comparison-target-network.sh"),
        COMPARISON_TARGET_NETWORK,
        0o600,
    )?;
    write_asset(&root.join("recorder-runtime.sh"), RECORDER_RUNTIME, 0o600)?;
    write_asset(&root.join("platform-mounts.sh"), PLATFORM_MOUNTS, 0o600)?;
    write_asset(&root.join("container-runtime.sh"), CONTAINER_RUNTIME, 0o600)?;
    write_asset(
        &root.join("preflight-readiness.sh"),
        PREFLIGHT_READINESS,
        0o600,
    )?;
    write_binary_asset(&root.join("HttpsProbe.class"), HTTPS_PROBE, 0o644)?;
    Ok(root)
}

pub(super) fn write_asset(path: &Path, content: &str, mode: u32) -> Result<()> {
    fs::write(path, content).with_context(|| format!("failed to write {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("failed to set permissions on {}", path.display()))
}

fn write_binary_asset(path: &Path, content: &[u8], mode: u32) -> Result<()> {
    fs::write(path, content).with_context(|| format!("failed to write {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("failed to set permissions on {}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use super::*;

    #[test]
    fn recorder_runtime_mounts_both_configuration_files_read_only() {
        let temp = tempfile::tempdir().unwrap();
        let runtime = temp.path().join("recorder-runtime.sh");
        let project = temp.path().join("project.yaml");
        let rules = temp.path().join("source-traffic-policy.yaml");
        write_asset(&runtime, RECORDER_RUNTIME, 0o600).unwrap();
        fs::write(&project, "version: 14\n").unwrap();
        fs::write(&rules, "version: 1\n").unwrap();

        let output = Command::new("bash")
            .arg("-c")
            .arg("source \"$1\"; printf '%s\\n' \"${recorder_config_mounts[@]}\"")
            .arg("bash")
            .arg(&runtime)
            .env("TRAFFIC_E2E_RECORDER_CONFIG", &project)
            .env("TRAFFIC_E2E_SOURCE_TRAFFIC_POLICY", &rules)
            .output()
            .unwrap();

        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            format!(
                "--volume\n{}:/workspace/project.yaml:ro\n--volume\n{}:/workspace/source-traffic-policy.yaml:ro\n",
                project.display(),
                rules.display()
            )
        );
    }
}
