use std::path::Path;

use anyhow::{Context, Result, ensure};

pub(super) fn stage_assets(
    assets: &Path,
    target_root: &Path,
    config: &crate::ResolvedProjectConfig,
) -> Result<()> {
    let snapshot = crate::startup::load_startup_snapshot(target_root, &config.target_startup)?;
    let environment_path = assets.join("target-startup.env");
    crate::startup::write_docker_environment_file(&environment_path, target_root)?;
    let mut mounts = String::new();
    for mount in snapshot.mounts() {
        let source = crate::startup::startup_mount_source(target_root, &mount.path)?;
        let source = source
            .to_str()
            .context("startup mount source path is not UTF-8")?;
        ensure!(
            !source.contains([',', '\r', '\n', '\t']),
            "startup mount source contains an unsupported delimiter"
        );
        mounts.push_str(source);
        mounts.push('\t');
        mounts.push_str(&mount.path.to_string_lossy());
        mounts.push('\t');
        mounts.push_str(if mount.writable { "true" } else { "false" });
        mounts.push('\n');
    }
    super::write_asset(&assets.join("target-startup-mounts.tsv"), &mounts, 0o600)
}
