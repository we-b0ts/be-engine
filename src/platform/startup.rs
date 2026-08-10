use std::path::Path;

use anyhow::{Context, Result, ensure};

pub(super) fn stage_assets(
    assets: &Path,
    target_root: &Path,
    config: &crate::e2e_run::ResolvedProjectConfig,
) -> Result<()> {
    let snapshot = crate::startup::load_startup_snapshot(target_root, &config.target_startup)?;
    let environment_path = assets.join("target-startup.env");
    if !crate::startup::write_docker_environment_file(
        &environment_path,
        &snapshot,
        &config.target_startup,
        config.target_port,
        false,
        crate::target_container::TARGET_REPLAY_CA_PATH,
    )? {
        super::write_asset(&environment_path, "", 0o600)?;
    }
    let mut mounts = String::new();
    for mount in &config.target_startup.mounts {
        let source = crate::startup::startup_mount_source(target_root, mount)?;
        let source = source
            .to_str()
            .context("startup mount source path is not UTF-8")?;
        ensure!(
            !source.contains([',', '\r', '\n', '\t']),
            "startup mount source contains an unsupported delimiter"
        );
        mounts.push_str(source);
        mounts.push('\t');
        mounts.push_str(&mount.to_string_lossy());
        mounts.push('\n');
    }
    super::write_asset(&assets.join("target-startup-mounts.tsv"), &mounts, 0o600)
}
