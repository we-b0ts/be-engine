use std::path::Path;

use anyhow::{Context, Result, ensure};

pub(crate) const TRAFFIC_E2E_ROOT: &str = ".traffic-e2e";
pub(crate) const LOCAL_ROOT: &str = ".traffic-e2e/local";
pub(crate) const LOCAL_GITIGNORE_RULE: &str = "/.traffic-e2e/local/";
pub(crate) const LOCAL_ARTIFACTS_RELATIVE_ROOT: &str = "local/artifacts";
pub(crate) const LOCAL_ARTIFACTS_ROOT: &str = ".traffic-e2e/local/artifacts";
pub(crate) const LOCAL_STARTUP_ROOT: &str = ".traffic-e2e/local/startup";
pub(crate) const LOCAL_STARTUP_MOUNTS_ROOT: &str = ".traffic-e2e/local/startup/mounts";
pub(crate) const LOCAL_STARTUP_ENVIRONMENT_PATH: &str =
    ".traffic-e2e/local/startup/environment.json";
pub(crate) const LOCAL_STARTUP_MANIFEST_PATH: &str = ".traffic-e2e/local/startup/manifest.json";
pub(crate) const LOCAL_DATA_ROOT: &str = ".traffic-e2e/local/data";
pub(crate) const LOCAL_RUNTIME_OUTPUTS_ROOT: &str = ".traffic-e2e/local/runtime-outputs";

pub(crate) fn directory_name(target_root: &Path) -> Result<String> {
    let name = target_root
        .file_name()
        .and_then(|name| name.to_str())
        .context("target repository directory name must be valid UTF-8")?;
    ensure!(
        name.chars()
            .any(|character| character.is_ascii_alphanumeric()),
        "target repository directory name must contain a letter or digit"
    );
    Ok(name.to_string())
}
