use std::path::Path;

use anyhow::{Context, Result, ensure};

pub(crate) const TRAFFIC_E2E_ROOT: &str = ".traffic-e2e";
pub(crate) const LOCAL_ROOT: &str = ".traffic-e2e/local";
pub(crate) const LOCAL_GITIGNORE_RULE: &str = "/.traffic-e2e/local/";
pub(crate) const LOCAL_ARTIFACTS_RELATIVE_ROOT: &str = "local/artifacts";
pub(crate) const LOCAL_ARTIFACTS_ROOT: &str = ".traffic-e2e/local/artifacts";
pub(crate) const LOCAL_BOOT_ROOT: &str = ".traffic-e2e/local/boot";
pub(crate) const LOCAL_DATA_ROOT: &str = ".traffic-e2e/local/data";

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
