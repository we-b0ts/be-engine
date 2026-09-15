use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, ensure};

pub(crate) const TRAFFIC_E2E_ROOT: &str = ".traffic-e2e";
pub(crate) const LOCAL_ROOT: &str = ".traffic-e2e/local";
pub(crate) const LOCAL_GITIGNORE_RULE: &str = "/.traffic-e2e/local/";
pub(crate) const LOCAL_ARTIFACTS_RELATIVE_ROOT: &str = "local/artifacts";
pub(crate) const LOCAL_ARTIFACTS_ROOT: &str = ".traffic-e2e/local/artifacts";
pub(crate) const LOCAL_STARTUP_ROOT: &str = ".traffic-e2e/local/startup";
pub(crate) const LOCAL_STARTUP_MOUNTS_ROOT: &str = ".traffic-e2e/local/startup/mounts";
pub(crate) const LOCAL_STARTUP_MANIFEST_PATH: &str = ".traffic-e2e/local/startup/manifest.json";
pub(crate) const LOCAL_SOURCE_ROOT: &str = ".traffic-e2e/local/source";
pub(crate) const LOCAL_SOURCE_MANIFEST_PATH: &str = ".traffic-e2e/local/source/manifest.json";
pub(crate) const LOCAL_TARGET_ENV_PATH: &str = ".traffic-e2e/local/target.env";
pub(crate) const LOCAL_DATA_ROOT: &str = ".traffic-e2e/local/data";
pub(crate) const LOCAL_SECRETS_ROOT: &str = ".traffic-e2e/local/secrets";
pub(crate) const LOCAL_ENCRYPTION_KEY_PATH: &str = ".traffic-e2e/local/secrets/traffic-e2e-enc.sec";
pub(crate) const LOCAL_ENCRYPTION_KEY_FROM_LOCAL: &str = "secrets/traffic-e2e-enc.sec";
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

pub(crate) fn git_root(path: &Path) -> Result<PathBuf> {
    let output = Command::new("git")
        .arg("-C")
        .arg(path)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .context("failed to resolve Git repository root")?;
    ensure!(
        output.status.success(),
        "failed to resolve Git repository root: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let root = String::from_utf8(output.stdout).context("Git repository root is not UTF-8")?;
    fs::canonicalize(root.trim()).context("failed to canonicalize Git repository root")
}
