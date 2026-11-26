use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, ensure};

mod cache;

pub const TRAFFIC_E2E_ROOT: &str = ".traffic-e2e";
pub const LOCAL_ROOT: &str = ".traffic-e2e/local";
pub const LOCAL_GITIGNORE_RULE: &str = "/.traffic-e2e/local/";
pub const LOCAL_ARTIFACTS_RELATIVE_ROOT: &str = "local/artifacts";
pub const LOCAL_ARTIFACTS_ROOT: &str = ".traffic-e2e/local/artifacts";
pub const LOCAL_STARTUP_ROOT: &str = ".traffic-e2e/local/startup";
pub const LOCAL_STARTUP_MOUNTS_ROOT: &str = ".traffic-e2e/local/startup/mounts";
pub const LOCAL_STARTUP_MANIFEST_PATH: &str = ".traffic-e2e/local/startup/manifest.json";
pub const LOCAL_SOURCE_ROOT: &str = ".traffic-e2e/local/source";
pub const LOCAL_SOURCE_MANIFEST_PATH: &str = ".traffic-e2e/local/source/manifest.json";
pub const LOCAL_TARGET_ENV_PATH: &str = ".traffic-e2e/local/target.env";
pub const LOCAL_DATA_ROOT: &str = ".traffic-e2e/local/data";
pub const LOCAL_SECRETS_ROOT: &str = ".traffic-e2e/local/secrets";
pub const LOCAL_ENCRYPTION_KEY_PATH: &str = ".traffic-e2e/local/secrets/traffic-e2e-enc.sec";
pub const LOCAL_ENCRYPTION_KEY_FROM_LOCAL: &str = "secrets/traffic-e2e-enc.sec";
pub const LOCAL_RUNTIME_OUTPUTS_ROOT: &str = ".traffic-e2e/local/runtime-outputs";

pub fn implementer_worktree(root: &Path, slot: usize) -> PathBuf {
    root.join(LOCAL_ROOT)
        .join("rewrite-worktrees")
        .join(format!("api-implementer-{slot}"))
}

pub fn directory_name(target_root: &Path) -> Result<String> {
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

pub fn git_root(path: &Path) -> Result<PathBuf> {
    if let Some(root) = cache::get(path) {
        return Ok(root);
    }
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
    let root =
        fs::canonicalize(root.trim()).context("failed to canonicalize Git repository root")?;
    cache::insert(path.to_path_buf(), root.clone());
    Ok(root)
}

pub fn with_git_root_cache<T>(operation: impl FnOnce() -> T) -> T {
    cache::scope(operation)
}
