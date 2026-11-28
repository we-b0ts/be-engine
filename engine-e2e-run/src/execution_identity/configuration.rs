//! Git state of managed project configuration.
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};

#[derive(Debug)]
pub struct ConfigurationChange {
    pub path: String,
    pub status: String,
}

/// Return staged, unstaged and untracked changes to managed configuration.
/// Paths are relative to the Target, which may be nested in a Git checkout.
pub fn configuration_changes(target_root: &Path) -> Result<Vec<ConfigurationChange>> {
    let target_root = std::fs::canonicalize(target_root)?;
    let target_prefix = git_target_prefix(&target_root)?;
    let paths = configuration_paths(&target_root)?;
    let output = Command::new("git")
        .arg("--no-optional-locks")
        .arg("-C")
        .arg(&target_root)
        .args([
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignored=matching",
            "--no-renames",
            "-z",
            "--",
        ])
        .args(paths.iter().map(|path| format!(":(literal){path}")))
        .output()
        .context("failed to inspect managed configuration changes")?;
    ensure!(
        output.status.success(),
        "cannot inspect managed configuration changes: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
        .map(|record| {
            let line = std::str::from_utf8(record)?;
            let path = line.get(3..).context("invalid Git configuration status")?;
            let path = path
                .strip_prefix(&target_prefix)
                .with_context(|| format!("unexpected configuration path {path:?}"))?;
            ensure!(
                paths.iter().any(|configured| configured == path),
                "unexpected configuration path {path:?}"
            );
            Ok(ConfigurationChange {
                path: path.to_owned(),
                status: line[..2].to_owned(),
            })
        })
        .collect()
}

/// Compare revisions across the Git checkout, excluding managed Target configuration.
pub fn configuration_only_between(target_root: &Path, from: &str, to: &str) -> Result<bool> {
    if from == to {
        return Ok(true);
    }
    let target_root = std::fs::canonicalize(target_root)?;
    let target_prefix = git_target_prefix(&target_root)?;
    let paths = configuration_paths(&target_root)?;
    let output = Command::new("git")
        .arg("--no-optional-locks")
        .arg("-C")
        .arg(&target_root)
        .args([
            "diff",
            "--quiet",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--ignore-submodules=none",
            "--end-of-options",
            from,
            to,
            "--",
            ":/",
        ])
        .args(
            paths
                .iter()
                .map(|path| format!(":(top,literal,exclude){target_prefix}{path}")),
        )
        .output()
        .context("failed to compare revisions outside managed configuration")?;
    match output.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => bail!(
            "cannot compare revisions outside managed configuration: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ),
    }
}

fn configuration_paths(target_root: &Path) -> Result<Vec<String>> {
    let mut paths = vec![
        ".traffic-e2e/project.yaml".to_owned(),
        crate::config::api_catalog::PATH.to_owned(),
    ];
    // A malformed or deleted project still needs the configuration commit gate.
    // Validation reports the parse failure after that review boundary.
    let policy = super::policy_file(target_root)
        .unwrap_or_else(|_| target_root.join(".traffic-e2e/policy.yaml"));
    let relative = policy
        .strip_prefix(target_root)
        .context("traffic policy is outside the target repository")?;
    paths.push(
        relative
            .to_str()
            .context("traffic policy path is not UTF-8")?
            .to_owned(),
    );
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn git_target_prefix(target_root: &Path) -> Result<String> {
    let output = Command::new("git")
        .arg("--no-optional-locks")
        .arg("-C")
        .arg(target_root)
        .args(["rev-parse", "--show-prefix"])
        .output()
        .context("failed to resolve managed configuration Git prefix")?;
    ensure!(
        output.status.success(),
        "cannot resolve managed configuration Git prefix: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let prefix = String::from_utf8(output.stdout)?;
    let prefix = prefix.strip_suffix('\n').unwrap_or(&prefix);
    let prefix = prefix.strip_suffix('\r').unwrap_or(prefix);
    Ok(prefix.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn revision_comparison_excludes_only_the_nested_targets_configuration() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let root = temp.path();
        let target = root.join("nested");
        let config = target.join(".traffic-e2e");
        fs::create_dir_all(&config)?;
        let policy = config.join("policy.yaml");
        let other_policy = root.join(".traffic-e2e/policy.yaml");
        fs::create_dir_all(other_policy.parent().unwrap())?;
        fs::write(&policy, "# original Target policy\n")?;
        fs::write(&other_policy, "# other policy\n")?;
        let git = |args: &[&str]| -> Result<()> {
            let result = Command::new("git")
                .arg("-C")
                .arg(root)
                .args(args)
                .output()?;
            ensure!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            Ok(())
        };
        git(&["init", "-q"])?;
        git(&["config", "user.name", "Test"])?;
        git(&["config", "user.email", "test@example.com"])?;
        git(&["add", "."])?;
        git(&["commit", "-qm", "baseline"])?;

        fs::write(&policy, "# updated Target policy\n")?;
        let changes = configuration_changes(&target)?;
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].path, ".traffic-e2e/policy.yaml");
        assert_eq!(changes[0].status, " M");
        git(&["commit", "-qam", "reviewed policy"])?;
        assert!(configuration_only_between(&target, "HEAD^", "HEAD")?);

        fs::write(&other_policy, "# changed outside Target\n")?;
        git(&["commit", "-qam", "change in the rest of the checkout"])?;
        assert!(!configuration_only_between(&target, "HEAD^", "HEAD")?);
        Ok(())
    }
}
