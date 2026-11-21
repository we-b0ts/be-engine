use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, ensure};

pub fn validate_pr_base(target_root: &Path, branch: &str) -> Result<()> {
    ensure!(
        branch == branch.trim() && !branch.is_empty(),
        "pr_base must be a non-empty branch name without surrounding whitespace"
    );
    let valid = Command::new("git")
        .arg("-C")
        .arg(target_root)
        .arg("check-ref-format")
        .arg("--branch")
        .arg(branch)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("failed to validate pr_base with git")?;
    ensure!(
        valid.success(),
        "pr_base is not a valid Git branch name: {branch}"
    );
    let local = git_ref_exists(target_root, &format!("refs/heads/{branch}^{{commit}}"))?;
    let remote = git_ref_exists(
        target_root,
        &format!("refs/remotes/origin/{branch}^{{commit}}"),
    )?;
    ensure!(
        local || remote,
        "pr_base {branch:?} does not exist as a local branch or origin remote-tracking branch"
    );
    Ok(())
}

pub fn require_work_branch(target_root: &Path, pr_base: &str) -> Result<()> {
    let output = Command::new("git")
        .arg("-C")
        .arg(target_root)
        .args(["symbolic-ref", "--quiet", "--short", "HEAD"])
        .output()
        .context("failed to resolve current Git branch")?;
    ensure!(
        output.status.success(),
        "migration write commands require a named feature branch; detached HEAD is not allowed"
    );
    let current = String::from_utf8(output.stdout)
        .context("current Git branch is not UTF-8")?
        .trim()
        .to_string();
    ensure!(
        !current.is_empty() && current != pr_base,
        "pr_base {pr_base:?} is only the pull-request target; switch to a feature branch"
    );
    Ok(())
}

fn git_ref_exists(target_root: &Path, reference: &str) -> Result<bool> {
    let status = Command::new("git")
        .arg("-C")
        .arg(target_root)
        .arg("rev-parse")
        .arg("--verify")
        .arg("--quiet")
        .arg(reference)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| format!("failed to resolve Git reference {reference}"))?;
    Ok(status.success())
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    fn target() -> TempDir {
        let target = tempfile::tempdir().unwrap();
        assert!(
            Command::new("git")
                .args(["init", "-q", "-b", "integration"])
                .arg(target.path())
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(target.path())
                .args([
                    "-c",
                    "user.name=E2E Test",
                    "-c",
                    "user.email=e2e-test@example.invalid",
                    "commit",
                    "--allow-empty",
                    "-q",
                    "-m",
                    "initial",
                ])
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(target.path())
                .args(["switch", "-q", "-c", "feature"])
                .status()
                .unwrap()
                .success()
        );
        target
    }

    #[test]
    fn rejects_pr_base() {
        let target = target();
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(target.path())
                .args(["switch", "-q", "integration"])
                .status()
                .unwrap()
                .success()
        );

        let error = require_work_branch(target.path(), "integration").unwrap_err();

        assert!(error.to_string().contains("only the pull-request target"));
    }

    #[test]
    fn rejects_detached_head() {
        let target = target();
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(target.path())
                .args(["checkout", "-q", "--detach"])
                .status()
                .unwrap()
                .success()
        );

        let error = require_work_branch(target.path(), "integration").unwrap_err();

        assert!(error.to_string().contains("detached HEAD"));
    }

    #[test]
    fn accepts_feature_branch() {
        let target = target();

        require_work_branch(target.path(), "integration").unwrap();
    }
}
