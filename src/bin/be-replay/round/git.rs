//! Git checkout checks and allocation for regression work branches.
use std::{
    path::Path,
    process::{Command, Output},
};

use anyhow::{Context, Result, ensure};

pub(super) fn checkout(root: &Path) -> Result<(Option<String>, String)> {
    let branch = git(root)
        .args(["symbolic-ref", "--quiet", "HEAD"])
        .output()?;
    let branch = if branch.status.code() == Some(1) {
        None
    } else {
        Some(
            output(branch)?
                .trim()
                .strip_prefix("refs/heads/")
                .context("Target HEAD does not point to a local branch")?
                .to_string(),
        )
    };
    let head = output(git(root).args(["rev-parse", "--verify", "HEAD"]).output()?)?;
    Ok((branch, head.trim().to_string()))
}

pub(super) fn require_ignored(root: &Path, runtime: &Path) -> Result<()> {
    let probe = runtime.strip_prefix(root)?.join(".ignore-check");
    let status = git(root)
        .args(["check-ignore", "-q", "--"])
        .arg(probe)
        .status()?;
    ensure!(
        status.success(),
        "{} must be ignored by Git",
        runtime.display()
    );
    Ok(())
}

pub(super) fn next_branch(root: &Path, has_round: impl Fn(&str) -> bool) -> Result<String> {
    let date = chrono::Local::now().format("%Y%m%d");
    let prefix = format!("codex/replay/{date}-");
    let refs = output(
        git(root)
            .args([
                "for-each-ref",
                "--format=%(refname)",
                "refs/heads/",
                "refs/remotes/",
            ])
            .output()?,
    )?;
    allocate_branch(&prefix, &refs, has_round)
}

fn allocate_branch(prefix: &str, refs: &str, has_round: impl Fn(&str) -> bool) -> Result<String> {
    let local = format!("refs/heads/{prefix}");
    let remote_suffix = format!("/{prefix}");
    let mut sequence = refs
        .lines()
        .filter_map(|reference| {
            reference
                .strip_prefix(&local)
                .or_else(|| {
                    reference
                        .strip_prefix("refs/remotes/")?
                        .rsplit_once(&remote_suffix)
                        .map(|(_, suffix)| suffix)
                })?
                .parse::<u64>()
                .ok()
        })
        .max()
        .unwrap_or_default();
    loop {
        sequence = sequence
            .checked_add(1)
            .context("Replay branch sequence exhausted")?;
        let branch = format!("{prefix}{sequence}");
        if !has_round(&branch) {
            return Ok(branch);
        }
    }
}

pub(super) fn switch(root: &Path, branch: &str, head: &str) -> Result<()> {
    output(
        git(root)
            .args(["switch", "--quiet", "-c", branch, head])
            .output()?,
    )?;
    Ok(())
}

fn git(root: &Path) -> Command {
    let mut command = Command::new("git");
    command.arg("-C").arg(root);
    command
}

fn output(result: Output) -> Result<String> {
    ensure!(
        result.status.success(),
        "Git failed: {}",
        String::from_utf8_lossy(&result.stderr).trim()
    );
    String::from_utf8(result.stdout).context("Git output was not UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_name_skips_remote_refs_and_prepared_rounds() {
        let prefix = "codex/replay/20261125-";
        let refs = "refs/heads/codex/replay/20261125-2\nrefs/remotes/origin/codex/replay/20261125-5\nrefs/heads/codex/replay/20261124-8\n";
        let branch =
            allocate_branch(prefix, refs, |branch| branch == "codex/replay/20261125-6").unwrap();
        assert_eq!(branch, "codex/replay/20261125-7");
    }
}
