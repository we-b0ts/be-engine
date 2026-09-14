use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, ensure};

/// Map either a Git worktree root or its target-project directory onto the
/// directory corresponding to the canonical target root.
pub(in crate::rewrite) fn project_root_in_worktree(
    canonical_target_root: &Path,
    supplied_worktree: &Path,
) -> Result<PathBuf> {
    let canonical = Layout::resolve(canonical_target_root)?;
    let supplied_worktree = fs::canonicalize(supplied_worktree).with_context(|| {
        format!(
            "failed to resolve review worktree {}",
            supplied_worktree.display()
        )
    })?;
    let worktree_repository = repository_root(&supplied_worktree)?;
    let supplied_prefix = supplied_worktree
        .strip_prefix(&worktree_repository)
        .context("review worktree is outside its Git repository")?;
    if supplied_prefix == canonical.prefix {
        return Ok(supplied_worktree);
    }
    ensure!(
        supplied_prefix.as_os_str().is_empty(),
        "review worktree must be either the Git worktree root or target project path {:?}",
        canonical.prefix
    );
    let project_root = worktree_repository.join(&canonical.prefix);
    let project_root = fs::canonicalize(&project_root).with_context(|| {
        format!(
            "review worktree does not contain target project {:?}",
            canonical.prefix
        )
    })?;
    ensure!(
        project_root.is_dir(),
        "review target project must be a directory: {}",
        project_root.display()
    );
    Ok(project_root)
}

/// Convert a target-project-relative path into the tree path accepted by
/// `git show REV:path` in the containing repository.
pub(in crate::rewrite) fn git_object_path(
    target_root: &Path,
    project_relative: &Path,
) -> Result<PathBuf> {
    let layout = Layout::resolve(target_root)?;
    ensure!(
        !project_relative.is_absolute(),
        "target source path must be relative"
    );
    Ok(layout.prefix.join(project_relative))
}

struct Layout {
    prefix: PathBuf,
}

impl Layout {
    fn resolve(target_root: &Path) -> Result<Self> {
        let target_root = fs::canonicalize(target_root)
            .with_context(|| format!("failed to resolve target root {}", target_root.display()))?;
        let repository_root = repository_root(&target_root)?;
        let prefix = target_root
            .strip_prefix(&repository_root)
            .context("target root is outside its Git repository")?
            .to_path_buf();
        Ok(Self { prefix })
    }
}

fn repository_root(path: &Path) -> Result<PathBuf> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_repository_worktree_to_the_nested_target_project() {
        let repository = tempfile::tempdir().unwrap();
        let target = repository.path().join("services/backend");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("tracked"), "baseline\n").unwrap();
        git(repository.path(), &["init", "-q", "-b", "main"]);
        git(repository.path(), &["add", "."]);
        commit(repository.path());

        let worktrees = tempfile::tempdir().unwrap();
        let worktree = worktrees.path().join("worker");
        git(
            repository.path(),
            &[
                "worktree",
                "add",
                "-qb",
                "worker",
                worktree.to_str().unwrap(),
            ],
        );

        assert_eq!(
            project_root_in_worktree(&target, &worktree).unwrap(),
            worktree.join("services/backend")
        );
        assert_eq!(
            project_root_in_worktree(&target, &worktree.join("services/backend")).unwrap(),
            worktree.join("services/backend")
        );
        assert_eq!(
            git_object_path(&target, Path::new("src/main.rs")).unwrap(),
            Path::new("services/backend/src/main.rs")
        );
    }

    #[test]
    fn preserves_an_independent_repository_worktree_root() {
        let repository = tempfile::tempdir().unwrap();
        fs::write(repository.path().join("tracked"), "baseline\n").unwrap();
        git(repository.path(), &["init", "-q", "-b", "main"]);
        git(repository.path(), &["add", "."]);
        commit(repository.path());

        assert_eq!(
            project_root_in_worktree(repository.path(), repository.path()).unwrap(),
            fs::canonicalize(repository.path()).unwrap()
        );
        assert_eq!(
            git_object_path(repository.path(), Path::new("src/main.rs")).unwrap(),
            Path::new("src/main.rs")
        );
    }

    fn commit(repository: &Path) {
        let output = Command::new("git")
            .arg("-C")
            .arg(repository)
            .args([
                "-c",
                "user.name=Traffic E2E Test",
                "-c",
                "user.email=test@example.com",
                "commit",
                "-qm",
                "baseline",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn git(repository: &Path, args: &[&str]) {
        let output = Command::new("git")
            .arg("-C")
            .arg(repository)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
