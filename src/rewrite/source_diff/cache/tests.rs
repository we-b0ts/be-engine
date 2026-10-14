use super::scope;
use crate::rewrite::source_diff::{git_text, resolve_pr_base};
use std::path::Path;
use std::process::Command;

fn git(root: &Path, args: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn repository(message: &str) -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    git(root.path(), &["init", "-qb", "base"]);
    git(root.path(), &["config", "user.name", "Test"]);
    git(root.path(), &["config", "user.email", "test@example.com"]);
    git(root.path(), &["commit", "--allow-empty", "-qm", message]);
    root
}

#[test]
fn snapshot_reuses_reads_and_refreshes_after_outer_scope() {
    let first = repository("first");
    let second = repository("second");
    let before = git_text(first.path(), &["rev-parse", "HEAD"]).unwrap();
    let other = git_text(second.path(), &["rev-parse", "HEAD"]).unwrap();
    assert_ne!(before, other);
    scope(|| {
        assert_eq!(
            git_text(first.path(), &["rev-parse", "HEAD"]).unwrap(),
            before
        );
        assert_eq!(
            git_text(second.path(), &["rev-parse", "HEAD"]).unwrap(),
            other
        );
        assert_eq!(
            git_text(first.path(), &["rev-parse", "--abbrev-ref", "HEAD"])
                .unwrap()
                .trim(),
            "base"
        );
        git(first.path(), &["commit", "--allow-empty", "-qm", "changed"]);
        scope(|| {
            assert_eq!(
                git_text(first.path(), &["rev-parse", "HEAD"]).unwrap(),
                before
            )
        });
        assert_eq!(
            git_text(first.path(), &["rev-parse", "HEAD"]).unwrap(),
            before
        );
    });
    let after = git_text(first.path(), &["rev-parse", "HEAD"]).unwrap();
    assert_ne!(before, after);
    scope(|| {
        assert_eq!(
            git_text(first.path(), &["rev-parse", "HEAD"]).unwrap(),
            after
        )
    });
}

#[test]
fn base_resolution_is_scoped_and_separated_by_repository_and_branch() {
    let first = repository("first");
    let second = repository("second");
    git(
        second.path(),
        &["update-ref", "refs/remotes/origin/base", "HEAD"],
    );
    git(second.path(), &["branch", "-m", "renamed"]);
    scope(|| {
        assert_eq!(
            resolve_pr_base(first.path(), "base").unwrap(),
            "refs/heads/base"
        );
        assert_eq!(
            resolve_pr_base(second.path(), "base").unwrap(),
            "refs/remotes/origin/base"
        );
        git(
            first.path(),
            &["update-ref", "refs/remotes/origin/base", "HEAD"],
        );
        git(first.path(), &["branch", "-m", "renamed"]);
        assert_eq!(
            resolve_pr_base(first.path(), "base").unwrap(),
            "refs/heads/base"
        );
        assert_eq!(
            resolve_pr_base(first.path(), "renamed").unwrap(),
            "refs/heads/renamed"
        );
    });
    scope(|| {
        assert_eq!(
            resolve_pr_base(first.path(), "base").unwrap(),
            "refs/remotes/origin/base"
        )
    });
}

#[test]
fn failures_are_not_cached_and_mutations_discard_reads() {
    let root = repository("first");
    scope(|| {
        assert!(git_text(root.path(), &["rev-parse", "refs/heads/later"]).is_err());
        assert!(resolve_pr_base(root.path(), "later").is_err());
        git(root.path(), &["update-ref", "refs/heads/later", "HEAD"]);
        assert!(git_text(root.path(), &["rev-parse", "refs/heads/later"]).is_ok());
        assert_eq!(
            resolve_pr_base(root.path(), "later").unwrap(),
            "refs/heads/later"
        );
        let before = git_text(root.path(), &["rev-parse", "HEAD"]).unwrap();
        git_text(root.path(), &["commit", "--allow-empty", "-qm", "changed"]).unwrap();
        assert_ne!(
            git_text(root.path(), &["rev-parse", "HEAD"]).unwrap(),
            before
        );
    });
}
