use std::process::Command;

use super::*;

fn git(root: &Path, args: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn target(root: &Path) -> Repository {
    git(root, &["init", "-q", "-b", "dev-migration"]);
    git(
        root,
        &[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.com",
            "commit",
            "--allow-empty",
            "-qm",
            "base",
        ],
    );
    fs::write(root.join(".gitignore"), "/.traffic-e2e/local/\n").unwrap();
    let (branch, head) = git::checkout(root).unwrap();
    Repository {
        root: root.into(),
        branch,
        pr_base: "dev-migration".to_string(),
        head,
    }
}

#[test]
fn active_replay_blocks_confirmed_branch_switch() {
    let target = tempfile::tempdir().unwrap();
    let mut repo = self::target(target.path());
    let lock = repo.lock().unwrap();
    let active = open_lock(&internal_runtime::root(&repo.root).join("event-replay.lock")).unwrap();
    active.try_lock().unwrap();
    let error = repo
        .start_round(
            &lock,
            Recording {
                id: "20261125131020".to_owned(),
                root: target.path().to_owned(),
                identity: "fixture".to_owned(),
            },
            true,
            None,
        )
        .unwrap_err();
    assert!(error.to_string().contains("another event Replay is active"));
    assert!(repo.on_base());
    assert_eq!(
        git::checkout(&repo.root).unwrap().0.as_deref(),
        Some("dev-migration")
    );
    assert!(!repo.rounds_dir().exists());
}

#[test]
fn stale_checkout_and_concurrent_mutations_are_rejected() {
    let target = tempfile::tempdir().unwrap();
    let repo = self::target(target.path());
    let lock = repo.lock().unwrap();
    let error = repo.lock().err().expect("exclusive mutation lock");
    assert!(
        error
            .to_string()
            .contains("another be-replay operation is active")
    );
    drop(lock);
    git(&repo.root, &["switch", "-qc", "already-selected"]);
    let error = repo.lock().err().expect("checkout changed");
    assert!(error.to_string().contains("Target checkout changed"));
}
