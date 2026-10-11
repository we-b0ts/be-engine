use std::fs;
use std::path::Path;
use std::process::Command;

use super::*;
use crate::rewrite::{self, RewriteContext, RewriteNextOptions, next_rewrite, test_support};

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

fn target() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    test_support::install_project_config(
        root.path(),
        "master",
        test_support::managed_test_recorder(),
        None,
    );
    fs::write(
        root.path().join(".traffic-e2e/verification.yaml"),
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();
    fs::write(root.path().join(".gitignore"), "/.traffic-e2e/local/\n").unwrap();
    git(root.path(), &["init", "-q", "-b", "master"]);
    git(root.path(), &["config", "user.name", "Test"]);
    git(root.path(), &["config", "user.email", "test@example.com"]);
    git(root.path(), &["add", "."]);
    git(root.path(), &["commit", "-qm", "baseline"]);
    git(root.path(), &["switch", "-qc", "fixture-work"]);
    root
}

fn required(action: &RewriteAction) -> &[String] {
    match action {
        RewriteAction::InputRequired {
            reason: RewriteInputRequiredReason::ConfigurationCommitRequired,
            required,
            ..
        } => required,
        other => panic!("expected configuration commit gate, got {other:?}"),
    }
}

#[tokio::test]
async fn status_and_next_require_actual_commit_without_mutating_files_or_state() {
    let root = target();
    let store = RewriteStore::new(root.path()).unwrap();
    let state = test_support::test_state();
    store.save(&state).unwrap();
    let path = root.path().join(CONFIGURATION_PATHS[1]);
    let policy = format!(
        "{}\n# new recording rule\n",
        fs::read_to_string(&path).unwrap()
    );
    fs::write(&path, &policy).unwrap();
    let index = fs::read(root.path().join(".git/index")).unwrap();
    let state_before = serde_json::to_value(store.load().unwrap()).unwrap();
    let context = RewriteContext {
        target_root: root.path().to_path_buf(),
    };
    for status in [
        rewrite::status_rewrite(context.clone()).unwrap(),
        rewrite::status_rewrite_for_api(context.clone(), Some(&"GET /api".parse().unwrap()))
            .unwrap(),
    ] {
        assert_eq!(required(&status.action), &[CONFIGURATION_PATHS[1]]);
        assert!(!status.terminal_allowed);
    }
    let envelope = next_rewrite(RewriteNextOptions {
        target_root: root.path().to_path_buf(),
        api: None,
        source_route: None,
    })
    .await
    .unwrap();
    assert_eq!(required(&envelope.action), &[CONFIGURATION_PATHS[1]]);
    assert_eq!(
        serde_json::to_value(store.load().unwrap()).unwrap(),
        state_before
    );
    assert_eq!(fs::read(root.path().join(".git/index")).unwrap(), index);
    assert_eq!(fs::read_to_string(&path).unwrap(), policy);
    git(root.path(), &["add", "--", CONFIGURATION_PATHS[1]]);
    assert!(
        pending(root.path()).unwrap().is_some(),
        "staging is not a commit"
    );
    git(root.path(), &["commit", "-qm", "recording rule"]);
    assert!(pending(root.path()).unwrap().is_none());
    assert_eq!(
        serde_json::to_value(store.load().unwrap()).unwrap(),
        state_before
    );
}

#[test]
fn includes_new_deleted_staged_and_unstaged_configuration_but_excludes_progress_and_code() {
    let root = target();
    fs::write(
        root.path().join(".traffic-e2e/progress.yaml"),
        "generated progress\n",
    )
    .unwrap();
    fs::write(root.path().join("main.rs"), "new code\n").unwrap();
    assert!(pending(root.path()).unwrap().is_none());
    fs::remove_file(root.path().join(CONFIGURATION_PATHS[0])).unwrap();
    fs::write(root.path().join(CONFIGURATION_PATHS[1]), "new policy\n").unwrap();
    git(root.path(), &["add", "--", CONFIGURATION_PATHS[1]]);
    git(
        root.path(),
        &["rm", "--cached", "--", CONFIGURATION_PATHS[2]],
    );
    git(
        root.path(),
        &["commit", "-qm", "remove verification from index"],
    );
    // The source policy commit above is followed by a new unstaged edit.
    fs::write(root.path().join(CONFIGURATION_PATHS[1]), "another policy\n").unwrap();
    let envelope = pending(root.path()).unwrap().unwrap();
    let mut paths = required(&envelope.action).to_vec();
    paths.sort();
    assert_eq!(paths, CONFIGURATION_PATHS);
    let json = serde_json::to_value(envelope).unwrap();
    assert_eq!(
        json["action"]["details"]["reason"],
        "configuration_commit_required"
    );
    assert_eq!(json["action"]["kind"], "input_required");
}

#[test]
fn reports_configuration_paths_relative_to_a_nested_target() {
    let repository = tempfile::tempdir().unwrap();
    let target_root = repository.path().join("backend-rs-intra");
    test_support::install_project_config(
        &target_root,
        "master",
        test_support::managed_test_recorder(),
        None,
    );
    fs::write(
        target_root.join(".traffic-e2e/verification.yaml"),
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();
    fs::write(target_root.join(".gitignore"), "/.traffic-e2e/local/\n").unwrap();
    git(repository.path(), &["init", "-q", "-b", "master"]);
    git(repository.path(), &["config", "user.name", "Test"]);
    git(
        repository.path(),
        &["config", "user.email", "test@example.com"],
    );
    git(repository.path(), &["add", "."]);
    git(repository.path(), &["commit", "-qm", "baseline"]);

    fs::write(
        target_root.join(CONFIGURATION_PATHS[1]),
        "nested target policy change\n",
    )
    .unwrap();

    let envelope = pending(&target_root).unwrap().unwrap();
    assert_eq!(required(&envelope.action), &[CONFIGURATION_PATHS[1]]);
}

#[test]
fn checks_uninitialized_workflow_and_does_not_create_runtime_state() {
    let root = target();
    fs::write(
        root.path().join(CONFIGURATION_PATHS[0]),
        "invalid YAML also needs review\n",
    )
    .unwrap();
    let status = rewrite::status_rewrite(RewriteContext {
        target_root: root.path().into(),
    })
    .unwrap();
    assert!(!status.initialized);
    assert_eq!(required(&status.action), &[CONFIGURATION_PATHS[0]]);
    assert!(!root.path().join(".traffic-e2e/local").exists());
}

#[test]
fn live_coordinator_or_traffic_keeps_its_existing_wait_priority() {
    let root = target();
    fs::write(root.path().join(CONFIGURATION_PATHS[1]), "pending config\n").unwrap();
    let store = RewriteStore::new(root.path()).unwrap();
    let lock = store.try_lock().unwrap().unwrap();
    assert!(pending(root.path()).unwrap().is_none());
    assert!(pending_locked(root.path()).unwrap().is_some());
    drop(lock);
    let traffic = traffic_operation::claim_current(
        root.path(),
        "live-replay".into(),
        traffic_operation::TrafficOperationKind::Replay,
        Some("GET /api".into()),
    )
    .unwrap();
    assert!(pending(root.path()).unwrap().is_none());
    drop(traffic);
    assert!(pending(root.path()).unwrap().is_some());
}
