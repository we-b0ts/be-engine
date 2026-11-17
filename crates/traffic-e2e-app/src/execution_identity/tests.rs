use std::fs;

use super::*;

#[test]
fn ids_are_stable_and_framed() {
    assert_eq!(id(&["ab", "c"]), id(&["ab", "c"]));
    assert_ne!(id(&["ab", "c"]), id(&["a", "bc"]));
}

#[test]
fn replay_timing_binds_execution_without_changing_target_or_code_identity() {
    let target = crate::test_support::configured_target();
    let root = target.path();
    let baseline = replay_identity(root).unwrap();
    let target_identity = repository_fingerprint(root).unwrap();
    let code_identity = code_fingerprint(root).unwrap();
    let regression = root.join(crate::config::regression::PATH);
    fs::write(
        &regression,
        "retry_failed_only: true\nreplay_interval_cap_ms: 100\n",
    )
    .unwrap();
    assert_eq!(replay_identity(root).unwrap(), baseline);
    fs::write(&regression, "replay_timing: fast\n").unwrap();
    let fast = replay_identity(root).unwrap();
    assert_ne!(fast, baseline);
    fs::write(
        &regression,
        "replay_timing: fast\nreplay_interval_cap_ms: 0\n",
    )
    .unwrap();
    assert_ne!(replay_identity(root).unwrap(), fast);
    fs::write(&regression, "replay_timing: recorded\n").unwrap();
    let recorded = replay_identity(root).unwrap();
    assert_ne!(recorded, fast);
    assert_ne!(recorded, baseline);
    fs::write(
        &regression,
        "replay_timing: recorded\nreplay_interval_cap_ms: 0\n",
    )
    .unwrap();
    assert_eq!(replay_identity(root).unwrap(), recorded);
    assert_eq!(repository_fingerprint(root).unwrap(), target_identity);
    assert_eq!(code_fingerprint(root).unwrap(), code_identity);
}

#[test]
fn repository_fingerprint_ignores_runner_progress_but_tracks_policy_and_source() {
    let repository = tempfile::tempdir().unwrap();
    fs::create_dir_all(repository.path().join(".traffic-e2e")).unwrap();
    fs::create_dir_all(repository.path().join("src")).unwrap();
    fs::write(
        repository.path().join("src/lib.rs"),
        "pub fn value() -> u8 { 1 }\n",
    )
    .unwrap();
    fs::write(
        repository.path().join(".traffic-e2e/policy.yaml"),
        "version: 2\n",
    )
    .unwrap();
    for name in ["progress.yaml", "replay-progress.yaml", "e2e-progress.yaml"] {
        fs::write(
            repository.path().join(".traffic-e2e").join(name),
            "attempt: 1\n",
        )
        .unwrap();
    }
    git_ok(repository.path(), &["init"]);
    git_ok(
        repository.path(),
        &["config", "user.email", "test@example.com"],
    );
    git_ok(
        repository.path(),
        &["config", "user.name", "Traffic E2E Test"],
    );
    git_ok(repository.path(), &["add", "."]);
    git_ok(repository.path(), &["commit", "-m", "baseline"]);

    let baseline = repository_fingerprint(repository.path()).unwrap();
    let regression = repository.path().join(crate::config::regression::PATH);
    fs::write(&regression, "").unwrap();
    assert_eq!(repository_fingerprint(repository.path()).unwrap(), baseline);
    let code = code_fingerprint(repository.path()).unwrap();
    git_ok(repository.path(), &["add", crate::config::regression::PATH]);
    git_ok(
        repository.path(),
        &["commit", "-m", "track local regression policy"],
    );
    fs::write(
        &regression,
        "recording_run_id: \"20260911093000\"\nskip: [/a]\n",
    )
    .unwrap();
    assert_eq!(repository_fingerprint(repository.path()).unwrap(), baseline);
    assert_eq!(code_fingerprint(repository.path()).unwrap(), code);
    fs::remove_file(&regression).unwrap();
    assert_eq!(repository_fingerprint(repository.path()).unwrap(), baseline);
    for name in ["progress.yaml", "replay-progress.yaml", "e2e-progress.yaml"] {
        fs::write(
            repository.path().join(".traffic-e2e").join(name),
            "attempt: 2\n",
        )
        .unwrap();
    }
    assert_eq!(repository_fingerprint(repository.path()).unwrap(), baseline);

    let local_artifacts = repository.path().join(".traffic-e2e/local/artifacts");
    fs::create_dir_all(&local_artifacts).unwrap();
    fs::write(local_artifacts.join("runtime.jsonl"), "local evidence\n").unwrap();
    assert_eq!(repository_fingerprint(repository.path()).unwrap(), baseline);

    fs::write(
        repository.path().join(".traffic-e2e/policy.yaml"),
        "version: 2\nresponses: changed\n",
    )
    .unwrap();
    assert_ne!(repository_fingerprint(repository.path()).unwrap(), baseline);

    git_ok(
        repository.path(),
        &["checkout", "--", ".traffic-e2e/policy.yaml"],
    );
    fs::write(
        repository.path().join("src/lib.rs"),
        "pub fn value() -> u8 { 2 }\n",
    )
    .unwrap();
    let dirty_source = repository_fingerprint(repository.path()).unwrap();
    assert_ne!(dirty_source, baseline);

    git_ok(repository.path(), &["add", "src/lib.rs"]);
    git_ok(repository.path(), &["commit", "-m", "change source"]);
    assert_eq!(
        repository_fingerprint(repository.path()).unwrap(),
        dirty_source
    );

    fs::write(
        repository.path().join("src/new.rs"),
        "pub const NEW: u8 = 1;\n",
    )
    .unwrap();
    let dirty_new_file = repository_fingerprint(repository.path()).unwrap();
    git_ok(repository.path(), &["add", "src/new.rs"]);
    git_ok(repository.path(), &["commit", "-m", "add source"]);
    assert_eq!(
        repository_fingerprint(repository.path()).unwrap(),
        dirty_new_file
    );

    fs::remove_file(repository.path().join("src/new.rs")).unwrap();
    let dirty_deletion = repository_fingerprint(repository.path()).unwrap();
    git_ok(repository.path(), &["add", "--update"]);
    git_ok(repository.path(), &["commit", "-m", "remove source"]);
    assert_eq!(
        repository_fingerprint(repository.path()).unwrap(),
        dirty_deletion
    );
}

#[test]
fn traffic_policy_changes_affect_verification_but_not_review() {
    for policy_name in [".traffic-e2e/policy.yaml", "contracts/rules.yaml"] {
        assert_traffic_policy_fingerprints(policy_name);
    }
}

fn assert_traffic_policy_fingerprints(policy_name: &str) {
    let repository = tempfile::tempdir().unwrap();
    let root = repository.path();
    fs::create_dir_all(root.join(".traffic-e2e")).unwrap();
    fs::write(root.join("lib.rs"), "pub fn value() {}\n").unwrap();
    crate::test_support::install_project_config(
        root,
        "integration",
        crate::test_support::managed_test_recorder(),
        None,
    );
    let project = root.join(".traffic-e2e/project.yaml");
    let mut document: serde_yaml::Value =
        serde_yaml::from_str(&fs::read_to_string(&project).unwrap()).unwrap();
    document["project"]["policy"] = serde_yaml::Value::String(policy_name.into());
    fs::write(&project, serde_yaml::to_string(&document).unwrap()).unwrap();
    fs::remove_file(root.join(".traffic-e2e/policy.yaml")).unwrap();
    let policy = root.join(policy_name);
    fs::create_dir_all(policy.parent().unwrap()).unwrap();
    git_ok(root, &["init", "-q", "-b", "integration"]);
    git_ok(root, &["config", "user.email", "test@example.com"]);
    git_ok(root, &["config", "user.name", "Test"]);
    git_ok(root, &["add", "."]);
    git_ok(root, &["commit", "-qm", "baseline"]);
    let revision = String::from_utf8(git_bytes(root, &["rev-parse", "HEAD"]).unwrap()).unwrap();
    let revision = revision.trim();
    let code = code_fingerprint(root).unwrap();
    let review = review_fingerprint(root).unwrap();
    let verification = repository_fingerprint(root).unwrap();
    let policy = root.join(policy_name);
    fs::write(&policy, "version: 2\n").unwrap();
    let with_policy = repository_fingerprint(root).unwrap();
    for stage in ["untracked", "staged", "committed", "modified", "deleted"] {
        match stage {
            "staged" => git_ok(root, &["add", "."]),
            "committed" => git_ok(root, &["commit", "-qm", "source policy"]),
            "modified" => fs::write(&policy, "version: 2\nhttp: {}\n").unwrap(),
            "deleted" => fs::remove_file(&policy).unwrap(),
            _ => {}
        }
        with_repository_cache(|| {
            assert_ne!(
                repository_fingerprint(root).unwrap(),
                if stage == "deleted" {
                    &with_policy
                } else {
                    &verification
                }
                .as_str(),
                "{stage}"
            );
            assert_eq!(code_fingerprint(root).unwrap(), code, "{stage}");
            assert_eq!(review_fingerprint(root).unwrap(), review, "{stage}");
            assert!(matches_revision(root, revision).unwrap(), "{stage}");
        });
    }
    fs::write(root.join("lib.rs"), "pub fn changed() {}\n").unwrap();
    assert_ne!(code_fingerprint(root).unwrap(), code);
    assert_ne!(review_fingerprint(root).unwrap(), review);
    assert!(!matches_revision(root, revision).unwrap());
}

#[test]
fn code_fingerprint_tracks_configured_managed_sibling() {
    let repository = tempfile::tempdir().unwrap();
    let target = repository.path().join("backend-rs-intra");
    let sibling = repository.path().join("backend-rs");
    fs::create_dir_all(target.join("src")).unwrap();
    fs::create_dir_all(sibling.join("src")).unwrap();
    crate::test_support::install_project_config(
        &target,
        "integration",
        crate::test_support::managed_test_recorder(),
        Some(serde_json::json!([])),
    );
    crate::test_support::set_managed_paths(&target, &["../backend-rs"]);
    fs::write(target.join("src/lib.rs"), "pub fn private() {}\n").unwrap();
    fs::write(sibling.join("src/lib.rs"), "pub fn public() {}\n").unwrap();
    git_ok(repository.path(), &["init", "-q", "-b", "integration"]);
    git_ok(
        repository.path(),
        &["config", "user.email", "test@example.com"],
    );
    git_ok(
        repository.path(),
        &["config", "user.name", "Traffic E2E Test"],
    );
    git_ok(repository.path(), &["add", "."]);
    git_ok(repository.path(), &["commit", "-m", "baseline"]);

    let baseline = code_fingerprint(&target).unwrap();
    fs::write(
        sibling.join("src/lib.rs"),
        "pub fn public() { println!(\"changed\"); }\n",
    )
    .unwrap();

    assert_ne!(code_fingerprint(&target).unwrap(), baseline);
}

#[test]
fn repository_cache_is_stable_only_inside_its_read_scope() {
    let repository = tempfile::tempdir().unwrap();
    fs::create_dir_all(repository.path().join("src")).unwrap();
    fs::write(
        repository.path().join("src/lib.rs"),
        "pub fn value() -> u8 { 1 }\n",
    )
    .unwrap();
    git_ok(repository.path(), &["init", "-q"]);
    git_ok(
        repository.path(),
        &["config", "user.email", "test@example.com"],
    );
    git_ok(
        repository.path(),
        &["config", "user.name", "Traffic E2E Test"],
    );
    git_ok(repository.path(), &["add", "."]);
    git_ok(repository.path(), &["commit", "-m", "baseline"]);

    let revision =
        String::from_utf8(git_bytes(repository.path(), &["rev-parse", "HEAD"]).unwrap()).unwrap();
    let revision = revision.trim();
    let (repository_before, code_before) = with_repository_cache(|| {
        let repository_before = repository_fingerprint(repository.path()).unwrap();
        let code_before = code_fingerprint(repository.path()).unwrap();
        assert!(matches_revision(repository.path(), revision).unwrap());
        fs::write(
            repository.path().join("src/lib.rs"),
            "pub fn value() -> u8 { 2 }\n",
        )
        .unwrap();

        assert_eq!(
            repository_fingerprint(repository.path()).unwrap(),
            repository_before
        );
        assert_eq!(code_fingerprint(repository.path()).unwrap(), code_before);
        with_repository_cache(|| {
            assert!(matches_revision(repository.path(), revision).unwrap());
        });
        assert!(matches_revision(repository.path(), revision).unwrap());
        (repository_before, code_before)
    });

    assert_ne!(
        repository_fingerprint(repository.path()).unwrap(),
        repository_before
    );
    assert_ne!(code_fingerprint(repository.path()).unwrap(), code_before);
    assert!(!matches_revision(repository.path(), revision).unwrap());
    with_repository_cache(|| {
        assert!(!matches_revision(repository.path(), revision).unwrap());
    });
    fs::write(
        repository.path().join("src/lib.rs"),
        "pub fn value() -> u8 { 1 }\n",
    )
    .unwrap();
    with_repository_cache(|| {
        assert!(matches_revision(repository.path(), revision).unwrap());
    });
}

#[test]
fn revision_match_cache_separates_roots_and_revisions() {
    let repository = tempfile::tempdir().unwrap();
    let first = repository.path().join("first");
    let second = repository.path().join("second");
    for root in [&first, &second] {
        fs::create_dir(root).unwrap();
        fs::write(root.join("lib.rs"), "pub fn original() {}\n").unwrap();
    }
    git_ok(repository.path(), &["init", "-q"]);
    git_ok(
        repository.path(),
        &["config", "user.email", "test@example.com"],
    );
    git_ok(repository.path(), &["config", "user.name", "Test"]);
    git_ok(repository.path(), &["add", "."]);
    git_ok(repository.path(), &["commit", "-qm", "baseline"]);
    let baseline =
        String::from_utf8(git_bytes(repository.path(), &["rev-parse", "HEAD"]).unwrap()).unwrap();
    fs::write(first.join("lib.rs"), "pub fn changed() {}\n").unwrap();
    git_ok(repository.path(), &["add", "."]);
    git_ok(repository.path(), &["commit", "-qm", "change first"]);
    let current =
        String::from_utf8(git_bytes(repository.path(), &["rev-parse", "HEAD"]).unwrap()).unwrap();
    with_repository_cache(|| {
        assert!(!matches_revision(&first, baseline.trim()).unwrap());
        assert!(matches_revision(&second, baseline.trim()).unwrap());
        assert!(matches_revision(&first, current.trim()).unwrap());
        assert!(!matches_revision(&first, baseline.trim()).unwrap());
    });
}

fn git_ok(repository: &Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(args)
        .status()
        .unwrap();
    assert!(status.success(), "git command failed: {args:?}");
}
