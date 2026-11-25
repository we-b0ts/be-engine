//! Final checks require frozen code and bind inherited Cargo configuration.
use super::*;

fn monorepo() -> (tempfile::TempDir, PathBuf) {
    let repository = tempfile::tempdir().unwrap();
    let root = repository.path().join("service");
    let shared = repository.path().join("shared");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&shared).unwrap();
    crate::workflow_test_support::install_project_config(
        &root,
        "master",
        crate::workflow_test_support::managed_test_recorder(),
        None,
    );
    crate::workflow_test_support::set_managed_paths(&root, &["../shared"]);
    fs::write(root.join("lib.rs"), "pub fn value() -> u8 { 1 }\n").unwrap();
    fs::write(shared.join("lib.rs"), "pub fn shared() {}\n").unwrap();
    fs::write(
        repository.path().join(".gitignore"),
        "/service/.traffic-e2e/local/\n",
    )
    .unwrap();
    fs::create_dir(repository.path().join(".cargo")).unwrap();
    fs::write(
        repository.path().join(".cargo/config.toml"),
        "[build]\njobs = 2\n",
    )
    .unwrap();
    fs::write(repository.path().join("Cargo.lock"), "version = 4\n").unwrap();
    fs::write(
        repository.path().join("rust-toolchain.toml"),
        "[toolchain]\nchannel = 'stable'\n",
    )
    .unwrap();
    git(repository.path(), &["init", "-qb", "master"]);
    git(
        repository.path(),
        &["config", "user.name", "Final Input Test"],
    );
    git(
        repository.path(),
        &["config", "user.email", "final-input@example.test"],
    );
    git(repository.path(), &["add", "."]);
    git(
        repository.path(),
        &["commit", "-qm", "monorepo build inputs"],
    );
    git(repository.path(), &["switch", "-qc", "feature"]);
    install_ready_state(&root, false);
    (repository, root)
}

fn dirty_source(root: &Path, kind: &str) {
    if kind == "untracked" {
        fs::write(root.join("additional.rs"), "pub fn untracked() {}\n").unwrap();
    } else {
        fs::write(root.join("lib.rs"), "pub fn value() -> u8 { 2 }\n").unwrap();
        if kind == "staged" {
            git(root, &["add", "lib.rs"]);
        }
    }
}

#[test]
fn final_check_rejects_staged_unstaged_and_untracked_candidate_code() {
    for kind in ["staged", "unstaged", "untracked"] {
        let target = target(false);
        let root = target.path();
        dirty_source(root, kind);
        let error = check_pre_revalidation(options(root, root)).unwrap_err();
        assert!(
            error.to_string().contains("commit the final candidate"),
            "{kind}: {error:#}"
        );
        assert!(load(root).pre_revalidation_review.is_none());
    }
}

#[test]
fn dirty_code_cannot_use_a_cached_final_check_or_be_admitted() {
    for kind in ["staged", "unstaged", "untracked"] {
        let target = target(false);
        let root = target.path();
        let report = check_pre_revalidation(options(root, root)).unwrap();
        dirty_source(root, kind);
        assert!(
            candidate::accept(root.into(), report.report_path).is_err(),
            "{kind}"
        );
        let error = check_pre_revalidation(options(root, root)).unwrap_err();
        assert!(
            error.to_string().contains("commit the final candidate"),
            "{kind}: {error:#}"
        );
        assert!(load(root).pre_revalidation_review.is_none());
    }
}

#[test]
fn final_check_freezes_managed_sibling_code_too() {
    for kind in ["staged", "unstaged", "untracked"] {
        let (_repository, root) = monorepo();
        let shared = root.parent().unwrap().join("shared");
        dirty_source(&shared, kind);
        let error = check_pre_revalidation(options(&root, &root)).unwrap_err();
        assert!(
            error.to_string().contains("commit the final candidate"),
            "{kind}: {error:#}"
        );
    }
}

#[test]
fn inherited_cargo_and_toolchain_inputs_bind_file_presence_and_content() {
    let (repository, root) = monorepo();
    let before = input_fingerprint(&root).unwrap();
    for name in [
        "Cargo.toml",
        "Cargo.lock",
        ".cargo/config",
        ".cargo/config.toml",
        "rust-toolchain",
        "rust-toolchain.toml",
    ] {
        let path = repository.path().join(name);
        let original = fs::read(&path).ok();
        fs::write(&path, "# a changed ancestor build input\n").unwrap();
        assert_ne!(input_fingerprint(&root).unwrap(), before, "{name}");
        if let Some(original) = original {
            fs::write(&path, original).unwrap();
        } else {
            fs::remove_file(&path).unwrap();
        }
        assert_eq!(input_fingerprint(&root).unwrap(), before, "restored {name}");
    }
}

#[test]
fn inherited_tracked_inputs_must_be_committed_and_stale_accepted_receipts() {
    let (repository, root) = monorepo();
    let report = accepted(&root);
    assert_eq!(
        report
            .validation
            .as_ref()
            .unwrap()
            .final_inputs_fingerprint
            .as_deref(),
        Some(input_fingerprint(&root).unwrap().as_str())
    );
    let state = load(&root);
    let code_before = fingerprint::code_fingerprint(&root).unwrap();
    for name in ["Cargo.lock", ".cargo/config.toml", "rust-toolchain.toml"] {
        let path = repository.path().join(name);
        let original = fs::read(&path).unwrap();
        let mut changed = original.clone();
        changed.extend_from_slice(b"\n# changed inherited input\n");
        fs::write(&path, changed).unwrap();
        assert_eq!(fingerprint::code_fingerprint(&root).unwrap(), code_before);
        assert!(!current(&root, &state), "{name}");
        let error = check_pre_revalidation(options(&root, &root)).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("commit changed Cargo and toolchain inputs"),
            "{name}: {error:#}"
        );
        fs::write(&path, original).unwrap();
        assert!(current(&root, &state), "restored {name}");
    }
    let lock = repository.path().join("Cargo.lock");
    fs::write(&lock, "version = 4\n# new committed dependency inputs\n").unwrap();
    git(repository.path(), &["add", "Cargo.lock"]);
    git(
        repository.path(),
        &["commit", "-qm", "change inherited lockfile"],
    );
    assert_eq!(fingerprint::code_fingerprint(&root).unwrap(), code_before);
    assert!(!current(&root, &state));
    assert!(matches!(
        required_action(&root, &state).unwrap(),
        Some(RewriteAction::PreRevalidationReviewRequired { .. })
    ));
}

#[test]
fn final_input_identity_is_portable_across_real_monorepo_worktrees() {
    let (repository, root) = monorepo();
    let directory = tempfile::tempdir().unwrap();
    let checkout = directory.path().join("integration");
    git(
        repository.path(),
        &[
            "worktree",
            "add",
            "-qb",
            "integration",
            checkout.to_str().unwrap(),
        ],
    );
    let other = checkout.join("service");
    assert_eq!(
        input_fingerprint(&root).unwrap(),
        input_fingerprint(&other).unwrap()
    );
    fs::write(checkout.join(".cargo/config.toml"), "[build]\njobs = 1\n").unwrap();
    assert_ne!(
        input_fingerprint(&root).unwrap(),
        input_fingerprint(&other).unwrap()
    );
}
