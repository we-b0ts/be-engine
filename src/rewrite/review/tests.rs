use super::*;
use crate::rewrite::worker::tests::{configured_target, implementation_state_with_inventory};

pub(in crate::rewrite) fn worker_report(root: &Path, scope: RewriteWorkScope) -> PathBuf {
    check(RewriteReviewOptions {
        target_root: root.into(),
        worktree: Some(root.into()),
        scope: Some(scope),
        evidence: None,
        integration: false,
        handoff_id: None,
        hardcode_ai_verified: Vec::new(),
    })
    .map(|report| report.report_path)
    .unwrap_or_else(|_| root.join("missing-review.json"))
}

fn setup() -> (tempfile::TempDir, RewriteWorkScope) {
    let target = configured_target();
    git(target.path(), &["switch", "-qc", "coordinator"]);
    let state = implementation_state_with_inventory(false);
    let scope = RewriteWorkScope::Api {
        api: crate::rewrite::api_selector::public_api(&state.api).to_string(),
    };
    RewriteStore::new(target.path())
        .unwrap()
        .save(&state)
        .unwrap();
    worker::confirm(super::super::RewriteWorkerConfirmOptions {
        target_root: target.path().into(),
        work_scope: scope.clone(),
        worktree: Some(target.path().into()),
        agent_handle: "review-worker".into(),
        agent_name: None,
    })
    .unwrap();
    (target, scope)
}

fn options(root: &Path, scope: RewriteWorkScope) -> RewriteReviewOptions {
    RewriteReviewOptions {
        target_root: root.into(),
        worktree: Some(root.into()),
        scope: Some(scope),
        evidence: None,
        integration: false,
        handoff_id: None,
        hardcode_ai_verified: Vec::new(),
    }
}

fn git(root: &Path, args: &[&str]) {
    source_diff::git_text(root, args).unwrap();
}

#[test]
fn complete_file_size_includes_committed_changes_and_last_line_without_newline() {
    let (target, scope) = setup();
    fs::create_dir_all(target.path().join("src")).unwrap();
    let path = target.path().join("src/oversized.rs");
    fs::write(&path, format!("{}// last", "// line\n".repeat(1000))).unwrap();
    git(target.path(), &["add", "src/oversized.rs"]);
    git(target.path(), &["commit", "-qm", "worker delivery"]);
    let report = check(options(target.path(), scope.clone())).unwrap();
    assert_eq!(report.status, ReviewStatus::ChangesRequired);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.message.contains("1001 lines"))
    );
    fs::write(path, "// line\n".repeat(1000)).unwrap();
    assert_eq!(
        check(options(target.path(), scope)).unwrap().status,
        ReviewStatus::Passed
    );
}

#[test]
fn spawn_review_requires_startup_evidence_and_rejects_request_ownership() {
    let (target, scope) = setup();
    fs::create_dir_all(target.path().join("src")).unwrap();
    fs::write(
        target.path().join("src/jobs.rs"),
        "fn main() { start(); }\nfn start() { tokio::spawn(async {}); }\n",
    )
    .unwrap();
    let mut opts = options(target.path(), scope);
    let report = check(opts.clone()).unwrap();
    assert_eq!(report.status, ReviewStatus::EvidenceRequired);
    let found = report
        .findings
        .iter()
        .find(|f| f.rule == ReviewRule::SpawnOwnership)
        .unwrap();
    let location = |line| ReviewCodeEvidence {
        file: "src/jobs.rs".into(),
        line,
        fact: "startup call chain".into(),
    };
    let mut proof = ReviewEvidence {
        spawns: vec![SpawnEvidence {
            finding_id: found.id.clone(),
            ownership: SpawnOwnership::Request,
            startup_entry: None,
            call_chain: Vec::new(),
            request_path_review: "handler invokes this task".into(),
            task_lifecycle: String::new(),
        }],
    };
    let path = target.path().join(".traffic-e2e/local/proof.json");
    write_json(&path, &proof).unwrap();
    opts.evidence = Some(path.clone());
    assert_eq!(
        check(opts.clone()).unwrap().status,
        ReviewStatus::ChangesRequired
    );
    proof.spawns[0].ownership = SpawnOwnership::Startup;
    write_json(&path, &proof).unwrap();
    assert!(
        check(opts.clone())
            .unwrap_err()
            .to_string()
            .contains("startup_entry")
    );
    proof.spawns[0].startup_entry = Some(location(1));
    proof.spawns[0].call_chain = vec![location(1), location(2)];
    proof.spawns[0].request_path_review =
        "All callers inspected: only startup calls start, no request callback invokes it".into();
    proof.spawns[0].task_lifecycle = "Application owns one worker with bounded queue, error reporting, shutdown cancellation and join".into();
    write_json(&path, &proof).unwrap();
    let passed = check(opts).unwrap();
    assert_eq!(passed.status, ReviewStatus::Passed);
    assert!(evidence::reusable(target.path(), &passed));
    fs::write(target.path().join("src/jobs.rs"), "fn main() {}\n").unwrap();
    assert!(!evidence::reusable(target.path(), &passed));
}

#[test]
fn handoff_requires_current_review_without_advancing_worker_state_on_rejection() {
    let (target, scope) = setup();
    let store = RewriteStore::new(target.path()).unwrap();
    let mut opts = worker::runtime::RewriteWorkerReportOptions {
        target_root: target.path().into(),
        agent_handle: "review-worker".into(),
        activity: worker::model::RewriteWorkerActivity::HandoffReady,
        handoff_id: Some("delivery-1".into()),
        review_report: None,
    };
    assert!(
        worker::runtime::report(opts.clone())
            .unwrap_err()
            .to_string()
            .contains("--review-report")
    );
    assert!(worker::runtime::observation(&store.load().unwrap().unwrap(), &scope).is_none());
    let report = check(options(target.path(), scope.clone())).unwrap();
    opts.review_report = Some(report.report_path);
    fs::write(target.path().join("changed-after-review"), "stale").unwrap();
    assert!(
        worker::runtime::report(opts.clone())
            .unwrap_err()
            .to_string()
            .contains("changed")
    );
    fs::remove_file(target.path().join("changed-after-review")).unwrap();
    git(
        target.path(),
        &["commit", "--allow-empty", "-qm", "new delivery identity"],
    );
    assert!(
        worker::runtime::report(opts.clone())
            .unwrap_err()
            .to_string()
            .contains("commit changed")
    );
    opts.review_report = Some(check(options(target.path(), scope)).unwrap().report_path);
    worker::runtime::report(opts.clone()).unwrap();
    let revision = store.load().unwrap().unwrap().revision;
    worker::runtime::report(opts).unwrap();
    assert_eq!(revision, store.load().unwrap().unwrap().revision);
}

#[test]
fn local_review_does_not_mutate_workflow_and_integrated_receipt_survives_resume() {
    let (target, scope) = setup();
    let store = RewriteStore::new(target.path()).unwrap();
    let state = store.load().unwrap().unwrap();
    let lock = store.lock().unwrap();
    check(options(target.path(), scope)).unwrap();
    assert_eq!(store.load().unwrap().unwrap().revision, state.revision);
    drop(lock);
    let report = check(RewriteReviewOptions {
        target_root: target.path().into(),
        worktree: None,
        scope: None,
        evidence: None,
        integration: false,
        handoff_id: None,
        hardcode_ai_verified: Vec::new(),
    })
    .unwrap();
    assert_eq!(report.status, ReviewStatus::Passed);
    assert!(!terminal_current(target.path(), &state));
    accept(target.path().into(), report.report_path.clone()).unwrap();
    assert!(terminal_current(target.path(), &state));
    let mut old = show(target.path().into()).unwrap();
    old.rules_version = "old-rule".into();
    write_json(&report.report_path, &old).unwrap();
    assert!(!terminal_current(target.path(), &state));
    assert!(show(target.path().into()).is_err());
}

#[test]
fn assigned_git_worktree_review_is_accepted_and_integrated_without_a_private_workflow() {
    assigned_worktree_delivery(false);
}

#[test]
fn route_worker_reviews_and_integrates_one_handoff_for_both_methods() {
    assigned_worktree_delivery(true);
}

fn assigned_worktree_delivery(route_workers: bool) {
    let target = configured_target();
    git(target.path(), &["switch", "-qc", "coordinator"]);
    let directory = tempfile::tempdir().unwrap();
    let worktree = directory.path().join("worker");
    git(
        target.path(),
        &[
            "worktree",
            "add",
            "-qb",
            "worker-code",
            worktree.to_str().unwrap(),
        ],
    );
    let mut state = implementation_state_with_inventory(false);
    if route_workers {
        let mut sibling = state.active_slice.clone();
        sibling.api = "PUT /api".into();
        sibling.active_issue.as_mut().unwrap().id = "issue-put".into();
        state.parked_slices.insert(sibling.api.clone(), sibling);
        let mut progress = state.api_inventory[0].clone();
        progress.api = "PUT /api".into();
        progress.status = super::super::RewriteApiStatus::ImplementationRequired;
        state.api_inventory.push(progress);
    }
    let scope = crate::rewrite::api_selector::work_scope(&state, &state.api);
    let store = RewriteStore::new(target.path()).unwrap();
    store.save(&state).unwrap();
    worker::confirm(crate::rewrite::RewriteWorkerConfirmOptions {
        target_root: target.path().into(),
        work_scope: scope.clone(),
        worktree: Some(worktree.clone()),
        agent_handle: "separate-worker".into(),
        agent_name: None,
    })
    .unwrap();
    if route_workers {
        let evidence = crate::rewrite::query_rewrite_evidence_for_scope(
            crate::rewrite::RewriteContext {
                target_root: target.path().into(),
            },
            &scope,
        )
        .unwrap();
        assert_eq!(
            evidence.facts["method_apis"],
            serde_json::json!(["GET /api", "PUT /api"])
        );
        assert_eq!(evidence.facts["method_issues"].as_array().unwrap().len(), 2);
    }
    fs::create_dir_all(worktree.join("src")).unwrap();
    fs::write(
        worktree.join("src/lib.rs"),
        "fn main() { start(); }\nfn start() { tokio::spawn(async {}); }\nfn response() { let _ = serde_json::json!({\"success\": true}); }\n",
    )
    .unwrap();
    git(&worktree, &["add", "src"]);
    git(&worktree, &["commit", "-qm", "typed delivery"]);
    let mut opts = RewriteReviewOptions {
        target_root: target.path().into(),
        worktree: Some(worktree.clone()),
        scope: Some(scope.clone()),
        evidence: None,
        integration: false,
        handoff_id: None,
        hardcode_ai_verified: Vec::new(),
    };
    let report = check(opts.clone()).unwrap();
    assert_eq!(report.status, ReviewStatus::EvidenceRequired);
    let location = |line| ReviewCodeEvidence {
        file: "src/lib.rs".into(),
        line,
        fact: "Inspected startup path".into(),
    };
    let proof = ReviewEvidence {
        spawns: vec![SpawnEvidence {
            finding_id: report.findings[0].id.clone(),
            ownership: SpawnOwnership::Startup,
            startup_entry: Some(location(1)),
            call_chain: vec![location(1), location(2)],
            request_path_review: "Only main calls start; the response function never starts tasks"
                .into(),
            task_lifecycle:
                "Single application-owned task finishes immediately; no queue or retained work"
                    .into(),
        }],
    };
    let proof_path = crate::internal_runtime::root(&worktree).join("spawn-evidence.json");
    write_json(&proof_path, &proof).unwrap();
    opts.evidence = Some(proof_path);
    let report = check(opts).unwrap();
    assert_eq!(report.status, ReviewStatus::Passed);
    assert!(
        !crate::internal_runtime::root(&worktree)
            .join("rewrite/state.json")
            .exists()
    );
    let mut delivery = worker::runtime::RewriteWorkerReportOptions {
        target_root: target.path().into(),
        agent_handle: "separate-worker".into(),
        activity: worker::model::RewriteWorkerActivity::HandoffReady,
        handoff_id: Some(report.head_revision.clone()),
        review_report: Some(report.report_path),
    };
    worker::runtime::report(delivery.clone()).unwrap();

    let integration_worktree = directory.path().join("integrator");
    git(
        target.path(),
        &[
            "worktree",
            "add",
            "-qb",
            "integrated-code",
            integration_worktree.to_str().unwrap(),
        ],
    );
    git(
        &integration_worktree,
        &["merge", "--ff-only", &report.head_revision],
    );
    let candidate = check(RewriteReviewOptions {
        target_root: target.path().into(),
        worktree: Some(integration_worktree.clone()),
        scope: Some(scope.clone()),
        evidence: None,
        integration: true,
        handoff_id: delivery.handoff_id.clone(),
        hardcode_ai_verified: Vec::new(),
    })
    .unwrap();
    assert_eq!(candidate.status, ReviewStatus::Passed);
    assert_eq!(candidate.evidence.spawns.len(), 1);
    assert!(
        !crate::internal_runtime::root(&integration_worktree)
            .join("rewrite/state.json")
            .exists()
    );
    git(
        target.path(),
        &["merge", "--ff-only", &candidate.head_revision],
    );
    delivery.activity = worker::model::RewriteWorkerActivity::Integrated;
    assert!(
        worker::runtime::report(delivery.clone())
            .unwrap_err()
            .to_string()
            .contains("integration review report")
    );
    assert_eq!(
        worker::runtime::observation(&store.load().unwrap().unwrap(), &scope)
            .unwrap()
            .activity,
        worker::model::RewriteWorkerActivity::HandoffReady
    );
    delivery.review_report = Some(candidate.report_path);
    worker::runtime::report(delivery).unwrap();
    assert!(
        gate(target.path(), &store.load().unwrap().unwrap(), "master")
            .unwrap()
            .is_none()
    );
    assert_eq!(show(target.path().into()).unwrap().evidence.spawns.len(), 1);
    let previous_report = fs::read(integrated_path(target.path())).unwrap();
    fs::write(target.path().join("src/lib.rs"), "fn main() { start(); }\nfn start() { tokio::spawn(async {}); }\nfn response() { start(); }\n").unwrap();
    assert!(matches!(
        gate(target.path(), &store.load().unwrap().unwrap(), "master").unwrap(),
        Some(RewriteAction::SourceReviewRequired { .. })
    ));
    assert!(show(target.path().into()).is_err());
    assert_eq!(
        fs::read(integrated_path(target.path())).unwrap(),
        previous_report
    );
    let refreshed = check(RewriteReviewOptions {
        target_root: target.path().into(),
        worktree: None,
        scope: None,
        evidence: None,
        integration: false,
        handoff_id: None,
        hardcode_ai_verified: Vec::new(),
    })
    .unwrap();
    assert_eq!(refreshed.status, ReviewStatus::EvidenceRequired);
    assert_eq!(
        show(target.path().into()).unwrap().status,
        ReviewStatus::EvidenceRequired
    );
}

#[test]
fn nested_target_maps_repository_worktree_and_reviews_managed_sibling() {
    let repository = tempfile::tempdir().unwrap();
    let target = repository.path().join("backend-rs-intra");
    fs::create_dir_all(target.join("src")).unwrap();
    fs::create_dir_all(repository.path().join("sibling/src")).unwrap();
    crate::rewrite::test_support::install_project_config(
        &target,
        "master",
        crate::rewrite::test_support::managed_test_recorder(),
        Some(serde_json::json!([])),
    );
    crate::rewrite::test_support::set_managed_paths(&target, &["../sibling"]);
    fs::write(
        target.join(".traffic-e2e/verification.yaml"),
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();
    fs::write(target.join(".gitignore"), "/.traffic-e2e/local/\n").unwrap();
    fs::write(target.join("src/lib.rs"), "pub fn value() -> u8 { 1 }\n").unwrap();
    fs::write(
        repository.path().join("sibling/src/lib.rs"),
        "pub fn sibling() {}\n",
    )
    .unwrap();
    git(repository.path(), &["init", "-q", "-b", "master"]);
    git(
        repository.path(),
        &["config", "user.email", "test@example.com"],
    );
    git(
        repository.path(),
        &["config", "user.name", "Traffic E2E Test"],
    );
    git(repository.path(), &["add", "."]);
    git(repository.path(), &["commit", "-qm", "baseline"]);
    git(repository.path(), &["switch", "-qc", "coordinator"]);

    let state = implementation_state_with_inventory(false);
    let scope = RewriteWorkScope::Api {
        api: crate::rewrite::api_selector::public_api(&state.api).to_string(),
    };
    RewriteStore::new(&target).unwrap().save(&state).unwrap();

    let worktrees = tempfile::tempdir().unwrap();
    let repository_worktree = worktrees.path().join("worker");
    git(
        repository.path(),
        &[
            "worktree",
            "add",
            "-qb",
            "worker-code",
            repository_worktree.to_str().unwrap(),
        ],
    );
    let target_worktree = repository_worktree.join("backend-rs-intra");
    let envelope = worker::confirm(crate::rewrite::RewriteWorkerConfirmOptions {
        target_root: target.clone(),
        work_scope: scope.clone(),
        worktree: Some(repository_worktree.clone()),
        agent_handle: "nested-worker".into(),
        agent_name: None,
    })
    .unwrap();
    assert_eq!(envelope.schema_version, 36);
    let stored = RewriteStore::new(&target).unwrap().load().unwrap().unwrap();
    assert_eq!(
        stored
            .worker_bindings
            .get(&scope.binding_key())
            .unwrap()
            .review_assignment
            .as_ref()
            .unwrap()
            .worktree,
        target_worktree
    );

    fs::write(
        target_worktree.join("src/lib.rs"),
        "pub fn start() { tokio::spawn(async {}); }\n",
    )
    .unwrap();
    fs::write(
        repository_worktree.join("sibling/src/lib.rs"),
        "pub fn sibling() { tokio::spawn(async {}); }\n",
    )
    .unwrap();
    git(&repository_worktree, &["add", "."]);
    git(
        &repository_worktree,
        &["commit", "-qm", "nested target delivery"],
    );

    let mut options = RewriteReviewOptions {
        target_root: target,
        worktree: Some(repository_worktree),
        scope: Some(scope),
        evidence: None,
        integration: false,
        handoff_id: None,
        hardcode_ai_verified: Vec::new(),
    };
    let report = check(options.clone()).unwrap();
    assert_eq!(report.worktree, target_worktree);
    assert_eq!(report.status, ReviewStatus::EvidenceRequired);
    assert_eq!(report.files.len(), 2);
    assert!(report.files.contains_key(Path::new("src/lib.rs")));
    assert!(
        report
            .files
            .contains_key(Path::new("../sibling/src/lib.rs"))
    );
    assert_eq!(report.findings.len(), 2);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.file == Path::new("src/lib.rs"))
    );
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.file == Path::new("../sibling/src/lib.rs"))
    );
    let proof = ReviewEvidence {
        spawns: report
            .findings
            .iter()
            .map(|finding| SpawnEvidence {
                finding_id: finding.id.clone(),
                ownership: SpawnOwnership::Startup,
                startup_entry: Some(ReviewCodeEvidence {
                    file: finding.file.clone(),
                    line: finding.line,
                    fact: "startup entry owns the task".into(),
                }),
                call_chain: vec![ReviewCodeEvidence {
                    file: finding.file.clone(),
                    line: finding.line,
                    fact: "startup invokes this task".into(),
                }],
                request_path_review: "all callers are startup-owned".into(),
                task_lifecycle: "the application owns shutdown and task completion".into(),
            })
            .collect(),
    };
    let evidence = target_worktree.join(".traffic-e2e/local/managed-proof.json");
    write_json(&evidence, &proof).unwrap();
    options.evidence = Some(evidence);
    assert_eq!(check(options.clone()).unwrap().status, ReviewStatus::Passed);

    fs::create_dir_all(target_worktree.join("../unmanaged")).unwrap();
    fs::write(
        target_worktree.join("../unmanaged/file.txt"),
        "not reviewed\n",
    )
    .unwrap();
    git(&target_worktree, &["add", "../unmanaged/file.txt"]);
    git(&target_worktree, &["commit", "-qm", "unmanaged change"]);
    assert!(
        check(options)
            .unwrap_err()
            .to_string()
            .contains("outside the target and delivery.managed_paths")
    );
}

#[test]
fn review_applies_the_same_rust_gates_to_a_managed_sibling() {
    let repository = tempfile::tempdir().unwrap();
    let target = repository.path().join("service");
    let sibling = repository.path().join("shared");
    fs::create_dir_all(&target).unwrap();
    fs::create_dir_all(sibling.join("src")).unwrap();
    crate::rewrite::test_support::install_project_config(
        &target,
        "master",
        crate::rewrite::test_support::managed_test_recorder(),
        None,
    );
    crate::rewrite::test_support::set_managed_paths(&target, &["../shared"]);
    fs::write(
        target.join(".traffic-e2e/verification.yaml"),
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();
    fs::write(target.join(".gitignore"), "/.traffic-e2e/local/\n").unwrap();
    fs::write(
        sibling.join("Cargo.toml"),
        "[package]\nname = \"shared\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    fs::write(
        sibling.join("Cargo.lock"),
        "# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n\n[[package]]\nname = \"shared\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    fs::write(sibling.join(".gitignore"), "/target/\n").unwrap();
    fs::write(sibling.join("src/lib.rs"), "pub fn shared() {}\n").unwrap();
    git(repository.path(), &["init", "-q", "-b", "master"]);
    git(
        repository.path(),
        &["config", "user.email", "test@example.com"],
    );
    git(
        repository.path(),
        &["config", "user.name", "Traffic E2E Test"],
    );
    git(repository.path(), &["add", "."]);
    git(repository.path(), &["commit", "-qm", "baseline"]);
    git(repository.path(), &["switch", "-qc", "coordinator"]);
    RewriteStore::new(&target)
        .unwrap()
        .save(&crate::rewrite::test_support::test_state())
        .unwrap();

    let unchanged = check(RewriteReviewOptions {
        target_root: target.clone(),
        worktree: None,
        scope: None,
        evidence: None,
        integration: false,
        handoff_id: None,
        hardcode_ai_verified: Vec::new(),
    })
    .unwrap();
    assert_eq!(
        unchanged.required_gates,
        [
            "source-review",
            "replay-isolation",
            "managed-1-rust-format",
            "managed-1-rust-test",
            "managed-1-rust-clippy"
        ]
    );
    assert_eq!(unchanged.quality.unwrap().commands.len(), 3);

    fs::write(
        sibling.join("src/lib.rs"),
        "pub fn shared() -> u8 {\n    1\n}\n",
    )
    .unwrap();
    git(repository.path(), &["add", "shared/src/lib.rs"]);
    git(repository.path(), &["commit", "-qm", "change shared crate"]);
    let changed = check(RewriteReviewOptions {
        target_root: target,
        worktree: None,
        scope: None,
        evidence: None,
        integration: false,
        handoff_id: None,
        hardcode_ai_verified: Vec::new(),
    })
    .unwrap();

    assert_eq!(changed.status, ReviewStatus::Passed);
    assert_eq!(
        changed.required_gates,
        [
            "source-review",
            "replay-isolation",
            "managed-1-rust-format",
            "managed-1-rust-test",
            "managed-1-rust-clippy"
        ]
    );
    assert_eq!(changed.quality.unwrap().commands.len(), 3);
}

#[test]
fn completed_api_quality_rework_reuses_worker_and_duplicate_route_is_idempotent() {
    let (target, scope) = setup();
    let store = RewriteStore::new(target.path()).unwrap();
    let mut state = store.load().unwrap().unwrap();
    state.phase = crate::rewrite::RewritePhase::SliceComplete;
    state.active_issue = None;
    state.api_inventory[0].status = crate::rewrite::RewriteApiStatus::Complete;
    store.save(&state).unwrap();
    fs::create_dir_all(target.path().join("src")).unwrap();
    fs::write(target.path().join("src/bad.rs"), "fn bad(\n").unwrap();
    let report = check(RewriteReviewOptions {
        target_root: target.path().into(),
        worktree: None,
        scope: None,
        evidence: None,
        integration: false,
        handoff_id: None,
        hardcode_ai_verified: Vec::new(),
    })
    .unwrap();
    assert_eq!(report.status, ReviewStatus::ChangesRequired);
    let routed = rework(target.path().into(), &report.findings[0].id, scope.clone()).unwrap();
    assert!(!routed.terminal_allowed);
    assert!(matches!(
        routed.action,
        RewriteAction::ImplementationRequired { .. }
    ));
    let saved = store.load().unwrap().unwrap();
    assert_eq!(
        saved.active_issue.as_ref().unwrap().kind,
        crate::rewrite::RewriteIssueKind::TargetQuality
    );
    assert_eq!(
        saved.worker_bindings[&scope.binding_key()].agent_handle_fingerprint,
        state.worker_bindings[&scope.binding_key()].agent_handle_fingerprint
    );
    rework(target.path().into(), &report.findings[0].id, scope).unwrap();
    assert_eq!(store.load().unwrap().unwrap().revision, saved.revision);
}

fn integrated_and_parked_worker() -> (tempfile::TempDir, RewriteWorkScope) {
    let target = configured_target();
    git(target.path(), &["switch", "-qc", "coordinator"]);
    let mut state = implementation_state_with_inventory(false);
    worker::integrate_current_for_test(&mut state);
    let api = "POST /other".to_string();
    let mut item = state.api_inventory[0].clone();
    item.api = api.clone();
    item.status = crate::rewrite::RewriteApiStatus::ImplementationRequired;
    state.api_inventory.push(item);
    let mut slice = state.active_slice.clone();
    slice.api = api.clone();
    state.parked_slices.insert(api.clone(), slice);
    RewriteStore::new(target.path())
        .unwrap()
        .save(&state)
        .unwrap();
    (
        target,
        RewriteWorkScope::Api {
            api: crate::rewrite::api_selector::public_api(&api).into(),
        },
    )
}

fn failing_integrated_review(root: &Path) -> RewriteReviewReport {
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(root.join("src/bad.rs"), "\n".repeat(1001) + "fn bad(\n").unwrap();
    check(RewriteReviewOptions {
        target_root: root.into(),
        worktree: None,
        scope: None,
        evidence: None,
        integration: false,
        handoff_id: None,
        hardcode_ai_verified: Vec::new(),
    })
    .unwrap()
}

#[test]
fn another_apis_failed_review_does_not_hide_scoped_worker_commands() {
    let (target, scope) = integrated_and_parked_worker();
    failing_integrated_review(target.path());
    let state = RewriteStore::new(target.path())
        .unwrap()
        .load()
        .unwrap()
        .unwrap();
    let scoped = worker::runtime::scoped(&state, &scope).unwrap();
    let action = action::for_scoped_status(target.path(), &scoped)
        .unwrap()
        .action;
    assert!(
        matches!(
            action,
            RewriteAction::ImplementationRequired {
                confirm_worker: Some(_),
                ..
            }
        ),
        "{action:?}"
    );
}

#[test]
fn routed_review_waits_for_worker_and_keeps_handoff_and_integration_available() {
    use worker::model::RewriteWorkerActivity as Activity;
    let (target, scope) = integrated_and_parked_worker();
    let store = RewriteStore::new(target.path()).unwrap();
    let report = failing_integrated_review(target.path());
    rework(target.path().into(), &report.findings[0].id, scope.clone()).unwrap();
    worker::confirm(crate::rewrite::RewriteWorkerConfirmOptions {
        target_root: target.path().into(),
        work_scope: scope.clone(),
        worktree: Some(target.path().into()),
        agent_handle: "repair-worker".into(),
        agent_name: None,
    })
    .unwrap();
    let mut feedback = worker::runtime::RewriteWorkerReportOptions {
        target_root: target.path().into(),
        agent_handle: "repair-worker".into(),
        activity: Activity::Running,
        handoff_id: None,
        review_report: None,
    };
    let waiting = worker::runtime::report(feedback.clone()).unwrap();
    assert!(
        matches!(waiting.action, RewriteAction::WaitRequired { .. }),
        "{:?}",
        waiting.action
    );
    assert_eq!(waiting.pending, 1);
    let inventory = crate::rewrite::inventory_rewrite(crate::rewrite::RewriteContext {
        target_root: target.path().into(),
    })
    .unwrap();
    assert_eq!(inventory.details.ready.get("wait"), Some(&1));
    assert!(!inventory.details.ready.contains_key("verify_handoff"));
    let dispatch =
        worker::dispatch_view(&store.load().unwrap().unwrap(), scope.clone(), None).dispatch_id;
    rework(target.path().into(), &report.findings[1].id, scope.clone()).unwrap();
    let saved = store.load().unwrap().unwrap();
    assert_eq!(
        worker::dispatch_view(&saved, scope.clone(), None).dispatch_id,
        dispatch
    );
    assert_eq!(
        worker::runtime::observation(&saved, &scope)
            .unwrap()
            .activity,
        Activity::Running
    );
    assert_eq!(
        context(target.path(), &saved, &scope)
            .rework
            .unwrap()
            .findings
            .len(),
        2
    );
    assert_eq!(
        worker::runtime::scoped(&saved, &scope)
            .unwrap()
            .active_slice
            .active_issue
            .unwrap()
            .id,
        "issue-a"
    );

    fs::write(
        target.path().join("other-api.txt"),
        "unrelated integration\n",
    )
    .unwrap();
    // The delivery owner refreshes the report for changed code. Coordinator
    // gate inspection must not perform that scan on its behalf.
    let refreshed = check(RewriteReviewOptions {
        target_root: target.path().into(),
        worktree: None,
        scope: None,
        evidence: None,
        integration: false,
        handoff_id: None,
        hardcode_ai_verified: Vec::new(),
    })
    .unwrap();
    assert_eq!(refreshed.status, ReviewStatus::ChangesRequired);
    assert_eq!(refreshed.findings[0].id, report.findings[0].id);
    assert!(is_rework_wait(
        &gate(target.path(), &saved, "master").unwrap().unwrap()
    ));
    assert_eq!(
        worker::dispatch_view(&store.load().unwrap().unwrap(), scope.clone(), None).dispatch_id,
        dispatch
    );

    fs::write(target.path().join("src/bad.rs"), "fn fixed() {}\n").unwrap();
    let passed = check(options(target.path(), scope.clone())).unwrap();
    feedback.activity = Activity::HandoffReady;
    feedback.handoff_id = Some("quality-repair".into());
    feedback.review_report = Some(passed.report_path);
    let handoff = worker::runtime::report(feedback.clone()).unwrap();
    assert!(matches!(
        handoff.action,
        RewriteAction::IntegrationRequired { .. }
    ));
    let scoped = worker::runtime::scoped(&store.load().unwrap().unwrap(), &scope).unwrap();
    assert!(matches!(
        action::for_scoped_status(target.path(), &scoped)
            .unwrap()
            .action,
        RewriteAction::IntegrationRequired { .. }
    ));
    let integrated = check(RewriteReviewOptions {
        target_root: target.path().into(),
        worktree: Some(target.path().into()),
        scope: Some(scope.clone()),
        evidence: None,
        integration: true,
        handoff_id: feedback.handoff_id.clone(),
        hardcode_ai_verified: Vec::new(),
    })
    .unwrap();
    assert_eq!(integrated.status, ReviewStatus::Passed);
    feedback.activity = Activity::Integrated;
    feedback.review_report = Some(integrated.report_path);
    worker::runtime::report(feedback).unwrap();
    assert!(
        !store
            .load()
            .unwrap()
            .unwrap()
            .source_review_rework
            .contains_key(&scope.binding_key())
    );
    assert!(
        gate(target.path(), &store.load().unwrap().unwrap(), "master")
            .unwrap()
            .is_none()
    );
}
