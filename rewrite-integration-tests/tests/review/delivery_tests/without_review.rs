//! Ordinary delivery performs identity admission; only final review scans code.
use super::*;
use crate::model::{RewriteApiStatus, RewritePhase};

fn commit_source(root: &Path, body: &str) -> String {
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(root.join("src/lib.rs"), body).unwrap();
    git(root, &["add", "src/lib.rs"]);
    git(root, &["commit", "-qm", "delivery without source review"]);
    candidate::head(root).unwrap()
}

fn submit(
    root: &Path,
    commit: &str,
    activity: RewriteWorkerActivity,
) -> RewriteWorkerReportOptions {
    RewriteWorkerReportOptions {
        target_root: root.into(),
        agent_handle: "delivery-worker".into(),
        handoff_id: Some("original-handoff".into()),
        review_report: None,
        delivery_commit: Some(commit.into()),
        activity,
    }
}

#[test]
fn oversized_spawn_and_isolation_findings_do_not_block_handoff_or_integration() {
    let target = target();
    let directory = tempfile::tempdir().unwrap();
    let invoked = directory.path().join("build-invoked");
    enable_standard_rust_checks(
        target.path(),
        &format!(
            "fn main() {{ std::fs::write({:?}, \"called\").unwrap(); panic!(\"no delivery build\"); }}",
            invoked.to_string_lossy(),
        ),
    );
    let worker = worktree(target.path(), directory.path(), "worker");
    let scope = worker_scope(target.path(), &worker);
    let commit = commit_source(
        &worker,
        &format!(
            "{}fn start() {{ tokio::spawn(async {{}}); }}\nconst HOST: &str = \"db.trp.test\";\n",
            "// final structural cleanup\n".repeat(1001),
        ),
    );
    for integration in [false, true] {
        let mut opts = options(
            target.path(),
            &worker,
            (!integration).then_some(scope.clone()),
        );
        opts.integration = integration;
        opts.evidence = Some(directory.path().join("no-evidence-needed.json"));
        let report = crate::review::check(opts).unwrap();
        assert_eq!(report.status, ReviewStatus::Passed);
        assert!(report.findings.is_empty() && report.quality.is_none());
        assert!(report.next_step.contains("No review check is needed"));
    }
    let envelope = worker::runtime::report(submit(
        target.path(),
        &commit,
        RewriteWorkerActivity::HandoffReady,
    ))
    .unwrap();
    assert!(matches!(
        envelope.action,
        RewriteAction::IntegrationRequired { .. }
    ));
    let store = RewriteStore::new(target.path()).unwrap();
    let state = store.load().unwrap().unwrap();
    let receipt = state.worker_bindings[&scope.binding_key()]
        .review_report
        .as_ref()
        .unwrap();
    assert_eq!(receipt.required_gates, ["delivery-identity"]);
    assert!(receipt.quality.is_none() && receipt.findings.is_empty());
    let view =
        serde_json::to_value(crate::worker::scheduler::inventory(target.path(), &state)).unwrap();
    assert_eq!(view[0]["delivery_commit"], commit);
    assert!(
        serde_json::to_value(super::super::context(target.path(), &state, &scope))
            .unwrap()
            .get("check")
            .is_none()
    );

    // The integrator performs only Git operations and returns the commit.
    git(target.path(), &["merge", "--ff-only", &commit]);
    let envelope = worker::runtime::report(submit(
        target.path(),
        &commit,
        RewriteWorkerActivity::Integrated,
    ))
    .unwrap();
    assert!(
        matches!(envelope.action, RewriteAction::AdvanceRequired { .. }),
        "{:?}",
        envelope.action
    );
    let mut state = store.load().unwrap().unwrap();
    assert!(worker::runtime::acceptance_ready(&state, &scope));
    assert_eq!(
        state.worker_bindings[&scope.binding_key()]
            .last_integrated_commit
            .as_deref(),
        Some(commit.as_str())
    );
    assert!(!invoked.exists());

    // Ordinary acceptance can complete first. The same code is still rejected
    // by the consolidated final review, and cannot open the final sweep.
    for item in &mut state.api_inventory {
        item.status = RewriteApiStatus::Complete;
    }
    state.phase = RewritePhase::SliceComplete;
    state.current_api_index = None;
    store.save(&state).unwrap();
    assert!(matches!(
        pre_revalidation::required_action(target.path(), &state).unwrap(),
        Some(RewriteAction::PreRevalidationReviewRequired { .. })
    ));
    let final_report = check_pre_revalidation(RewriteReviewOptions {
        target_root: target.path().into(),
        worktree: Some(target.path().into()),
        scope: None,
        evidence: None,
        integration: true,
        quality_check: Some("cargo-clippy".into()),
        handoff_id: None,
    })
    .unwrap();
    assert_eq!(final_report.status, ReviewStatus::ChangesRequired);
    assert!(
        final_report
            .findings
            .iter()
            .any(|f| f.rule == ReviewRule::FileLines)
    );
    assert!(
        final_report
            .findings
            .iter()
            .any(|f| f.rule == ReviewRule::SpawnOwnership)
    );
    let identity = state.worker_bindings[&scope.binding_key()]
        .review_report
        .as_ref()
        .unwrap();
    assert!(accept(target.path().into(), identity.report_path.clone()).is_err());
    assert!(!pre_revalidation::current(
        target.path(),
        &store.load().unwrap().unwrap()
    ));
    assert!(!invoked.exists());
}

#[test]
fn commit_only_delivery_rejects_stale_dirty_and_unpublished_candidates() {
    let target = target();
    let directory = tempfile::tempdir().unwrap();
    let worker = worktree(target.path(), directory.path(), "worker");
    let scope = worker_scope(target.path(), &worker);
    let base = candidate::head(&worker).unwrap();
    let commit = commit_source(&worker, "pub fn value() -> u8 { 2 }\n");
    assert!(
        worker::runtime::report(submit(
            target.path(),
            &base,
            RewriteWorkerActivity::HandoffReady
        ))
        .is_err()
    );
    fs::write(worker.join("src/lib.rs"), "pub fn value() -> u8 { 3 }\n").unwrap();
    assert!(
        worker::runtime::report(submit(
            target.path(),
            &commit,
            RewriteWorkerActivity::HandoffReady
        ))
        .is_err()
    );
    fs::write(worker.join("src/lib.rs"), "pub fn value() -> u8 { 2 }\n").unwrap();
    worker::runtime::report(submit(
        target.path(),
        &commit,
        RewriteWorkerActivity::HandoffReady,
    ))
    .unwrap();
    assert!(
        worker::runtime::report(submit(
            target.path(),
            &commit,
            RewriteWorkerActivity::Integrated
        ))
        .is_err()
    );
    let state = RewriteStore::new(target.path())
        .unwrap()
        .load()
        .unwrap()
        .unwrap();
    assert_eq!(
        worker::runtime::observation(&state, &scope)
            .unwrap()
            .activity,
        RewriteWorkerActivity::HandoffReady
    );
    git(target.path(), &["merge", "--ff-only", &commit]);
    worker::runtime::report(submit(
        target.path(),
        &commit,
        RewriteWorkerActivity::Integrated,
    ))
    .unwrap();
    worker::runtime::report(submit(
        target.path(),
        &commit,
        RewriteWorkerActivity::Integrated,
    ))
    .unwrap();
}
