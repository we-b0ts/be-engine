//! Purpose baselines bypass review, while changed deliveries retain admission.
use super::*;
use crate::rewrite::{action, fingerprint, review};

fn review_path(root: &Path) -> PathBuf {
    crate::internal_runtime::root(root).join("rewrite/source-review.json")
}

#[test]
fn both_purposes_ignore_old_receipts_at_entry() {
    for record_new_traffic in [false, true] {
        let target = fixture();
        let path = review_path(target.path());
        let old = serde_json::to_vec(&serde_json::json!({
            "schema_version":2, "rules_version":"target-source-review-v3",
            "workflow_id":"old-workflow", "worktree":target.path(),
            "base_revision":"old", "head_revision":"old", "target_fingerprint":"old",
            "status":"passed", "files":{}, "findings":[], "evidence":{"spawns":[]},
            "evidence_files":{}, "report_path":path, "next_step":"old delivery"
        }))
        .unwrap();
        serde_json::from_slice::<rewrite::RewriteReviewReport>(&old).unwrap();
        fs::write(&path, &old).unwrap();
        let report = begin(RewriteRegressionBeginOptions {
            record_new_traffic,
            ..options(target.path())
        })
        .unwrap();
        assert!(matches!(
            report.next.action,
            rewrite::RewriteAction::AdvanceRequired { .. }
                | rewrite::RewriteAction::RecordingRequired { .. }
        ));
        assert!(!report.next.terminal_allowed);
        let state = RewriteStore::new(target.path())
            .unwrap()
            .load()
            .unwrap()
            .unwrap();
        assert!(!review::requires_delivery_review(target.path(), &state));
        assert!(
            review::required_action(target.path(), &state)
                .unwrap()
                .is_none()
        );
        assert_eq!(fs::read(&path).unwrap(), old); // Old evidence remains historical.
        fs::write(&path, "broken old receipt").unwrap();
        assert!(!review::requires_delivery_review(target.path(), &state));
    }
}

#[test]
fn unchanged_purposes_complete_without_review_after_progress_publication() {
    for record_new_traffic in [false, true] {
        let target = fixture();
        begin(RewriteRegressionBeginOptions {
            record_new_traffic,
            ..options(target.path())
        })
        .unwrap();
        let store = RewriteStore::new(target.path()).unwrap();
        let mut state = store.load().unwrap().unwrap();
        // Model the successful verification result; exercise final admission.
        inventory::install(&mut state, vec!["GET /api".into()]).unwrap();
        state.phase = RewritePhase::SliceComplete;
        state.current_api_index = None;
        state.require_comparison = false;
        state.e2e_current = true;
        state.api_inventory[0].status = rewrite::RewriteApiStatus::Complete;
        state.api_inventory[0].e2e_current = true;
        state.api_inventory[0].verified_target_fingerprint =
            Some(fingerprint::repository_fingerprint(target.path()).unwrap());
        // A receipt accepted by the previous engine version is not an obligation
        // to re-review an unchanged baseline if that receipt later becomes stale.
        state.delivery_review_required = true;
        fs::write(review_path(target.path()), "stale").unwrap();
        let progress = target.path().join(".traffic-e2e/progress.yaml");
        crate::verification_progress::write(
            &progress,
            &crate::verification_progress::ProgressReport::new(
                crate::verification_progress::VerificationStage::Progress,
            ),
        )
        .unwrap();
        let before_commit = action::for_status(target.path(), &state).unwrap();
        assert!(!before_commit.terminal_allowed);
        assert!(matches!(
            before_commit.action,
            rewrite::RewriteAction::InputRequired { .. }
        ));
        git(target.path(), &["add", ".traffic-e2e/progress.yaml"]);
        git(
            target.path(),
            &["commit", "-qm", "publish regression progress"],
        );
        let completed = action::for_status(target.path(), &state).unwrap();
        assert!(matches!(
            completed.action,
            rewrite::RewriteAction::Complete { .. }
        ));
        assert!(completed.terminal_allowed);
    }
}

#[tokio::test]
async fn new_code_changes_require_review_before_verification_even_without_history() {
    for kind in ["working", "staged", "committed", "untracked", "deleted"] {
        let target = fixture();
        begin(options(target.path())).unwrap();
        match kind {
            "untracked" => fs::write(target.path().join("new.rs"), "pub fn added() {}\n").unwrap(),
            "deleted" => fs::remove_file(target.path().join("lib.rs")).unwrap(),
            _ => fs::write(target.path().join("lib.rs"), "pub fn value() -> u8 { 2 }\n").unwrap(),
        }
        if matches!(kind, "staged" | "committed") {
            git(target.path(), &["add", "lib.rs"]);
        }
        if kind == "committed" {
            git(target.path(), &["commit", "-qm", "external code update"]);
        }
        let context = rewrite::RewriteContext {
            target_root: target.path().into(),
        };
        let status = rewrite::status_rewrite(context).unwrap();
        assert!(
            matches!(
                status.action,
                rewrite::RewriteAction::SourceReviewRequired { .. }
            ),
            "{kind}"
        );
        assert!(!status.terminal_allowed);
        let next = rewrite::next_rewrite(rewrite::RewriteNextOptions {
            target_root: target.path().into(),
            api: None,
            process_output: None,
            source_route: None,
        })
        .await
        .unwrap();
        assert!(
            matches!(
                next.action,
                rewrite::RewriteAction::SourceReviewRequired { .. }
            ),
            "{kind}"
        );
        assert!(matches!(
            traffic_operation::state(target.path()).unwrap(),
            traffic_operation::TrafficOperationState::Absent
        ));
    }
}

#[test]
fn changed_purpose_needs_a_fresh_accepted_receipt_and_keeps_rework_gates() {
    let target = fixture();
    begin(options(target.path())).unwrap();
    fs::write(target.path().join("lib.rs"), "pub fn value() -> u8 { 2 }\n").unwrap();
    git(target.path(), &["add", "lib.rs"]);
    git(target.path(), &["commit", "-qm", "new purpose fix"]);
    let store = RewriteStore::new(target.path()).unwrap();
    let state = store.load().unwrap().unwrap();
    assert!(!review::admission_current(target.path(), &state));
    let receipt = review::check(rewrite::RewriteReviewOptions {
        target_root: target.path().into(),
        worktree: None,
        scope: None,
        evidence: None,
        integration: true,
        handoff_id: None,
        hardcode_ai_verified: vec![],
    })
    .unwrap();
    assert!(!review::admission_current(target.path(), &state));
    review::accept(target.path().into(), receipt.report_path).unwrap();
    let mut state = store.load().unwrap().unwrap();
    assert!(review::admission_current(target.path(), &state));
    fs::write(target.path().join("lib.rs"), "pub fn value() -> u8 { 3 }\n").unwrap();
    assert!(!review::admission_current(target.path(), &state));
    let base = &state.regression.as_ref().unwrap().base_revision;
    git(
        target.path(),
        &["restore", "--source", base, "--", "lib.rs"],
    );
    assert!(review::admission_current(target.path(), &state));
    state.source_review_rework.insert(
        "GET /api".into(),
        review::ReviewRework {
            target_fingerprint: "candidate".into(),
            findings: Default::default(),
        },
    );
    assert!(!review::admission_current(target.path(), &state));
}

#[test]
fn first_case_pattern_policy_update_does_not_require_delivery_review() {
    for record_new_traffic in [false, true] {
        let target = fixture();
        begin(RewriteRegressionBeginOptions {
            record_new_traffic,
            ..options(target.path())
        })
        .unwrap();
        let state = RewriteStore::new(target.path())
            .unwrap()
            .load()
            .unwrap()
            .unwrap();
        let policy_path = target
            .path()
            .join(".traffic-e2e/source-traffic-policy.yaml");
        let mut policy = crate::config::SourceTrafficPolicyConfig::load(&policy_path).unwrap();
        policy.http.case_path_patterns = vec!["/api/*".into()];
        fs::write(&policy_path, policy.render().unwrap()).unwrap();
        assert!(!review::requires_delivery_review(target.path(), &state));
        assert!(
            review::gate(target.path(), &state, "master")
                .unwrap()
                .is_none()
        );
        git(
            target.path(),
            &["add", ".traffic-e2e/source-traffic-policy.yaml"],
        );
        git(target.path(), &["commit", "-qm", "discover case pattern"]);
        assert!(!review::requires_delivery_review(target.path(), &state));
        assert!(
            review::gate(target.path(), &state, "master")
                .unwrap()
                .is_none()
        );
        fs::write(target.path().join("lib.rs"), "pub fn changed() {}\n").unwrap();
        assert!(review::requires_delivery_review(target.path(), &state));
        assert!(
            review::gate(target.path(), &state, "master")
                .unwrap()
                .is_some()
        );
    }
}
