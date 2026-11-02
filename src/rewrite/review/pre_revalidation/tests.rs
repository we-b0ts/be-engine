//! Final candidate admission is separate from ordinary deliveries and sweep progress.
use super::*;
use crate::rewrite::inventory;
use crate::rewrite::quality::QualityScope;

#[path = "tests/inputs.rs"]
mod inputs;

mod system_repair;

fn git(root: &Path, argv: &[&str]) {
    source_diff::git_text(root, argv).unwrap();
}

fn load(root: &Path) -> RewriteState {
    RewriteStore::new(root).unwrap().load().unwrap().unwrap()
}

fn save(root: &Path, state: &RewriteState) {
    RewriteStore::new(root).unwrap().save(state).unwrap();
}

fn target(retained_current_index: bool) -> tempfile::TempDir {
    let target = crate::rewrite::worker::tests::configured_target();
    fs::write(
        target.path().join(".gitignore"),
        "/.traffic-e2e/local/\n/.traffic-e2e/regression.yaml\n",
    )
    .unwrap();
    fs::write(
        target.path().join(crate::config::regression::PATH),
        "skip: [/skipped]\n",
    )
    .unwrap();
    git(target.path(), &["add", ".gitignore"]);
    git(target.path(), &["commit", "-qm", "ignore engine runtime"]);
    install_ready_state(target.path(), retained_current_index);
    target
}

fn install_ready_state(root: &Path, retained_current_index: bool) {
    let mut state = crate::rewrite::test_state();
    inventory::install(
        &mut state,
        ["GET /api", "POST /other", "GET /skipped"]
            .into_iter()
            .map(str::to_string)
            .collect(),
    )
    .unwrap();
    let fingerprint = fingerprint::repository_fingerprint(root).unwrap();
    for item in &mut state.api_inventory {
        item.status = RewriteApiStatus::Complete;
        item.e2e_current = true;
        item.verified_target_fingerprint = Some(fingerprint.clone());
    }
    if !retained_current_index {
        state.current_api_index = None;
    }
    state.phase = RewritePhase::SliceComplete;
    state.e2e_current = true;
    state.target_fingerprint = Some(fingerprint);
    crate::rewrite::regression_scope::apply(root, &mut state).unwrap();
    assert_eq!(state.api_inventory[2].status, RewriteApiStatus::Skipped);
    save(root, &state);
}

fn options(root: &Path, worktree: &Path) -> RewriteReviewOptions {
    RewriteReviewOptions {
        target_root: root.into(),
        worktree: Some(worktree.into()),
        integration: false, // The explicit final entry point selects integration.
        quality_check: Some("cargo-clippy".into()),
        scope: None,
        evidence: None,
        handoff_id: None,
        hardcode_ai_verified: Vec::new(),
    }
}

fn accepted(root: &Path) -> RewriteReviewReport {
    let report = check_pre_revalidation(options(root, root)).unwrap();
    assert_eq!(report.status, ReviewStatus::Passed);
    candidate::accept(root.into(), report.report_path.clone()).unwrap();
    report
}

#[test]
fn ordinary_noop_does_not_replace_or_invalidate_an_accepted_final_review() {
    let target = target(false);
    let root = target.path();
    accepted(root);
    let before = fs::read(super::super::integrated_path(root)).unwrap();
    let state_before = serde_json::to_value(load(root)).unwrap();
    let mut ordinary = options(root, root);
    ordinary.quality_check = None;
    ordinary.integration = true;
    ordinary.evidence = Some(root.join("no-evidence-needed.json"));
    let report = super::super::check(ordinary).unwrap();
    assert_eq!(report.status, ReviewStatus::Passed);
    assert_eq!(report.required_gates, ["delivery-identity"]);
    assert!(report.files.is_empty() && report.findings.is_empty() && report.quality.is_none());
    assert!(report.next_step.contains("No review check is needed"));
    assert_eq!(
        fs::read(super::super::integrated_path(root)).unwrap(),
        before
    );
    assert_eq!(serde_json::to_value(load(root)).unwrap(), state_before);
    assert!(current(root, &load(root)));
}

fn complete_current(root: &Path, state: &mut RewriteState) {
    state.phase = RewritePhase::SliceComplete;
    state.e2e_current = true;
    state.target_fingerprint = Some(fingerprint::repository_fingerprint(root).unwrap());
    inventory::complete_current_and_advance(state).unwrap();
}

#[test]
fn exact_final_candidate_publication_starts_a_complete_sweep() {
    for retained_current_index in [false, true] {
        let target = target(retained_current_index);
        let root = target.path();
        let directory = tempfile::tempdir().unwrap();
        let integration = directory.path().join("integration");
        git(
            root,
            &[
                "worktree",
                "add",
                "-qb",
                "integration",
                integration.to_str().unwrap(),
            ],
        );
        fs::write(
            integration.join("lib.rs"),
            "pub fn value() -> u8 {\n    2\n}\n",
        )
        .unwrap();
        git(&integration, &["add", "lib.rs"]);
        git(&integration, &["commit", "-qm", "final candidate"]);
        let before = load(root);
        assert!(ready(&before));
        assert!(matches!(
            required_action(root, &before).unwrap(),
            Some(RewriteAction::PreRevalidationReviewRequired { .. })
        ));
        let report = check_pre_revalidation(options(root, &integration)).unwrap();
        assert_eq!(report.status, ReviewStatus::Passed);
        assert_eq!(
            report.quality.as_ref().unwrap().scope,
            Some(QualityScope::PreRevalidation)
        );
        assert!(report.quality.as_ref().unwrap().commands.is_empty());
        assert!(report.pre_revalidation.is_some());
        let error = candidate::accept(root.into(), report.report_path.clone()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("reviewed candidate is not published"),
            "{error:#}"
        );
        assert!(load(root).pre_revalidation_review.is_none());

        git(root, &["merge", "--ff-only", &report.head_revision]);
        candidate::accept(root.into(), report.report_path).unwrap();
        let after = load(root);
        assert!(current(root, &after));
        assert!(!completion_current(root, &after));
        assert!(required_action(root, &after).unwrap().is_none());
        let final_review = after.pre_revalidation_review.as_ref().unwrap();
        assert_eq!(
            final_review.remaining,
            BTreeSet::from(["GET /api".into(), "POST /other".into()])
        );
        assert_eq!(after.api, "GET /api");
        assert_eq!(after.phase, RewritePhase::ApiPending);
        assert_eq!(after.api_inventory[0].status, RewriteApiStatus::Active);
        assert_eq!(
            after.api_inventory[1].status,
            RewriteApiStatus::RevalidationPending
        );
        assert_eq!(after.api_inventory[2].status, RewriteApiStatus::Skipped);
        assert!(!after.api_inventory[0].e2e_current);
        assert!(!after.api_inventory[1].e2e_current);
        assert!(inventory::revalidation_round::contains(&after, "GET /api"));
        assert!(inventory::revalidation_round::contains(
            &after,
            "POST /other"
        ));
        assert!(!inventory::revalidation_round::contains(
            &after,
            "GET /skipped"
        ));
    }
}

#[test]
fn ordinary_integration_receipt_does_not_authorize_final_revalidation() {
    let target = target(false);
    let root = target.path();
    let mut ordinary_options = options(root, root);
    ordinary_options.integration = true;
    ordinary_options.quality_check = None;
    let ordinary = check(ordinary_options).unwrap();
    assert_eq!(ordinary.status, ReviewStatus::Passed);
    assert!(ordinary.pre_revalidation.is_none());
    assert!(
        ordinary
            .validation
            .as_ref()
            .unwrap()
            .final_inputs_fingerprint
            .is_none()
    );
    candidate::accept(root.into(), ordinary.report_path).unwrap();
    let state = load(root);
    assert!(state.pre_revalidation_review.is_none());
    assert!(state.revalidation_round.is_none());
    assert!(matches!(
        required_action(root, &state).unwrap(),
        Some(RewriteAction::PreRevalidationReviewRequired { .. })
    ));
    assert!(state.api_inventory.iter().all(|item| item.status.is_done()));
}

#[test]
fn final_stage_waits_for_implementation_acceptance_and_rejects_handoff_selectors() {
    let target = target(false);
    let root = target.path();
    let mature = load(root);
    for status in [
        RewriteApiStatus::Pending,
        RewriteApiStatus::ImplementationRequired,
        RewriteApiStatus::AwaitingRecordingRefresh,
        RewriteApiStatus::Active,
    ] {
        let mut state = mature.clone();
        state.api_inventory[1].status = status;
        assert!(!ready(&state), "{status:?}");
        assert!(required_action(root, &state).unwrap().is_none());
        save(root, &state);
        assert!(
            check_pre_revalidation(options(root, root))
                .unwrap_err()
                .to_string()
                .contains("finish API implementations and integrations")
        );
    }
    save(root, &mature);
    for with_scope in [false, true] {
        let mut invalid = options(root, root);
        if with_scope {
            invalid.scope = Some(RewriteWorkScope::Api { api: "/api".into() });
        } else {
            invalid.handoff_id = Some("handoff".into());
        }
        assert!(
            check_pre_revalidation(invalid)
                .unwrap_err()
                .to_string()
                .contains("global integration worktree without a handoff")
        );
    }
    let mut active = mature.clone();
    active.api_inventory[0].status = RewriteApiStatus::Active;
    active.current_api_index = Some(0);
    active.phase = RewritePhase::ApiPending;
    assert!(!ready(&active));
    active.phase = RewritePhase::SliceComplete;
    assert!(
        !ready(&active),
        "publish the completed Replay into API inventory first"
    );
    assert!(crate::rewrite::transition::complete_replay_if_ready(root, &mut active).unwrap());
    assert!(ready(&active));
    active.phase = RewritePhase::RecordingRequired;
    assert!(!ready(&active));
}

#[test]
fn progress_publication_and_sweep_progress_keep_the_receipt_without_resetting_membership() {
    let target = target(false);
    let root = target.path();
    let report = accepted(root);
    let mut state = load(root);
    let progress = crate::verification_progress::ProgressReport::new(
        crate::verification_progress::VerificationStage::Progress,
    );
    crate::verification_progress::write(&root.join(".traffic-e2e/progress.yaml"), &progress)
        .unwrap();
    git(root, &["add", ".traffic-e2e/progress.yaml"]);
    git(root, &["commit", "-qm", "publish progress only"]);
    assert_ne!(candidate::head(root).unwrap(), report.head_revision);
    assert!(current(root, &state));
    complete_current(root, &mut state);
    assert_eq!(state.api, "POST /other");
    assert!(current(root, &state));
    assert_eq!(
        state.pre_revalidation_review.as_ref().unwrap().remaining,
        BTreeSet::from(["POST /other".into()])
    );
    let before_remaining = state
        .pre_revalidation_review
        .as_ref()
        .unwrap()
        .remaining
        .clone();
    // Admission itself is idempotent even after the canonical branch has a
    // progress-only descendant. Public accept retains exact publication checks.
    let stored: RewriteReviewReport = read_json(&accepted_path(root)).unwrap();
    admit(root, &mut state, &stored).unwrap();
    assert_eq!(
        state.pre_revalidation_review.as_ref().unwrap().remaining,
        before_remaining
    );
    complete_current(root, &mut state);
    assert!(completion_current(root, &state));
    assert!(
        state
            .pre_revalidation_review
            .as_ref()
            .unwrap()
            .remaining
            .is_empty()
    );
    assert!(state.revalidation_round.is_none());
    assert!(state.api_inventory.iter().all(|item| item.status.is_done()));
    assert!(required_action(root, &state).unwrap().is_none());
}

#[test]
fn reaccepting_the_same_published_candidate_never_restarts_finished_members() {
    let target = target(false);
    let root = target.path();
    let report = accepted(root);
    let mut state = load(root);
    complete_current(root, &mut state);
    save(root, &state);
    candidate::accept(root.into(), report.report_path).unwrap();
    let state = load(root);
    assert_eq!(state.api, "POST /other");
    assert_eq!(state.api_inventory[0].status, RewriteApiStatus::Complete);
    assert_eq!(
        state.pre_revalidation_review.as_ref().unwrap().remaining,
        BTreeSet::from(["POST /other".into()])
    );
}

#[test]
fn final_receipt_expires_on_code_policy_recording_workflow_inventory_or_skip_changes() {
    let target = target(false);
    let root = target.path();
    accepted(root);
    let original = load(root);
    let source_path = root.join("lib.rs");
    let source = fs::read(&source_path).unwrap();
    let policy_path = root.join(".traffic-e2e/policy.yaml");
    let policy_bytes = fs::read(&policy_path).unwrap();
    let regression_path = root.join(crate::config::regression::PATH);
    let regression_bytes = fs::read(&regression_path).unwrap();
    for variant in [
        "code",
        "policy",
        "recording",
        "workflow",
        "inventory",
        "source_route",
        "skip",
    ] {
        let mut state = original.clone();
        match variant {
            "code" => fs::write(&source_path, "pub fn value() -> u8 { 3 }\n").unwrap(),
            "policy" => {
                let mut policy =
                    crate::policy::parse_policy(std::str::from_utf8(&policy_bytes).unwrap())
                        .unwrap();
                policy.json = Some(
                    serde_json::from_value(
                        serde_json::json!({"fields":{"/members":{"kind":"unordered"}}}),
                    )
                    .unwrap(),
                );
                fs::write(&policy_path, serde_yaml::to_string(&policy).unwrap()).unwrap();
            }
            "recording" => state.recording_run_id.push_str("-new"),
            "workflow" => state.workflow_id.push_str("-new"),
            "inventory" => {
                let mut item = state.api_inventory[0].clone();
                item.api = "DELETE /third".into();
                item.source_route = Some("/third".into());
                state.api_inventory.push(item);
            }
            "source_route" => state.api_inventory[1].source_route = Some("/different".into()),
            "skip" => {
                fs::write(&regression_path, "skip: [/skipped, /other]\n").unwrap();
                crate::rewrite::regression_scope::apply(root, &mut state).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(!current(root, &state), "{variant}");
        assert!(!completion_current(root, &state), "{variant}");
        fs::write(&source_path, &source).unwrap();
        fs::write(&policy_path, &policy_bytes).unwrap();
        fs::write(&regression_path, &regression_bytes).unwrap();
    }
    assert!(current(root, &original));
}

#[test]
fn missing_or_outdated_final_quality_cannot_be_admitted_or_reused() {
    let target = target(false);
    let root = target.path();
    let report = check_pre_revalidation(options(root, root)).unwrap();
    for variant in [
        "missing_quality",
        "worker_scope",
        "integration_scope",
        "missing_scope",
        "old_schema",
        "scoped_report",
    ] {
        let mut invalid = report.clone();
        match variant {
            "missing_quality" => invalid.quality = None,
            "worker_scope" => invalid.quality.as_mut().unwrap().scope = Some(QualityScope::Worker),
            "integration_scope" => {
                invalid.quality.as_mut().unwrap().scope = Some(QualityScope::Integration)
            }
            "missing_scope" => invalid.quality.as_mut().unwrap().scope = None,
            "old_schema" => invalid.quality.as_mut().unwrap().schema_version = 1,
            "scoped_report" => invalid.scope = Some(RewriteWorkScope::Api { api: "/api".into() }),
            _ => unreachable!(),
        }
        write_json(&report.report_path, &invalid).unwrap();
        assert!(
            candidate::accept(root.into(), report.report_path.clone()).is_err(),
            "{variant}"
        );
        assert!(load(root).pre_revalidation_review.is_none());
    }
    write_json(&report.report_path, &report).unwrap();
    candidate::accept(root.into(), report.report_path).unwrap();
    let state = load(root);
    let path = accepted_path(root);
    let valid: RewriteReviewReport = read_json(&path).unwrap();
    fs::remove_file(&path).unwrap();
    assert!(!current(root, &state));
    for scope in [
        None,
        Some(QualityScope::Worker),
        Some(QualityScope::Integration),
    ] {
        let mut invalid = valid.clone();
        invalid.quality.as_mut().unwrap().scope = scope;
        write_json(&path, &invalid).unwrap();
        assert!(!current(root, &state), "{scope:?}");
    }
    write_json(&path, &valid).unwrap();
    assert!(current(root, &state));
}

#[test]
fn invalid_candidate_suspends_the_old_sweep_and_preserves_failed_worker_obligations() {
    let target = target(false);
    let root = target.path();
    accepted(root);
    let mut state = load(root);
    let failed_api = state.api.clone();
    let mut failed = state.active_slice.clone();
    failed.phase = RewritePhase::ImplementationRequired;
    failed.active_issue = Some(crate::rewrite::worker::tests::issue(
        "final-api-failure",
        1,
        "checked-candidate",
    ));
    state.parked_slices.insert(failed_api.clone(), failed);
    state.api_inventory[0].status = RewriteApiStatus::ImplementationRequired;
    inventory::revalidation_round::finish(&mut state, &failed_api);
    inventory::resume_at(&mut state, 1).unwrap();
    assert_eq!(state.api, "POST /other");
    assert!(current(root, &state));
    assert!(!ready(&state));
    let remaining = state
        .pre_revalidation_review
        .as_ref()
        .unwrap()
        .remaining
        .clone();
    assert_eq!(remaining, BTreeSet::from(["POST /other".into()]));
    assert!(!reconcile(root, &mut state).unwrap());

    fs::write(root.join("lib.rs"), "pub fn value() -> u8 { 3 }\n").unwrap();
    assert!(!current(root, &state));
    assert!(
        matches!(required_action(root, &state).unwrap(), Some(RewriteAction::WaitRequired { resource, .. }) if resource == "pre_revalidation_candidate")
    );
    assert!(reconcile(root, &mut state).unwrap());
    assert!(state.revalidation_round.is_none());
    assert!(state.current_api_index.is_none());
    assert_eq!(
        state.api_inventory[1].status,
        RewriteApiStatus::RevalidationPending
    );
    assert_eq!(
        state.api_inventory[0].status,
        RewriteApiStatus::ImplementationRequired
    );
    assert_eq!(
        state.parked_slices[&failed_api].phase,
        RewritePhase::ImplementationRequired
    );
    assert!(state.parked_slices[&failed_api].active_issue.is_some());
    assert_eq!(
        state.pre_revalidation_review.as_ref().unwrap().remaining,
        remaining
    );
    save(root, &state);
    let mut restored = load(root);
    assert_eq!(
        restored.pre_revalidation_review.as_ref().unwrap().remaining,
        remaining
    );
    assert!(!reconcile(root, &mut restored).unwrap());
}

#[test]
fn replaced_final_artifact_cannot_reuse_the_previous_candidates_sweep_membership() {
    let target = target(false);
    let root = target.path();
    accepted(root);
    let mut previous = load(root);
    complete_current(root, &mut previous);
    save(root, &previous);
    assert_eq!(
        previous.pre_revalidation_review.as_ref().unwrap().remaining,
        BTreeSet::from(["POST /other".into()])
    );

    fs::write(root.join("lib.rs"), "pub fn value() -> u8 {\n    3\n}\n").unwrap();
    git(root, &["add", "lib.rs"]);
    git(root, &["commit", "-qm", "new final candidate"]);
    let mut replacement = check_pre_revalidation(options(root, root)).unwrap();
    replacement.accepted_target_fingerprint = Some(fingerprint::review_fingerprint(root).unwrap());
    // Simulate a crash after publication of the replacement accepted artifact,
    // before the coordinator can save the restarted complete sweep's state.
    write_json(&accepted_path(root), &replacement).unwrap();
    assert!(
        !current(root, &previous),
        "a new receipt must not inherit an old candidate's partially consumed membership"
    );
}

#[test]
fn repeated_final_commands_reuse_successful_receipts_before_and_after_publication() {
    let target = target(false);
    let root = target.path();
    let first = check_pre_revalidation(options(root, root)).unwrap();
    assert_eq!(first.status, ReviewStatus::Passed);
    fs::remove_file(&first.report_path).unwrap();
    let retried = check_pre_revalidation(options(root, root)).unwrap();
    assert_eq!(retried.report_path, first.report_path);
    assert!(retried.report_path.is_file());
    assert_eq!(retried.head_revision, first.head_revision);
    candidate::accept(root.into(), retried.report_path).unwrap();
    let admitted = check_pre_revalidation(options(root, root)).unwrap();
    assert_eq!(admitted.report_path, first.report_path);

    let progress = crate::verification_progress::ProgressReport::new(
        crate::verification_progress::VerificationStage::Progress,
    );
    crate::verification_progress::write(&root.join(".traffic-e2e/progress.yaml"), &progress)
        .unwrap();
    git(root, &["add", ".traffic-e2e/progress.yaml"]);
    git(
        root,
        &["commit", "-qm", "publish progress after final check"],
    );
    let after_progress = check_pre_revalidation(options(root, root)).unwrap();
    assert_eq!(after_progress.report_path, first.report_path);
    assert_eq!(after_progress.head_revision, first.head_revision);
    assert_ne!(candidate::head(root).unwrap(), after_progress.head_revision);
}

#[test]
fn final_report_retains_agent_quality_result_without_command_logs() {
    let target = target(false);
    let root = target.path();
    let report = check_pre_revalidation(options(root, root)).unwrap();
    let stored: RewriteReviewReport = read_json(&checked_path(root)).unwrap();
    assert_eq!(stored.report_path, report.report_path);
    assert_eq!(
        stored.quality.as_ref().unwrap().quality_check.as_deref(),
        Some("cargo-clippy")
    );
    assert!(stored.quality.as_ref().unwrap().commands.is_empty());
    assert!(!stored.report_path.with_extension("logs").exists());
}

#[test]
fn adopting_a_legacy_recorded_route_does_not_expire_the_final_scope() {
    let target = target(false);
    let root = target.path();
    let mut state = load(root);
    state.api_inventory[0].api = "GET /legacy/*".into();
    state.api_inventory[0].source_route = None;
    let unbound = context(root, &state).unwrap();
    state
        .source_route_bindings
        .insert("GET /legacy/*".into(), "/legacy/*".into());
    assert_eq!(context(root, &state).unwrap(), unbound);
    state.api_inventory[0].source_route = Some("/legacy/*".into());
    assert_eq!(context(root, &state).unwrap(), unbound);
    state.api_inventory[0].source_route = Some("/different/*".into());
    assert_ne!(context(root, &state).unwrap(), unbound);
}

#[test]
fn final_stage_requires_agent_success_for_the_configured_tool_without_running_cargo() {
    let target = target(false);
    let root = target.path();
    // Any Cargo subprocess would fail, including fmt, test and Clippy.
    fs::write(root.join("Cargo.toml"), "invalid Cargo manifest\n").unwrap();
    git(root, &["add", "Cargo.toml"]);
    git(root, &["commit", "-qm", "unusable Cargo manifest"]);
    for tool in [None, Some("".into()), Some("eslint".into())] {
        let mut opts = options(root, root);
        opts.quality_check = tool;
        let error = check_pre_revalidation(opts).unwrap_err();
        assert!(error.to_string().contains("run delivery.quality_check"));
        assert!(load(root).pre_revalidation_review.is_none());
    }
    let action = required_action(root, &load(root)).unwrap().unwrap();
    let value = serde_json::to_value(&action).unwrap();
    assert_eq!(value["kind"], "pre_revalidation_review_required");
    assert_eq!(value["details"]["quality_check"], "cargo-clippy");
    assert_eq!(value["details"]["quality_paths"], serde_json::json!(["."]));
    assert!(
        value["commands"]["check"]["argv"]
            .as_array()
            .unwrap()
            .iter()
            .any(|arg| arg == "--quality-check")
    );
    let report = accepted(root);
    assert!(report.quality.as_ref().unwrap().commands.is_empty());
    assert!(current(root, &load(root)));
    assert!(!root.join("target").exists());
    assert!(
        !crate::internal_runtime::root(root)
            .join("rewrite/quality")
            .exists()
    );
}

#[test]
fn configured_language_tool_is_required_and_changes_expire_final_proof() {
    let target = target(false);
    let root = target.path();
    let config_path = root.join(".traffic-e2e/project.yaml");
    let original = fs::read_to_string(&config_path).unwrap();
    let mut config: serde_yaml::Value = serde_yaml::from_str(&original).unwrap();
    config["project"]["delivery"]["quality_check"] = "ruff".into();
    fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();
    git(root, &["add", ".traffic-e2e/project.yaml"]);
    git(root, &["commit", "-qm", "configure Python quality tool"]);
    let action =
        serde_json::to_value(required_action(root, &load(root)).unwrap().unwrap()).unwrap();
    assert_eq!(action["details"]["quality_check"], "ruff");
    assert!(check_pre_revalidation(options(root, root)).is_err());
    let mut opts = options(root, root);
    opts.quality_check = Some("ruff".into());
    let report = check_pre_revalidation(opts.clone()).unwrap();
    candidate::accept(root.into(), report.report_path.clone()).unwrap();
    let state = load(root);
    assert!(current(root, &state));
    assert_eq!(
        check_pre_revalidation(opts).unwrap().report_path,
        report.report_path
    );
    config["project"]["delivery"]["quality_check"] = "eslint".into();
    fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();
    assert!(!current(root, &state));
    assert!(matches!(
        required_action(root, &state).unwrap(),
        Some(RewriteAction::PreRevalidationReviewRequired { .. })
    ));
}
