use super::*;
use crate::RewriteAction;

#[test]
fn recording_execute_conflict_returns_pollable_wait_report() {
    let target = Path::new("/target");
    let report = waiting_start_report(
        target,
        "recording-a",
        ManagedRecordingOperation::RecordComparison,
        "run-a".to_string(),
        "GET /api",
        None,
    );

    assert_eq!(
        report.execution_state,
        RewriteRecordingStartState::WaitingForTrafficRuntime
    );
    assert_eq!(
        report.status_poll_after_seconds,
        Some(STATUS_POLL_AFTER_SECONDS)
    );
    assert_eq!(
        serde_json::to_value(&report).unwrap()["status_poll_after_seconds"],
        STATUS_POLL_AFTER_SECONDS
    );
    assert!(report.waiting_on.is_none());
    assert_eq!(
        report.status.argv,
        [
            "backend-rewrite",
            "--target-root",
            "/target",
            "status",
            "--api",
            "GET /api"
        ]
    );
}

#[test]
fn recording_execute_only_delays_status_polling_for_waiting_states() {
    let target = Path::new("/target");
    for execution_state in [
        RewriteRecordingStartState::Started,
        RewriteRecordingStartState::AlreadyRunning,
    ] {
        let report = start_report(
            target,
            "recording-a",
            ManagedRecordingOperation::RecordComparison,
            "run-a".to_string(),
            execution_state,
        );
        assert_eq!(
            serde_json::to_value(report).unwrap()["status_poll_after_seconds"],
            STATUS_POLL_AFTER_SECONDS
        );
    }
    let completed = start_report(
        target,
        "recording-a",
        ManagedRecordingOperation::RecordComparison,
        "run-a".to_string(),
        RewriteRecordingStartState::AlreadyCompleted,
    );

    assert!(serde_json::to_value(completed).unwrap()["status_poll_after_seconds"].is_null());
}

#[test]
fn fresh_request_invalidates_evidence_and_returns_opaque_managed_action() {
    let mut state = crate::rewrite::test_state();
    state.phase = RewritePhase::SliceComplete;
    state.case_source = Some(PathBuf::from("old-cases"));
    state.case_inventory_id = Some("old-inventory".to_string());
    state.group_id = Some("GET /api".to_string());
    state.comparison_run_id = Some("20260802000001".to_string());
    state.e2e_current = true;
    state.comparison_current = true;

    reset_for_fresh_recording(
        &mut state,
        "20260802000002".to_string(),
        RewriteRecordingSettings {
            duration_seconds: NonZeroU64::new(90).unwrap(),
            per_api_case_limit: NonZeroUsize::new(250).unwrap(),
        },
        RewriteRecordingReason::UserRequested,
    );

    assert_eq!(state.phase, RewritePhase::RecordingRequired);
    assert!(state.case_source.is_none());
    assert!(state.case_inventory_id.is_none());
    assert!(state.group_id.is_none());
    assert!(state.comparison_run_id.is_none());
    assert!(!state.e2e_current);
    assert!(!state.comparison_current);
    let target = tempfile::tempdir().unwrap();
    let action = action::for_state(target.path(), &state).action;
    let RewriteAction::RecordingRequired {
        summary, command, ..
    } = action
    else {
        panic!("expected a standard recording action");
    };
    assert_eq!(
        command.argv,
        [
            "backend-rewrite",
            "--target-root",
            target.path().to_str().unwrap(),
            "recording",
            "execute",
            recording_action::recording_action_id(&state, false).as_str(),
        ]
    );
    assert_eq!(command.cwd, target.path());
    assert!(state.recording_input_case_source.is_none());
    assert_eq!(
        summary,
        "fresh standard recording requested (user_requested) for GET /api; the request reason requires fresh external live traffic"
    );
}

#[test]
fn recorder_contract_change_keeps_the_atomic_all_api_scope_but_not_old_input() {
    let mut state = crate::rewrite::test_state();
    state.api.clear();
    state.source_route.clear();
    state.recording_apis.clear();
    state.case_source = Some(PathBuf::from("old-all-api-cases"));

    let settings = state.recording_settings;
    reset_for_fresh_recording(
        &mut state,
        "20260802000003".to_string(),
        settings,
        RewriteRecordingReason::RecorderContractChanged,
    );

    assert!(state.recording_apis.is_empty());
    assert!(state.recording_input_case_source.is_none());
    assert!(requires_external_live_traffic(&state));
}

#[test]
fn pending_request_is_idempotent_and_requires_explicit_replacement() {
    let mut state = crate::rewrite::test_state();
    state.recording_request_reason = Some(RewriteRecordingReason::UserRequested);
    let settings = state.recording_settings;

    assert!(
        reuse_pending_recording(
            &state,
            RewriteRecordingReason::UserRequested,
            settings,
            &state.recording_apis,
            false,
        )
        .unwrap()
    );

    let different = RewriteRecordingSettings {
        duration_seconds: NonZeroU64::new(90).unwrap(),
        per_api_case_limit: settings.per_api_case_limit,
    };
    assert!(
        reuse_pending_recording(
            &state,
            RewriteRecordingReason::UserRequested,
            different,
            &state.recording_apis,
            false,
        )
        .is_err()
    );
    assert!(
        !reuse_pending_recording(
            &state,
            RewriteRecordingReason::UserRequested,
            different,
            &state.recording_apis,
            true,
        )
        .unwrap()
    );
}

#[test]
fn omitted_api_requests_all_configured_traffic() {
    assert!(requested_recording_apis(None).is_empty());
    let api = "GET /api/widgets/*".parse::<RecordingApi>().unwrap();
    assert_eq!(requested_recording_apis(Some(&api)), ["GET /api/widgets/*"]);
}

#[test]
fn finalized_single_api_can_be_replaced_by_an_all_configured_request() {
    let mut state = crate::rewrite::test_state();
    state.recording_request_reason = Some(RewriteRecordingReason::UserRequested);

    assert_eq!(
        existing_recording_disposition(
            artifacts::RecordingPublication::Finalized,
            &state,
            RewriteRecordingReason::UserRequested,
            RewriteRecordingSettings {
                duration_seconds: NonZeroU64::new(60).unwrap(),
                per_api_case_limit: NonZeroUsize::new(100).unwrap(),
            },
            &[],
            true,
        )
        .unwrap(),
        ExistingRecordingDisposition::Replace
    );
}

#[test]
fn drained_capture_plans_start_one_all_scope_fresh_recording() {
    let target = tempfile::tempdir().unwrap();
    fs::create_dir_all(target.path().join(".traffic-e2e")).unwrap();
    crate::rewrite::test_support::install_project_config(
        target.path(),
        "master",
        crate::config::AppConfig::default(),
        None,
    );
    let mut state = crate::rewrite::test_state();
    inventory::install(
        &mut state,
        vec!["GET /a".to_string(), "POST /b".to_string()],
    )
    .unwrap();
    state.recording_apis.clear();
    for item in &mut state.api_inventory {
        item.status = super::super::model::RewriteApiStatus::AwaitingRecordingRefresh;
    }
    state.case_source = Some(PathBuf::from("old-recording"));
    state.current_api_index = None;
    state.recording_refresh = Some(super::super::model::RewriteRecordingRefreshState {
        applied: vec![super::super::model::RewriteRecorderCaptureAppliedRecord {
            plan_id: "capture-1".to_string(),
            issue_id: "issue-1".to_string(),
            evidence_id: "evidence-1".to_string(),
            api: "GET /a".to_string(),
            endpoint: "counter.example.com:9332".to_string(),
            resource_identity: "resource-1".to_string(),
            source_revision: "source-1".to_string(),
            source_evidence: "CounterService.java:88".to_string(),
        }],
        dependency_rules: Vec::new(),
        baseline_case_source: Some(PathBuf::from("old-recording")),
        project_config_revision: super::super::fingerprint::project_config_revision(target.path())
            .unwrap(),
        source_traffic_policy_revision: super::super::fingerprint::source_traffic_policy_revision(
            target.path(),
        )
        .unwrap(),
        recording_run_id: None,
    });

    assert!(begin_pending_capture_refresh(target.path(), &mut state).unwrap());
    assert_eq!(state.phase, RewritePhase::RecordingRequired);
    assert_eq!(
        state.recording_request_reason,
        Some(RewriteRecordingReason::RecorderContractChanged)
    );
    assert!(state.recording_apis.is_empty());
    assert!(state.api_inventory.is_empty());
    assert_eq!(
        state
            .recording_refresh
            .as_ref()
            .and_then(|refresh| refresh.baseline_case_source.as_deref()),
        Some(Path::new("old-recording"))
    );
    assert_eq!(
        state
            .recording_refresh
            .as_ref()
            .and_then(|refresh| refresh.recording_run_id.as_deref()),
        Some(state.recording_run_id.as_str())
    );
}

fn pending_refresh() -> super::super::model::RewriteRecordingRefreshState {
    use super::super::model::{RewriteDependencyRuleAppliedRecord, RewriteRecordingRefreshState};
    RewriteRecordingRefreshState {
        applied: Vec::new(),
        dependency_rules: vec![RewriteDependencyRuleAppliedRecord {
            plan_id: "dependency-plan".to_string(),
            issue_id: "dependency-issue".to_string(),
            evidence_id: "dependency-evidence".to_string(),
            api: "GET /widgets/*".to_string(),
            rule_name: "background-read".to_string(),
            source_evidence: "src/background.rs:42".to_string(),
        }],
        baseline_case_source: Some(PathBuf::from("old-recording")),
        project_config_revision: "fnv1a64:old-project".to_string(),
        source_traffic_policy_revision: "fnv1a64:old-policy".to_string(),
        recording_run_id: None,
    }
}

fn legacy_repair_recording() -> RewriteState {
    let mut state = crate::rewrite::test_state();
    state.api.clear();
    state.source_route.clear();
    state.recording_apis.clear();
    state.recording_request_reason = Some(RewriteRecordingReason::RecorderContractChanged);
    state.recording_input_case_source = None;
    state.recording_refresh = Some(pending_refresh());
    state.api_catalog_initialized = true;
    state.api_catalog.insert("GET /widgets/*".to_string());
    state
}

#[test]
fn repair_replacement_owns_pending_refresh_without_losing_its_provenance() {
    for reason in [
        RewriteRecordingReason::RecorderContractChanged,
        RewriteRecordingReason::SourceBaselineChanged,
    ] {
        let mut state = legacy_repair_recording();
        state.phase = RewritePhase::SystemRepairRequired;
        state.case_source = Some(PathBuf::from("old-recording"));
        let mut expected = pending_refresh();
        let settings = state.recording_settings;
        reset_for_fresh_recording(&mut state, "20260906065817".to_string(), settings, reason);
        expected.recording_run_id = Some("20260906065817".to_string());
        assert_eq!(
            serde_json::to_value(&state.recording_refresh).unwrap(),
            serde_json::to_value(&expected).unwrap()
        );

        // A later repair must also replace an already-bound run.
        reset_for_fresh_recording(&mut state, "20260906065818".to_string(), settings, reason);
        expected.recording_run_id = Some("20260906065818".to_string());
        assert_eq!(
            serde_json::to_value(&state.recording_refresh).unwrap(),
            serde_json::to_value(&expected).unwrap()
        );
        assert!(state.case_source.is_none());
        assert!(state.recording_input_case_source.is_none());
    }
}

#[test]
fn legacy_refresh_adoption_is_idempotent_and_preserves_recording_action_identity() {
    let target = tempfile::tempdir().unwrap();
    for publication in [None, Some("running"), Some("completed")] {
        let mut state = legacy_repair_recording();
        if let Some(status) = publication {
            write_recording(target.path(), &state, status, &[]);
        }
        let action_id = recording_action::recording_action_id(&state, false);
        let original_run = state.recording_run_id.clone();
        let mut expected = state.recording_refresh.clone().unwrap();
        expected.recording_run_id = Some(original_run.clone());

        assert!(begin_pending_capture_refresh(target.path(), &mut state).unwrap());
        assert_eq!(
            serde_json::to_value(&state.recording_refresh).unwrap(),
            serde_json::to_value(&expected).unwrap()
        );
        assert_eq!(state.recording_run_id, original_run);
        assert_eq!(
            recording_action::recording_action_id(&state, false),
            action_id
        );
        let revision = state.revision;
        assert!(!begin_pending_capture_refresh(target.path(), &mut state).unwrap());
        assert_eq!(state.revision, revision);
    }
}

#[test]
fn unscheduled_refresh_still_rejects_project_and_policy_changes() {
    let target = tempfile::tempdir().unwrap();
    crate::rewrite::test_support::install_project_config(
        target.path(),
        "master",
        crate::config::AppConfig::default(),
        None,
    );
    for filename in ["project.yaml", "source-traffic-policy.yaml"] {
        let mut state = legacy_repair_recording();
        state.phase = RewritePhase::AwaitingRecordingRefresh;
        state
            .recording_refresh
            .as_mut()
            .unwrap()
            .project_config_revision =
            super::super::fingerprint::project_config_revision(target.path()).unwrap();
        state
            .recording_refresh
            .as_mut()
            .unwrap()
            .source_traffic_policy_revision =
            super::super::fingerprint::source_traffic_policy_revision(target.path()).unwrap();
        let path = target.path().join(".traffic-e2e").join(filename);
        let mut bytes = fs::read(&path).unwrap();
        bytes.extend_from_slice(b"\n# changed after scheduling\n");
        fs::write(path, bytes).unwrap();
        let before = serde_json::to_value(&state).unwrap();
        let error = begin_pending_capture_refresh(target.path(), &mut state).unwrap_err();
        assert!(error.to_string().contains("changed after scheduling"));
        assert_eq!(serde_json::to_value(&state).unwrap(), before);
    }
}

fn recording_target() -> tempfile::TempDir {
    let target = tempfile::tempdir().unwrap();
    crate::rewrite::test_support::install_project_config(
        target.path(),
        "master",
        crate::rewrite::test_support::managed_test_recorder(),
        None,
    );
    fs::write(
        target.path().join(".traffic-e2e/verification.yaml"),
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();
    let mut policy = crate::config::SourceTrafficPolicyConfig::empty();
    policy.http.case_path_patterns = vec!["/widgets/*".to_string()];
    fs::write(
        target
            .path()
            .join(".traffic-e2e/source-traffic-policy.yaml"),
        policy.render().unwrap(),
    )
    .unwrap();
    for args in [
        vec!["init", "--quiet", "--initial-branch=master"],
        vec![
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.com",
            "commit",
            "--quiet",
            "--allow-empty",
            "-m",
            "baseline",
        ],
    ] {
        assert!(
            std::process::Command::new("git")
                .arg("-C")
                .arg(target.path())
                .args(args)
                .status()
                .unwrap()
                .success()
        );
    }
    target
}

fn write_recording(target: &Path, state: &RewriteState, status: &str, apis: &[(&str, &str)]) {
    let run = artifacts::recording_run(target, &state.recording_run_id);
    fs::create_dir_all(&run).unwrap();
    fs::write(
        run.join("recording-run.json"),
        serde_json::to_vec(&serde_json::json!({
            "run_id": state.recording_run_id,
            "status": status,
            "recording_apis": state.recording_apis,
            "published_cases": apis.len(),
        }))
        .unwrap(),
    )
    .unwrap();
    for (index, (pattern, uri)) in apis.iter().enumerate() {
        let case = run.join(format!("apis/api-{index}/case-{index}"));
        fs::create_dir_all(&case).unwrap();
        fs::write(
            case.join("request.json"),
            serde_json::to_vec(&serde_json::json!({
                "method": "GET", "uri": uri, "api_pattern": pattern,
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(case.join("expected-response.json"), "{}").unwrap();
    }
}

async fn next(target: &Path) -> RewriteActionEnvelope {
    crate::rewrite::next_rewrite(crate::rewrite::RewriteNextOptions {
        target_root: target.to_path_buf(),
        api: None,
        process_output: None,
        source_route: None,
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn finalized_refresh_installs_observed_apis_and_preserves_rare_history() {
    let target = recording_target();
    let mut historical = legacy_repair_recording();
    historical.recording_run_id = "20260801000000".to_string();
    write_recording(
        target.path(),
        &historical,
        "completed",
        &[("/rare-case", "/rare-case")],
    );
    let historical_run = artifacts::recording_run(target.path(), &historical.recording_run_id);
    let historical_request = historical_run.join("apis/api-0/case-0/request.json");
    let historical_before = fs::read(&historical_request).unwrap();

    let mut legacy = serde_json::to_value(legacy_repair_recording()).unwrap();
    legacy["recording_refresh"]["required_apis"] =
        serde_json::json!(["GET /widgets/*", "GET /rare-case"]);
    legacy["recording_refresh"]["baseline_case_source"] = serde_json::json!(historical_run);
    let mut state: RewriteState = serde_json::from_value(legacy).unwrap();
    state.api_catalog.insert("GET /rare-case".to_string());
    let original_run = state.recording_run_id.clone();
    write_recording(
        target.path(),
        &state,
        "completed",
        &[("/widgets/*", "/widgets/7")],
    );
    let store = RewriteStore::new(target.path()).unwrap();
    store.save(&state).unwrap();
    let manifest = artifacts::recording_manifest(target.path(), &original_run);
    let before = fs::read(&manifest).unwrap();
    assert!(matches!(
        action::for_status(target.path(), &state).unwrap().action,
        RewriteAction::AdvanceRequired { .. }
    ));

    let result = next(target.path()).await;
    assert!(
        matches!(result.action, RewriteAction::InputRequired { .. }),
        "{:?}",
        result.action
    );
    let installed = store.load().unwrap().unwrap();
    assert_eq!(installed.recording_run_id, original_run);
    assert!(installed.recording_refresh.is_none());
    assert_eq!(installed.api_inventory.len(), 1);
    assert_eq!(installed.api_inventory[0].api, "GET /widgets/*");
    assert!(installed.api_catalog.contains("GET /rare-case"));
    assert!(!installed.api_inventory[0].e2e_current);
    assert!(!result.terminal_allowed);
    assert_eq!(fs::read(manifest).unwrap(), before);
    assert_eq!(fs::read(historical_request).unwrap(), historical_before);
    assert!(artifacts::recording_manifest(target.path(), &historical.recording_run_id).exists());
}

#[test]
fn refreshed_recording_accepts_the_observed_apis_without_requiring_rare_history() {
    let target = recording_target();
    let mut legacy = serde_json::to_value(legacy_repair_recording()).unwrap();
    legacy["recording_refresh"]["required_apis"] =
        serde_json::json!(["GET /widgets/*", "GET /rare-case"]);
    let state: RewriteState = serde_json::from_value(legacy).unwrap();
    write_recording(
        target.path(),
        &state,
        "completed",
        &[("/widgets/*", "/widgets/7")],
    );

    artifacts::validate_standard_recording(target.path(), &state).unwrap();
    assert_eq!(
        artifacts::standard_recording_apis(target.path(), &state).unwrap(),
        ["GET /widgets/*"]
    );
    assert!(
        serde_json::to_value(&state).unwrap()["recording_refresh"]
            .get("required_apis")
            .is_none()
    );
}

#[test]
fn refreshed_recording_still_requires_completed_nonempty_evidence_and_matching_scope() {
    let target = recording_target();
    let state = legacy_repair_recording();
    for status in ["running", "failed"] {
        write_recording(
            target.path(),
            &state,
            status,
            &[("/widgets/*", "/widgets/7")],
        );
        assert!(artifacts::validate_standard_recording(target.path(), &state).is_err());
    }
    write_recording(target.path(), &state, "completed", &[]);
    assert!(artifacts::validate_standard_recording(target.path(), &state).is_err());
    write_recording(
        target.path(),
        &state,
        "completed",
        &[("/widgets/*", "/widgets/7")],
    );
    let mut different_scope = state;
    different_scope.recording_apis = vec!["GET /widgets/*".to_string()];
    assert!(artifacts::validate_standard_recording(target.path(), &different_scope).is_err());
}
