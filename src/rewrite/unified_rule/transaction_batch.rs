//! Batch authoring uses real full-run state without borrowing an API worker.
use super::*;
use serde_json::Value;

fn install_actual_batch(fixture: &Fixture) -> PathBuf {
    let mut workflow = fixture.state();
    let source = workflow.case_source.clone().unwrap();
    let revision = crate::rewrite::test_support::install_source_snapshot(fixture.root());
    let focused = fixture.paths.replay.parent().unwrap().parent().unwrap();
    let run = focused
        .ancestors()
        .find(|path| path.file_name().is_some_and(|name| name == "focused"))
        .unwrap()
        .parent()
        .unwrap();
    let index = run.join("case-groups.json");
    fs::remove_file(&index).unwrap();
    crate::case_group::ensure_case_group(crate::CaseGroupOptions {
        case_source: source.clone(),
        case_dir: source.join("apis"),
        method: "GET".into(),
        source_route: "/api".into(),
        pattern: None,
        source_revision: revision.clone(),
        output: index.clone(),
        recorder_config: None,
    })
    .unwrap();
    let inventory = crate::case_group::load_complete_case_group_inventory(&index, &source).unwrap();
    let full = run.join("latest");
    fs::create_dir_all(full.join("reports")).unwrap();
    let mut state: Value =
        serde_yaml::from_str(&fs::read_to_string(focused.join("state.yaml")).unwrap()).unwrap();
    let session = uuid::Uuid::new_v4().to_string();
    state["source_revision"] = json!(revision);
    state["case_inventory_id"] = json!(inventory.case_inventory_id);
    state["status"] = json!("failed");
    state["finished_at"] = json!(chrono::Utc::now());
    state["session_id"] = json!(session);
    state["executed_replay_identity"] =
        json!(crate::rewrite::batch_execution_identity(fixture.root()).unwrap());
    state.as_object_mut().unwrap().remove("case_selection");
    for case in state["cases"].as_array_mut().unwrap() {
        case["status"] = json!("failed");
        case["assertion_passed"] = json!(false);
        case["replay_clean"] = json!(true);
    }
    for (field, name) in [
        ("replay_report", "replay-report.json"),
        ("assertions_report", "assertions.json"),
        ("aggregate_report", "aggregate.json"),
    ] {
        let original = PathBuf::from(state[field].as_str().unwrap());
        let destination = full.join("reports").join(name);
        fs::copy(original, &destination).unwrap();
        state[field] = json!(destination);
    }
    workflow.source_revision = Some(revision);
    workflow.recording_run_id = source.file_name().unwrap().to_str().unwrap().into();
    workflow.active_issue = None;
    workflow.replay_identity =
        Some(crate::rewrite::batch_execution_identity(fixture.root()).unwrap());
    fixture.store().save(&workflow).unwrap();
    let manifest: Value =
        serde_json::from_slice(&fs::read(source.join("dependency-manifest.json")).unwrap())
            .unwrap();
    let snapshot =
        crate::rewrite::dependency_attribution_snapshot(fixture.root(), &workflow.recording_run_id)
            .unwrap();
    let cases = inventory
        .groups
        .iter()
        .flat_map(|group| group.cases.iter().map(|case| case.case_id.clone()))
        .collect::<Vec<_>>();
    let mut report: Value =
        serde_json::from_slice(&fs::read(full.join("reports/replay-report.json")).unwrap())
            .unwrap();
    report["session_id"] = json!(session);
    report["dependency_attribution_snapshot"] = json!(snapshot);
    report["batch_reconciliation"] = json!({"schema":"dependency-reconciliation/v3","session_id":session,"source_inventory_id":crate::policy_evidence::digest(&fs::read(source.join("dependency-manifest.json")).unwrap()),"recording_run_id":workflow.recording_run_id,"recording_run_epoch":manifest["run_epoch"],"process_epochs":manifest["process_epochs"],"dependency_attribution_snapshot":snapshot,"complete_source_scope":true,"source_capture_complete":true,"execution_complete":true,"selected_cases":cases,"required_cases":cases});
    write(&full.join("reports/replay-report.json"), report);
    fs::write(
        full.join("state.yaml"),
        serde_yaml::to_string(&state).unwrap(),
    )
    .unwrap();
    full
}

#[test]
fn dirty_full_batch_can_plan_and_apply_without_fabricating_api_issue_or_acceptance() {
    let fixture = Fixture::new();
    let full = install_actual_batch(&fixture);
    let evidence =
        crate::rewrite::unified_rule::batch::information(fixture.root(), &fixture.state()).unwrap();
    assert_eq!(evidence["assignment"]["role"], "repository_analyst");
    assert!(fixture.state().active_issue.is_none());
    let report_before = fs::read(full.join("reports/replay-report.json")).unwrap();
    let plan = plan_rewrite_unified_rule(
        fixture.context(),
        RewriteUnifiedRulePlanOptions {
            file: fixture.proposal.clone(),
            evidence_id: evidence["evidence_id"].as_str().unwrap().into(),
        },
    )
    .unwrap();
    assert_eq!(plan.traffic_e2e_report["evidence_scope"]["scope"], "batch");
    let applied = apply_rewrite_rule(fixture.context(), &plan.plan_id).unwrap();
    assert_eq!(applied.traffic_e2e_report["requires_fresh_replay"], true);
    assert_eq!(
        applied.traffic_e2e_report["replay_scope"]["kind"],
        "complete_source_run"
    );
    assert_eq!(
        fs::read(full.join("reports/replay-report.json")).unwrap(),
        report_before
    );
    let state = fixture.state();
    assert!(state.active_issue.is_none());
    assert!(!state.e2e_current && state.dependency_review.batch_receipt.is_none());
}

#[test]
fn batch_evidence_cannot_survive_a_proof_revision_change_or_hide_missing_execution() {
    let fixture = Fixture::new();
    let full = install_actual_batch(&fixture);
    let evidence =
        crate::rewrite::unified_rule::batch::information(fixture.root(), &fixture.state()).unwrap();
    let mut state = fixture.state();
    state.dependency_review.revision += 1;
    fixture.store().save(&state).unwrap();
    assert!(
        plan_rewrite_unified_rule(
            fixture.context(),
            RewriteUnifiedRulePlanOptions {
                file: fixture.proposal.clone(),
                evidence_id: evidence["evidence_id"].as_str().unwrap().into()
            }
        )
        .is_err()
    );
    let path = full.join("state.yaml");
    let mut actual: Value = serde_yaml::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    actual["cases"][0]["assertion_passed"] = Value::Null;
    fs::write(&path, serde_yaml::to_string(&actual).unwrap()).unwrap();
    assert!(
        crate::rewrite::unified_rule::batch::information(fixture.root(), &fixture.state()).is_err()
    );
}
