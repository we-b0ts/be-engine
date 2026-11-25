use super::*;
use crate::{
    case_selection::{self, ReplayIteration},
    dependency::observation::{
        CaptureCoverage, RecordedCase, RecordingManifest, SemanticInventory, SourceArtifactIdentity,
    },
    focused_batch,
    model::{CaseStatus, RunStatus},
    test_session,
};
use serde_json::json;

struct Fixture {
    layout: super::super::model::RunLayout,
    inventory: crate::case_group::CaseGroupInventory,
    state: ActiveRunState,
    manifest: RecordingManifest,
    report: Value,
}

fn fixture(root: &Path) -> Fixture {
    let (layout, mut inventory, _) = test_session::session(root);
    let mut report: Value = serde_json::from_slice(
        &fs::read(layout.active_dir.join("reports/replay-report.json")).unwrap(),
    )
    .unwrap();
    for (index, group) in inventory.groups.iter_mut().enumerate() {
        let case = &mut group.cases[0];
        let id = Uuid::from_u128(index as u128 + 1).to_string();
        let path = layout.case_source.join(&id);
        fs::rename(&case.case_dir, &path).unwrap();
        case.case_id = id;
        case.case_dir = path;
    }
    let selection = case_selection::prepare(
        &layout,
        &mut inventory,
        Some(&ReplayIteration {
            workflow_id: "workflow-current".into(),
            final_round: true,
        }),
    )
    .unwrap();
    let mut state = ActiveRunState::new(layout.run_key.clone(), 7, &inventory, &layout.active_dir);
    state.case_selection = selection;
    state.session_id = Some("one-real-session".into());
    state.executed_replay_identity = Some("frozen-runtime".into());
    state.status = RunStatus::Successful;
    state.finished_at = Some(chrono::Utc::now());
    state.replay_finalized = true;
    state.aggregate_complete = true;
    state.aggregate_clean = true;
    for (index, case) in state.cases.iter_mut().enumerate() {
        case.status = CaseStatus::Passed;
        case.assertion_passed = Some(true);
        case.replay_clean = Some(true);
        let actual = layout.active_dir.join(format!("actual-{index}.json"));
        fs::write(&actual, "{}").unwrap();
        let detail_path = layout
            .active_dir
            .join(format!("reports/assertion-{index}.json"));
        let detail = json!({"passed":true,"case_id":case.case_id,"differences":[],
            "policy_fingerprint":"policy","actual_response_path":actual,
            "request_path":case.case_dir.join("request.json"),
            "expected_response_path":case.case_dir.join("expected-response.json"),
            "expected_response_fingerprint":crate::verification_progress::fingerprint(b"{}"),
            "actual_response_fingerprint":crate::verification_progress::fingerprint(b"{}")});
        store::write_json(&detail_path, &detail).unwrap();
        case.response_assertion = Some(serde_json::from_value(json!({
            "passed":true,"method":case.group_id.split_once(' ').unwrap().0,"path":"/api",
            "gateway_protocol":"http","body_codec":"json","difference_count":0,
            "detail_report":detail_path,"detail_fingerprint":crate::verification_progress::fingerprint(&fs::read(&detail_path).unwrap()),
            "request":case.case_dir.join("request.json"),"expected_response":case.case_dir.join("expected-response.json"),
            "actual_response":actual,"policy_path":"/policy","policy_fingerprint":"policy"
        })).unwrap());
    }
    let manifest = RecordingManifest {
        schema: crate::dependency::observation::RECORDING_SCHEMA.into(),
        run_id: "recording".into(),
        run_epoch: Uuid::from_u128(100),
        process_epochs: vec![Uuid::from_u128(101)],
        capture_policy_identity: "capture".into(),
        source_artifact: SourceArtifactIdentity::Unavailable {
            reason: "synthetic fixture".into(),
        },
        sealed: true,
        capture_complete: true,
        coverage: CaptureCoverage::default(),
        records: 0,
        unattributed_records: 0,
        semantic_inventory: SemanticInventory::default(),
        inputs: state
            .cases
            .iter()
            .map(|case| RecordedCase {
                case_id: case.case_id.parse().unwrap(),
                path: case.case_id.clone(),
                complete: true,
            })
            .collect(),
        files: vec![],
    };
    let selected: BTreeSet<_> = state
        .cases
        .iter()
        .map(|case| case.case_id.clone())
        .collect();
    report["cases"] = json!(
        selected
            .iter()
            .map(|id| json!({"case_id":id,"status":"ended"}))
            .collect::<Vec<_>>()
    );
    report["selected_case_ids"] = json!(selected);
    report["session_id"] = json!(state.session_id);
    report["complete"] = json!(true);
    report["active_case_id"] = Value::Null;
    report["unused_case_http_exchanges"] = json!([]);
    report["dependency_pre_matches"] = json!([]);
    report["dependency_attribution_snapshot"] = json!("owners");
    report["replay_policy"] = json!({"fingerprint":"policy","path":"/policy","expected_response":"assertions_only","unused_applicable_dependency_rule_ids":[]});
    report["batch_reconciliation"] = json!({"schema":"dependency-reconciliation/v3",
        "session_id":state.session_id,"source_capture_complete":true,"execution_complete":true,
        "complete_source_scope":true,"selected_cases":selected,"required_cases":selected,
        "source_inventory_id":"manifest","recording_run_id":manifest.run_id,"recording_run_epoch":manifest.run_epoch,
        "process_epochs":manifest.process_epochs,"dependency_attribution_snapshot":"owners",
        "source_inventory":manifest.semantic_inventory,"provisional_hypotheses_used":false,
        // WholeSource remains explicitly unverified even when API contracts pass.
        "dependency_inventory_verified":false,"startup_phase_complete":false,
        "unused_run_dependencies":{"redis":10},"actual_unmatched_or_unsafe":1});
    report["startup_phase"] = json!({"status":"dirty"});
    report["unmatched_queries"] = json!([{"query":"unimplemented startup task"}]);
    report["redis"]["unused_global"] = json!([{"owner":"process"}]);
    store::write_json(&state.replay_report, &report).unwrap();
    store::write_json(
        &layout.active_dir.join("reports/target-stop.json"),
        &json!({"status":"stopped","exit_code":0,"removed":true,"container_name":"actual-target"}),
    )
    .unwrap();
    super::super::final_evidence::build_final_evidence(
        &test_session::config(root),
        &layout,
        &inventory,
        &mut state,
    )
    .unwrap();
    Fixture {
        layout,
        inventory,
        state,
        manifest,
        report,
    }
}

fn report_valid(f: &Fixture, report: &Value) -> Result<()> {
    let selected = f
        .state
        .cases
        .iter()
        .map(|case| case.case_id.clone())
        .collect();
    validation::session_report(
        report,
        &f.state,
        &selected,
        &selected,
        &f.manifest,
        "manifest",
        "owners",
        "policy",
    )
}

#[test]
fn complete_unselected_methods_need_no_implementation_or_case_group_for_workflow_receipt() {
    let root = tempfile::tempdir().unwrap();
    let mut f = fixture(root.path());
    let id = Uuid::from_u128(999);
    f.manifest.inputs.push(RecordedCase {
        case_id: id,
        path: id.to_string(),
        complete: true,
    });
    let path = f.layout.case_source.join(id.to_string());
    fs::create_dir_all(&path).unwrap();
    fs::write(
        path.join("request.json"),
        r#"{"method":"DELETE","uri":"/unimplemented"}"#,
    )
    .unwrap();
    fs::write(path.join("expected-response.json"), "{}").unwrap();
    fs::write(path.join("dependencies.jsonl"), "").unwrap();
    let methods = f
        .inventory
        .groups
        .iter()
        .map(|group| group.group_id.parse::<crate::RecordingApi>().unwrap())
        .collect::<Vec<_>>();
    let selected: BTreeSet<_> =
        crate::case_group::resolve_recording_api_case_ids(&f.layout.case_source, &methods)
            .unwrap()
            .into_iter()
            .collect();
    let all: BTreeSet<_> = f
        .manifest
        .inputs
        .iter()
        .map(|input| input.case_id.to_string())
        .collect();
    assert_eq!(selected.len(), 2);
    assert_eq!(all.len(), 3);
    f.report["batch_reconciliation"]["required_cases"] = json!(all);
    f.report["batch_reconciliation"]["complete_source_scope"] = json!(false);
    validation::complete_source(&f.manifest).unwrap();
    validation::session_report(
        &f.report,
        &f.state,
        &selected,
        &all,
        &f.manifest,
        "manifest",
        "owners",
        "policy",
    )
    .unwrap();
    assert!(
        crate::protocols::replay::report::validation::validate_completed_receipt(&f.report)
            .is_err()
    );
}

#[test]
fn one_fresh_multimethod_session_can_certify_api_contracts_while_whole_source_remains_dirty() {
    let root = tempfile::tempdir().unwrap();
    let f = fixture(root.path());
    validation::complete_source(&f.manifest).unwrap();
    report_valid(&f, &f.report).unwrap();
    assert!(
        crate::protocols::replay::report::validation::validate_completed_receipt(&f.report)
            .is_err()
    );
    assert!(f.state.aggregate_complete && f.state.aggregate_clean);
    let mut global = f.layout.clone();
    global.run_root = root.path().join("published");
    focused_batch::publish(&global, &f.layout, &f.state).unwrap();
    let mut projections = Vec::new();
    let mut reports = BTreeSet::new();
    for group in &f.inventory.groups {
        let latest = global
            .run_root
            .join("focused")
            .join(support::api_directory(&group.group_id))
            .join("latest");
        let state: ActiveRunState = store::read_yaml(&latest.join("state.yaml")).unwrap();
        validation::projection(&state, group, &f.inventory, &global).unwrap();
        validation::response_and_stop(&state, &latest, "policy", &mut BTreeMap::new()).unwrap();
        reports.insert(fs::read(&state.replay_report).unwrap());
        projections.push(state);
    }
    validation::one_session(&projections).unwrap();
    assert_eq!(
        reports.len(),
        1,
        "publication retains the same complete actual report bytes"
    );
}

#[test]
fn historical_passes_retry_subsets_and_different_workflows_cannot_form_one_session() {
    let root = tempfile::tempdir().unwrap();
    let f = fixture(root.path());
    let first = focused_batch::project(&f.state, &f.inventory.groups[0].group_id);
    let second = focused_batch::project(&f.state, &f.inventory.groups[1].group_id);
    for mutation in 0..5 {
        let mut other = second.clone();
        match mutation {
            0 => other.session_id = Some("other-session".into()),
            1 => other.sequence += 1,
            2 => other.executed_replay_identity = Some("older-runtime".into()),
            3 => other.finished_at = Some(chrono::Utc::now() + chrono::Duration::seconds(1)),
            _ => {
                let mut value = serde_json::to_value(&other).unwrap();
                value["case_selection"]["workflow_id"] = json!("older-workflow");
                other = serde_json::from_value(value).unwrap();
            }
        }
        assert!(
            validation::one_session(&[first.clone(), other]).is_err(),
            "mutation {mutation}"
        );
    }
    for mutation in 0..3 {
        let mut value = serde_json::to_value(&first).unwrap();
        match mutation {
            0 => value["case_selection"]["final_round"] = json!(false),
            1 => {
                value["case_selection"]["skipped_passed_case_ids"] = json!([first.cases[0].case_id])
            }
            _ => value["case_selection"] = Value::Null,
        }
        let state: ActiveRunState = serde_json::from_value(value).unwrap();
        assert!(
            validation::projection(&state, &f.inventory.groups[0], &f.inventory, &f.layout)
                .is_err()
        );
    }
}

#[test]
fn session_report_cannot_hide_cases_or_change_immutable_source_policy_or_ownership() {
    let root = tempfile::tempdir().unwrap();
    let f = fixture(root.path());
    for mutation in 0..10 {
        let mut report = f.report.clone();
        match mutation {
            0 => {
                report["cases"].as_array_mut().unwrap().pop();
            }
            1 => report["cases"][0]["status"] = json!("active"),
            2 => report["batch_reconciliation"]["required_cases"] = json!([]),
            3 => report["batch_reconciliation"]["source_inventory_id"] = json!("changed"),
            4 => report["batch_reconciliation"]["dependency_attribution_snapshot"] = json!("old"),
            5 => report["replay_policy"]["fingerprint"] = json!("old"),
            6 => {
                report["batch_reconciliation"]["source_inventory"]["unattributed_dependencies"] =
                    json!(1)
            }
            7 => report["batch_reconciliation"]["provisional_hypotheses_used"] = json!(true),
            8 => report["finalized"] = json!(false),
            _ => report["target_observation_coverage_error"] = json!("omitted"),
        }
        assert!(report_valid(&f, &report).is_err(), "mutation {mutation}");
    }
    let mut clean = f.report.clone();
    clean
        .as_object_mut()
        .unwrap()
        .remove("dependency_pre_matches");
    report_valid(&f, &clean).unwrap();
    clean["dependency_pre_matches"] = json!([{"provisional":true}]);
    assert!(report_valid(&f, &clean).is_err());
}

#[test]
fn known_unsupported_startup_process_and_other_methods_remain_outside_workflow_contracts() {
    let root = tempfile::tempdir().unwrap();
    let f = fixture(root.path());
    let mut report = f.report.clone();
    for scope in ["startup", "process", "another-unselected-case"] {
        report["batch_reconciliation"]["source_inventory"]["unsupported_by_scope"][scope] =
            json!({"unknown":3});
    }
    report_valid(&f, &report).unwrap();
    let selected = &f.state.cases[0].case_id;
    report["batch_reconciliation"]["source_inventory"]["unsupported_by_scope"][selected] =
        json!({"unknown":1});
    assert!(report_valid(&f, &report).is_err());
}

#[test]
fn incomplete_unselected_source_inputs_are_never_hidden_by_a_clean_workflow_scope() {
    let root = tempfile::tempdir().unwrap();
    let f = fixture(root.path());
    for mutation in 0..5 {
        let mut manifest = f.manifest.clone();
        match mutation {
            0 => manifest.capture_complete = false,
            1 => manifest.inputs.push(RecordedCase {
                case_id: Uuid::new_v4(),
                path: "failed/unselected".into(),
                complete: false,
            }),
            2 => manifest.coverage.inventory_gaps = true,
            3 => manifest.sealed = false,
            _ => manifest.coverage.capture_failures = 4,
        }
        assert!(
            validation::complete_source(&manifest).is_err(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn clean_status_alone_cannot_replace_genuine_primary_response_and_target_stop_artifacts() {
    let root = tempfile::tempdir().unwrap();
    let f = fixture(root.path());
    let state = focused_batch::project(&f.state, &f.inventory.groups[0].group_id);
    validation::response_and_stop(&state, &f.layout.active_dir, "policy", &mut BTreeMap::new())
        .unwrap();
    fs::write(
        &state.cases[0]
            .response_assertion
            .as_ref()
            .unwrap()
            .actual_response,
        "changed",
    )
    .unwrap();
    assert!(
        validation::response_and_stop(&state, &f.layout.active_dir, "policy", &mut BTreeMap::new())
            .is_err()
    );
    fs::write(
        &state.cases[0]
            .response_assertion
            .as_ref()
            .unwrap()
            .actual_response,
        "{}",
    )
    .unwrap();
    store::write_json(
        &f.layout.active_dir.join("reports/target-stop.json"),
        &json!({"status":"stopped","exit_code":0,"removed":false,"container_name":"still-running"}),
    )
    .unwrap();
    assert!(
        validation::response_and_stop(&state, &f.layout.active_dir, "policy", &mut BTreeMap::new())
            .is_err()
    );
}
