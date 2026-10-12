use super::*;
use crate::case_group::{CanonicalCase, CanonicalCaseGroup};
use crate::{BackgroundDependencyFeedback, plan_background_dependency};
use serde_json::{Value, json};
use std::{fs, path::PathBuf};

use crate::e2e_run::test_session::{config, session};

#[test]
fn interrupted_apply_retries_reclassification_and_rebuilds_published_method_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let config = config(root);
    fs::write(&config.source_traffic_policy, "version: 2\n").unwrap();
    let (layout, inventory, session) = session(root);
    let mut selected = crate::e2e_run::focused_batch::project(&session, "OPTIONS /api");
    let mut method_inventory = inventory.clone();
    method_inventory
        .groups
        .retain(|group| group.method == "OPTIONS");
    let original = selected.clone();
    let recorded = fs::read(layout.case_source.join("get-case/dependencies.jsonl")).unwrap();
    let replay_report = selected.replay_report.clone();
    let feedback = || BackgroundDependencyFeedback {
        rules_path: config.source_traffic_policy.clone(),
        replay_report_path: replay_report.clone(),
        name: "stream-startup".into(),
        authority: "stream.test".into(),
        method: "GET".into(),
        path_prefix: "/connect".into(),
        source_revision: "source".into(),
        source_evidence: "startup.rs:run starts process-wide stream".into(),
    };
    plan_background_dependency(feedback())
        .unwrap()
        .apply()
        .unwrap();
    let reclassified = refresh_background_evidence(&config, &selected, &inventory).unwrap();
    assert_eq!(reclassified.matched_unused_case, 14);
    apply_reclassified_case_outcomes(&mut selected, &reclassified);
    // Fail after policy/report publication, before the coordinator can retire its plan.
    fs::create_dir_all(&selected.aggregate_report).unwrap();
    assert!(
        build_final_evidence_from_current_report(
            &config,
            &layout,
            &method_inventory,
            &mut selected
        )
        .is_err()
    );
    fs::remove_dir(&selected.aggregate_report).unwrap();

    let retry = plan_background_dependency(feedback()).unwrap();
    assert!(retry.report().reused_existing);
    assert_eq!(retry.report().matched_unused_exchanges, 14);
    retry.apply().unwrap();
    let mut selected = original;
    let reclassified = refresh_background_evidence(&config, &selected, &inventory).unwrap();
    assert_eq!(reclassified.matched_unused_case, 14);
    apply_reclassified_case_outcomes(&mut selected, &reclassified);
    build_final_evidence_from_current_report(&config, &layout, &method_inventory, &mut selected)
        .unwrap();
    assert!(selected.aggregate_complete && selected.aggregate_clean);
    assert_eq!(selected.cases.len(), 1);
    assert_eq!(selected.cases[0].case_id, "options-case");
    assert!(selected.apis[0].complete_pass);
    let aggregate: Value =
        serde_json::from_slice(&fs::read(&selected.aggregate_report).unwrap()).unwrap();
    assert_eq!(
        aggregate["selected_case_ids"],
        json!(["get-case", "options-case"])
    );
    let report: Value =
        serde_json::from_slice(&fs::read(&selected.replay_report).unwrap()).unwrap();
    assert_eq!(report["unused_case_http_exchanges"], json!([]));
    assert_eq!(
        report["unused_global_http_exchanges"]
            .as_array()
            .unwrap()
            .len(),
        14
    );
    assert_eq!(
        fs::read(layout.case_source.join("get-case/dependencies.jsonl")).unwrap(),
        recorded
    );
}

#[test]
fn method_reclassification_uses_immutable_dependencies_of_sibling_session_cases() {
    let temp = tempfile::tempdir().unwrap();
    let config = config(temp.path());
    let (layout, inventory, session) = session(temp.path());
    let selected = crate::e2e_run::focused_batch::project(&session, "OPTIONS /api");
    fs::write(
        &config.source_traffic_policy,
        r#"version: 2
process_owned_dependencies:
  - protocol: redis
    name: cache-warm
    ports: [6379]
    command: SCARD
    initial_load_timeout_ms: 60000
    keys: [startup:cache]
    source_evidence: startup.rs scheduled cache warm
"#,
    )
    .unwrap();
    let dependency = json!({"event_type":"redis_exchange","connection_id":"connection","sequence":1,
        "target_port":6379,"command":"SCARD","args":[{"encoding":"utf8","data":"startup:cache"}],"replay_safe":true});
    fs::write(
        layout.case_source.join("get-case/dependencies.jsonl"),
        dependency.to_string(),
    )
    .unwrap();
    let mut report: Value =
        serde_json::from_slice(&fs::read(&session.replay_report).unwrap()).unwrap();
    report["redis"]["unused_case"] = json!([{"case_id":"get-case","connection_id":"connection","sequence":1,
        "command":"SCARD","target":{"host":"redis.test","port":6379}}]);
    store::write_json(&session.replay_report, &report).unwrap();
    let classified = refresh_background_evidence(&config, &selected, &inventory).unwrap();
    assert_eq!(classified.by_protocol["redis"], 1);
    // The unrelated HTTP evidence remains dirty for the shared session.
    assert!(classified.remaining_dirty_case_ids.contains("get-case"));
}

#[test]
fn assertion_report_omits_cases_without_an_assertion_result() {
    let inventory = CaseGroupInventory {
        case_source: PathBuf::from("/cases"),
        source_revision: "source".to_string(),
        case_inventory_id: "inventory".to_string(),
        groups: vec![CanonicalCaseGroup {
            group_id: "GET /api/devices".to_string(),
            method: "GET".to_string(),
            source_route: "/api/devices".to_string(),
            pattern: None,
            case_inventory_id: "inventory".to_string(),
            cases: ["passed", "failed", "pending"]
                .into_iter()
                .map(|case_id| CanonicalCase {
                    case_id: case_id.to_string(),
                    case_dir: PathBuf::from("/cases").join(case_id),
                    recorded_at: None,
                })
                .collect(),
        }],
    };
    let temp = tempfile::tempdir().unwrap();
    let mut state = ActiveRunState::new("run".to_string(), 1, &inventory, temp.path());
    let passed = state
        .cases
        .iter_mut()
        .find(|case| case.case_id == "passed")
        .unwrap();
    passed.assertion_passed = Some(true);
    passed.status = CaseStatus::Passed;
    let failed = state
        .cases
        .iter_mut()
        .find(|case| case.case_id == "failed")
        .unwrap();
    failed.assertion_passed = Some(false);
    failed.status = CaseStatus::Failed;

    let report = assertion_report(
        &state,
        true,
        state.cases.iter().map(|case| case.case_id.as_str()),
    );

    assert_eq!(report.cases.len(), 2);
    assert!(
        report
            .cases
            .iter()
            .any(|case| case.case_id == "passed" && case.passed)
    );
    assert!(
        report
            .cases
            .iter()
            .any(|case| case.case_id == "failed" && !case.passed)
    );
}
