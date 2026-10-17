use super::*;
use crate::case_group::{CanonicalCase, CanonicalCaseGroup};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::e2e_run::test_session::{config, session};

#[test]
fn final_pipeline_classifies_once_and_keeps_shared_session_evidence_complete() {
    let temp = tempfile::tempdir().unwrap();
    let config = config(temp.path());
    let (layout, inventory, session) = session(temp.path());
    let mut selected = crate::e2e_run::focused_batch::project(&session, "OPTIONS /api");
    let mut method_inventory = inventory.clone();
    method_inventory
        .groups
        .retain(|group| group.method == "OPTIONS");
    let recorded = fs::read(layout.case_source.join("get-case/dependencies.jsonl")).unwrap();
    write_process_policy(
        &config.source_traffic_policy,
        json!({"protocol":"http","authorities":["stream.test"],"methods":["GET"],"path_prefixes":["/connect"]}),
    );
    // Classification requires the complete session inventory, while final
    // method evidence keeps the selected slice and all shared-session gates.
    let mut report = read_replay_report(&selected).unwrap();
    let classified =
        refresh_background_report(&config, &selected, &inventory, &mut report).unwrap();
    apply_reclassified_case_outcomes(&mut selected, &classified);
    fs::write(&selected.replay_report, b"the loaded report must be reused").unwrap();
    build_final_evidence_with_report(
        &config,
        &layout,
        &method_inventory,
        &mut selected,
        Some(&report),
    )
    .unwrap();
    assert!(selected.aggregate_complete && selected.aggregate_clean);
    assert!(selected.apis[0].complete_pass);
    let aggregate: Value =
        serde_json::from_slice(&fs::read(&selected.aggregate_report).unwrap()).unwrap();
    assert_eq!(
        aggregate["selected_case_ids"],
        json!(["get-case", "options-case"])
    );
    assert_eq!(
        aggregate["counts"]["events"]["http"]["unused_global_exchanges"],
        14
    );
    assert_eq!(report["unused_case_http_exchanges"], json!([]));
    store::write_json(&selected.replay_report, &report).unwrap();
    let before = fs::read(&selected.replay_report).unwrap();
    assert!(build_final_evidence(&config, &layout, &method_inventory, &mut selected).is_err());
    assert_eq!(fs::read(&selected.replay_report).unwrap(), before);
    let mut complete_session = session;
    build_final_evidence(&config, &layout, &inventory, &mut complete_session).unwrap();
    assert!(complete_session.aggregate_complete && complete_session.aggregate_clean);
    assert!(complete_session.apis.iter().all(|api| api.complete_pass));
    let persisted = read_replay_report(&complete_session).unwrap();
    assert_eq!(persisted, report);
    assert_eq!(
        fs::read(layout.case_source.join("get-case/dependencies.jsonl")).unwrap(),
        recorded
    );
}

#[test]
fn interrupted_reclassification_retries_and_rebuilds_published_method_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let config = config(root);
    let (layout, inventory, session) = session(root);
    let mut selected = crate::e2e_run::focused_batch::project(&session, "OPTIONS /api");
    let mut method_inventory = inventory.clone();
    method_inventory
        .groups
        .retain(|group| group.method == "OPTIONS");
    let original = selected.clone();
    let recorded = fs::read(layout.case_source.join("get-case/dependencies.jsonl")).unwrap();
    write_process_policy(
        &config.source_traffic_policy,
        json!({
            "protocol":"http","authorities":["stream.test"],
            "methods":["GET"],"path_prefixes":["/connect"]
        }),
    );
    let original_policy = fs::read(&config.source_traffic_policy).unwrap();
    let reclassified = refresh_background_evidence(&config, &selected, &inventory).unwrap();
    assert_eq!(reclassified.matched_unused_case, 14);
    apply_reclassified_case_outcomes(&mut selected, &reclassified);
    // Fail after report publication, before aggregate evidence can be committed.
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
    assert_eq!(
        fs::read(&config.source_traffic_policy).unwrap(),
        original_policy
    );
}

#[test]
fn method_reclassification_uses_immutable_dependencies_of_sibling_session_cases() {
    let temp = tempfile::tempdir().unwrap();
    let config = config(temp.path());
    let (layout, inventory, session) = session(temp.path());
    let selected = crate::e2e_run::focused_batch::project(&session, "OPTIONS /api");
    write_process_policy(
        &config.source_traffic_policy,
        json!({
            "protocol":"redis","ports":[6379],"operation":"SCARD", "initial_load_timeout_ms":60000,
            "keys":[{"kind":"exact","value":"startup:cache"}]
        }),
    );
    let dependency = json!({"event_type":"redis_exchange","connection_id":"connection","sequence":1,
        "target_host":"redis.test","target_port":6379,"database":0,"command":"SCARD",
        "outcome":"response","args":[{"encoding":"utf8","data":"startup:cache","truncated":false}],
        "response":{"encoding":"utf8","data":":1\r\n","truncated":false},"replay_safe":true});
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

fn write_process_policy(path: &Path, selector: Value) {
    let document = json!({"format":"traffic-policy/v1","rules":[{
        "id":"process-startup","match":{},
        "effect":{"kind":"process_owned","source_revision":format!("sha256:{}", "1".repeat(64)),"selector":selector},
        "proof":{"source":"startup.rs:run","fact":"Source starts this process-wide dependency independently of API calls"}
    }]});
    crate::policy::compile_policy(&serde_json::from_value(document.clone()).unwrap()).unwrap();
    fs::write(path, serde_yaml::to_string(&document).unwrap()).unwrap();
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
