use super::*;
use crate::case_group::{CanonicalCase, CanonicalCaseGroup, CaseGroupInventory};
use crate::e2e_run::model::CaseStatus;

fn state(root: &Path) -> ActiveRunState {
    let inventory = CaseGroupInventory {
        case_source: root.join("cases"),
        source_revision: "source".into(),
        case_inventory_id: "inventory".into(),
        groups: ["GET /api", "PUT /api"]
            .into_iter()
            .enumerate()
            .map(|(i, api)| CanonicalCaseGroup {
                group_id: api.into(),
                method: api.split_once(' ').unwrap().0.into(),
                source_route: "/api".into(),
                pattern: None,
                case_inventory_id: "inventory".into(),
                cases: vec![CanonicalCase {
                    case_id: format!("case-{i}"),
                    case_dir: root.join(format!("case-{i}")),
                    recorded_at: None,
                }],
            })
            .collect(),
    };
    let mut state = ActiveRunState::new("run".into(), 3, &inventory, root);
    state.status = RunStatus::Failed;
    state.replay_finalized = true;
    state.aggregate_complete = true;
    state.aggregate_clean = true;
    for case in &mut state.cases {
        let passed = case.group_id == "GET /api";
        case.status = if passed {
            CaseStatus::Passed
        } else {
            CaseStatus::Failed
        };
        case.assertion_passed = Some(passed);
        case.replay_clean = Some(true);
    }
    let layout = layout(root);
    super::super::final_evidence::summarize_apis_without_aggregate(&layout, &mut state, &inventory);
    for api in &mut state.apis {
        api.complete_pass = api.group_id == "GET /api";
    }
    state
}

#[test]
fn route_response_failure_keeps_passing_method_evidence() {
    let mut state = state(Path::new("/runtime"));
    state.errors.push(
        "API \"PUT /api\" stopped after reaching the configured failure limit of 3 case(s)".into(),
    );
    let get = project(&state, "GET /api");
    let put = project(&state, "PUT /api");
    assert_eq!(get.status, RunStatus::Successful);
    assert_eq!(put.status, RunStatus::Failed);
    assert_eq!(get.cases.len(), 1);
    assert_eq!(put.cases.len(), 1);
    assert_ne!(get.cases[0].case_id, put.cases[0].case_id);
    assert_eq!(get.sequence, put.sequence);
    let mut dirty = state;
    dirty.aggregate_clean = false;
    assert_eq!(project(&dirty, "GET /api").status, RunStatus::Failed);
}

fn layout(root: &Path) -> RunLayout {
    RunLayout {
        target_root: root.into(),
        run_key: "run".into(),
        case_source: root.join("cases"),
        progress_path: root.join("progress.yaml"),
        legacy_progress_path: root.join("legacy-progress.yaml"),
        internal_root: root.join("internal"),
        current_path: root.join("current"),
        run_root: root.join("run"),
        index_path: root.join("index.yaml"),
        group_index_path: root.join("groups.json"),
        active_dir: root.into(),
        latest_dir: root.join("latest"),
    }
}

#[test]
fn method_publication_retains_separate_readable_snapshots() {
    let temporary = tempfile::tempdir().unwrap();
    let global = layout(temporary.path());
    let mut primary = global.clone();
    primary.run_root = global
        .run_root
        .join("focused")
        .join(api_directory("GET /api"));
    primary.active_dir = primary.run_root.join(".active");
    primary.latest_dir = primary.run_root.join("latest");
    let mut state = state(&primary.active_dir);
    fs::create_dir_all(&primary.active_dir).unwrap();
    fs::write(
        primary.active_dir.join("target.log"),
        "one shared target session",
    )
    .unwrap();
    fs::create_dir_all(primary.active_dir.join("reports")).unwrap();
    store::write_json(
        &state.replay_report,
        &serde_json::json!({"version":6,"finalized":true,"cases":[]}),
    )
    .unwrap();
    fs::create_dir_all(primary.active_dir.join("tmp")).unwrap();
    for (index, case) in state.cases.iter_mut().enumerate() {
        let actual = primary.active_dir.join(format!("tmp/actual-{index}.json"));
        fs::write(&actual, "{}").unwrap();
        let detail = primary
            .active_dir
            .join(format!("reports/assertion-detail-{index}.json"));
        store::write_json(&detail,&serde_json::json!({"actual_response_path":actual,"request_path":case.case_dir.join("request.json")})).unwrap();
        case.response_assertion = Some(serde_json::from_value(serde_json::json!({
            "passed":case.status == CaseStatus::Passed,"method":case.group_id.split_once(' ').unwrap().0,"path":"/api",
            "gateway_protocol":"http","body_codec":"json","difference_count":0,"detail_report":detail,
            "detail_fingerprint":crate::verification_progress::fingerprint(&fs::read(&detail).unwrap()),
            "request":case.case_dir.join("request.json"),"expected_response":case.case_dir.join("expected-response.json"),
            "actual_response":actual,"policy_path":"/target/verification.yaml","policy_fingerprint":"policy"
        })).unwrap());
    }
    for api in &state.apis {
        fs::create_dir_all(&api.report_dir).unwrap();
        let mut report = super::super::model::AssertionReport::new(&state, true);
        report.cases = state
            .cases
            .iter()
            .filter(|case| case.group_id == api.group_id)
            .map(|case| super::super::model::AssertionCase {
                case_id: case.case_id.clone(),
                passed: case.status == CaseStatus::Passed,
                response: case.response_assertion.clone(),
            })
            .collect();
        store::write_json(&api.report_dir.join("assertions.json"), &report).unwrap();
        store::write_json(
            &api.report_dir.join("aggregate.json"),
            &serde_json::json!({
                "reports":[{"path":state.replay_report}]
            }),
        )
        .unwrap();
    }
    publish(&global, &primary, &state).unwrap();
    for (api, expected) in [
        ("GET /api", RunStatus::Successful),
        ("PUT /api", RunStatus::Failed),
    ] {
        let latest = global
            .run_root
            .join("focused")
            .join(api_directory(api))
            .join("latest");
        let snapshot: ActiveRunState = store::read_yaml(&latest.join("state.yaml")).unwrap();
        assert_eq!(snapshot.status, expected);
        assert_eq!(snapshot.cases.len(), 1);
        assert_eq!(snapshot.apis[0].group_id, api);
        assert!(snapshot.aggregate_report.starts_with(&latest));
        assert_eq!(
            snapshot.replay_report,
            latest.join("reports/replay-report.json")
        );
        crate::replay::report::read_dependency_evidence(&snapshot.replay_report).unwrap();
        let aggregate: serde_json::Value =
            serde_json::from_slice(&fs::read(&snapshot.aggregate_report).unwrap()).unwrap();
        assert_eq!(
            aggregate["reports"][0]["path"],
            serde_json::json!(snapshot.replay_report)
        );
        assert!(latest.join("target.log").is_file());
        assert!(!latest.parent().unwrap().join(".active").exists());
        let response = snapshot.cases[0].response_assertion.as_ref().unwrap();
        let bytes = fs::read(&response.detail_report).unwrap();
        assert_eq!(
            response.detail_fingerprint,
            crate::verification_progress::fingerprint(&bytes)
        );
        let detail: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            detail["actual_response_path"],
            serde_json::json!(response.actual_response)
        );
        assert!(response.actual_response.is_file());
        assert!(response.actual_response.starts_with(&latest));
        let assertions: super::super::model::AssertionReport =
            serde_json::from_slice(&fs::read(&snapshot.assertions_report).unwrap()).unwrap();
        assert_eq!(
            assertions.cases[0]
                .response
                .as_ref()
                .unwrap()
                .detail_fingerprint,
            response.detail_fingerprint
        );
    }
}

#[test]
fn route_progress_counts_every_method_without_recounting_the_run() {
    let temp = tempfile::tempdir().unwrap();
    let state = state(temp.path());
    let inventory = CaseGroupInventory {
        case_source: state.case_source.clone(),
        source_revision: state.source_revision.clone(),
        case_inventory_id: state.case_inventory_id.clone(),
        groups: state
            .apis
            .iter()
            .map(|api| CanonicalCaseGroup {
                group_id: api.group_id.clone(),
                method: api.method.clone(),
                source_route: api.api_pattern.clone(),
                pattern: None,
                case_inventory_id: "inventory".into(),
                cases: state
                    .cases
                    .iter()
                    .filter(|case| case.group_id == api.group_id)
                    .map(|case| CanonicalCase {
                        case_id: case.case_id.clone(),
                        case_dir: case.case_dir.clone(),
                        recorded_at: None,
                    })
                    .collect(),
            })
            .collect(),
    };
    let mut index = super::super::model::RunIndex::empty_managed(
        state.run_key.clone(),
        state.case_source.clone(),
        temp.path(),
    )
    .unwrap();
    super::super::progress::update_focused_index(&mut index, &state, &inventory, true);
    assert_eq!(index.latest_focused_sequences.len(), 2);
    assert_eq!(index.apis["GET /api"].passed_cases, 1);
    assert_eq!(index.apis["PUT /api"].passed_cases, 0);
    let before = serde_json::to_value(&index).unwrap();
    super::super::progress::update_focused_index(&mut index, &state, &inventory, true);
    assert_eq!(before, serde_json::to_value(&index).unwrap());
}
