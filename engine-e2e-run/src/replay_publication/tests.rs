use super::*;
use crate::{case_group::CaseGroupInventory, model::RunStatus};
use serde_json::json;

#[test]
fn published_replay_and_sidecar_survive_removal_of_external_replay_tree() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let active = root.join(".active");
    let latest = root.join("latest");
    fs::create_dir_all(active.join("reports")).unwrap();
    let mut state = ActiveRunState::new(
        "run".into(),
        1,
        &CaseGroupInventory {
            case_source: root.join("cases"),
            source_revision: "source".into(),
            case_inventory_id: "inventory".into(),
            groups: vec![],
        },
        &active,
    );
    state.status = RunStatus::Failed;
    state.replay_finalized = true;
    let external = root.join("cases/.replay/attempt");
    fs::create_dir_all(&external).unwrap();
    state.replay_report = external.join("replay-report.json");
    let bytes = serde_json::to_vec(&json!({"version":7,"finalized":true,"complete":true,"cases":[],"replay_policy":{"fingerprint":"policy"}})).unwrap();
    fs::write(&state.replay_report, &bytes).unwrap();
    store::write_json(
        &state.aggregate_report,
        &json!({"reports":[{"path":state.replay_report}]}),
    )
    .unwrap();
    store::publish_snapshot(&active, &latest, &state).unwrap();
    fs::remove_dir_all(root.join("cases/.replay")).unwrap();
    let published: ActiveRunState = store::read_yaml(&latest.join("state.yaml")).unwrap();
    assert_eq!(
        published.replay_report,
        latest.join("reports/replay-report.json")
    );
    assert_eq!(fs::read(&published.replay_report).unwrap(), bytes);
    crate::replay::report::read_dependency_evidence(&published.replay_report).unwrap();
    let aggregate: Value =
        serde_json::from_slice(&fs::read(&published.aggregate_report).unwrap()).unwrap();
    assert_eq!(
        aggregate["reports"][0]["path"],
        published.replay_report.to_string_lossy().as_ref()
    );
}

#[test]
fn missing_finalized_report_cannot_publish_a_dangling_evidence_reference() {
    let temp = tempfile::tempdir().unwrap();
    let mut state = ActiveRunState::new(
        "run".into(),
        1,
        &CaseGroupInventory {
            case_source: temp.path().into(),
            source_revision: "source".into(),
            case_inventory_id: "inventory".into(),
            groups: vec![],
        },
        temp.path(),
    );
    state.replay_finalized = true;
    assert!(
        prepare(
            &state,
            temp.path(),
            temp.path(),
            &temp.path().join("latest")
        )
        .is_err()
    );
    state.replay_finalized = false;
    assert!(
        prepare(
            &state,
            temp.path(),
            temp.path(),
            &temp.path().join("latest")
        )
        .is_ok()
    );
}
