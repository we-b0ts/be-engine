use super::{manifest::Artifact, *};
use serde_json::json;

#[path = "transaction.rs"]
mod transaction;

fn rule() -> serde_json::Value {
    json!({"id":"members","surface":"api.response","match":{"api":"GET /api"},"slot":"body","codec":"json",
        "contract":{"/members":{"kind":"unordered"}},"proof":{"source":"src/members.rs:12","fact":"Source uses an unordered set"}})
}

fn record(path: &Path) -> UnifiedRulePlanRecord {
    serde_json::from_value(json!({"policy":path,"original":"original","updated":"updated",
        "identity":{"workflow":"workflow","recording_run":"run","api":"GET /api","group":"group","source_revision":"source",
            "case_inventory":"inventory","case_source":"cases","attempt":1,"target_inputs":"target","engine":"engine"},
        "artifacts":[],"preflight":{"source_validations":1,"independent_target_validations":0,"derived_delivery_validations":0,"missing_target_witnesses":1,"rules":{"members":1}},
        "rule_ids":["members"]})).unwrap()
}

#[test]
fn single_list_and_document_use_the_same_schema_and_compiler() {
    let single = rule();
    let expected = parse_proposal(&single.to_string()).unwrap();
    assert_eq!(
        parse_proposal(&json!([single]).to_string()).unwrap(),
        expected
    );
    assert_eq!(
        parse_proposal(&json!({"format":"traffic-policy/v1","rules":[rule()]}).to_string())
            .unwrap(),
        expected
    );
    let mut no_proof = rule();
    no_proof["proof"]["source"] = json!("");
    assert!(parse_proposal(&no_proof.to_string()).is_err());
    assert!(parse_proposal(&json!([rule(), rule()]).to_string()).is_err());
}

#[test]
fn exact_updated_policy_is_only_recoverable_with_durable_apply_intent() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("policy.yaml");
    let mut record = record(&path);
    std::fs::write(&path, "original").unwrap();
    record.ensure_policy_current().unwrap();
    std::fs::write(&path, "updated").unwrap();
    assert!(record.ensure_policy_current().is_err());
    record.apply_started = true;
    record.ensure_policy_current().unwrap();
    rollback(&record).unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "original");
    std::fs::write(&path, "another authorized writer").unwrap();
    assert!(record.ensure_policy_current().is_err());
    assert!(rollback(&record).is_err());
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "another authorized writer"
    );
}

#[test]
fn missing_target_or_derived_delivery_cannot_claim_real_replay_passed() {
    let temp = tempfile::tempdir().unwrap();
    let record = record(&temp.path().join("policy.yaml"));
    let report = record.report(false);
    assert_eq!(report["status"], "planned_needs_replay");
    assert_eq!(report["verified"], false);
    assert_eq!(record.report(true)["requires_fresh_replay"], true);
    let mut state = crate::rewrite::test_state();
    state.e2e_current = true;
    state.target_fingerprint = Some("old".into());
    let mut parked = state.active_slice.clone();
    parked.e2e_current = true;
    state.parked_slices.insert("POST /other".into(), parked);
    invalidate_global(&mut state);
    assert!(!state.e2e_current);
    assert!(state.target_fingerprint.is_none());
    assert!(
        state
            .parked_slices
            .values()
            .all(|s| !s.e2e_current && s.target_fingerprint.is_none())
    );
}

#[test]
fn frozen_artifacts_reject_changed_or_symlinked_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("witness.json");
    std::fs::write(&path, "complete").unwrap();
    let artifact = Artifact::capture(&path).unwrap();
    artifact.verify().unwrap();
    std::fs::write(&path, "changed").unwrap();
    assert!(artifact.verify().is_err());
    std::fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(temp.path().join("other"), &path).unwrap();
    assert!(Artifact::capture(&path).is_err());
}
