use super::{manifest::Artifact, *};
use serde_json::json;
use traffic_rewrite_rules::rewrite::unified_rule::manifest::ArtifactMethods;

fn record(path: &Path) -> UnifiedRulePlanRecord {
    serde_json::from_value(json!({"policy":path,"original":"original","updated":"updated",
        "identity":{"scope":"api_issue","identity":{"workflow":"workflow","recording_run":"run","api":"GET /api","group":"group","source_revision":"source",
            "case_inventory":"inventory","case_source":"cases","attempt":1,"target_inputs":"target","engine":"engine"}},
        "artifacts":[],"preflight":{"capture_scopes":{},"source_validations":1,"independent_target_validations":0,"derived_delivery_validations":0,"missing_target_witnesses":1,"rules":{"global.json":1}},
        "source_proofs":{"rules":[],"sha256":crate::policy_evidence::digest(b"[]")},
        "rule_ids":["global.json"]})).unwrap()
}

#[test]
fn single_list_and_document_use_the_same_schema_and_compiler() {
    let native = || {
        json!({"id":"generated","match":{"api":"GET /api"},"effect":{"kind":"response_generated","fields":{
        "/id":{"contract":{"kind":"uuid_v4"},"proof":{"source":"src/handler.rs:12","fact":"Source generates a response UUID"}}
    }},"proof":{"source":"src/handler.rs:12","fact":"Source generates a response UUID"}})
    };
    let single = native();
    let expected = parse_proposal(&single.to_string()).unwrap();
    assert_eq!(
        parse_proposal(&json!([single]).to_string()).unwrap(),
        expected
    );
    assert_eq!(
        parse_proposal(&json!({"format":"traffic-policy/v3","rules":[native()]}).to_string())
            .unwrap(),
        expected
    );
    let mut no_proof = native();
    no_proof["proof"]["source"] = json!("");
    assert!(parse_proposal(&no_proof.to_string()).is_err());
    assert!(parse_proposal(&json!([native(), native()]).to_string()).is_err());
    let global =
        json!({"format":"traffic-policy/v3","json":{"fields":{"/members":{"kind":"unordered"}}}});
    assert_eq!(
        parse_proposal(&global.to_string()).unwrap(),
        parse_proposal(&json!({"format":"traffic-policy/v3","json":global["json"]}).to_string())
            .unwrap()
    );
}

#[test]
fn nested_async_proposals_keep_logical_policy_identity_and_publish_canonically() {
    let ends = json!({"POST /jobs":{"end":[{"redis":{"operation":"DEL","key":"done:*"}}]}});
    let legacy =
        parse_proposal(&json!({"format":"traffic-policy/v3","async_api":ends}).to_string())
            .unwrap();
    let nested = parse_proposal(
        &json!({"format":"traffic-policy/v3","recording":{"async_api":ends}}).to_string(),
    )
    .unwrap();
    assert_eq!(nested, legacy);
    let published = crate::policy::render_policy(&nested).unwrap();
    let value: serde_yaml::Value = serde_yaml::from_str(&published).unwrap();
    assert!(value.get("async_api").is_none());
    assert!(value["recording"].get("async_api").is_some());
    assert_eq!(parse_proposal(&published).unwrap(), nested);
    assert!(
        parse_proposal(
            &json!({"format":"traffic-policy/v3","async_api":{},
        "recording":{"async_api":ends}})
            .to_string()
        )
        .is_err()
    );
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

#[test]
fn unchanged_rules_do_not_renew_recording_or_replay_obligations() {
    let temp = tempfile::tempdir().unwrap();
    let mut record = record(&temp.path().join("policy.yaml"));
    record.updated = record.original.clone();
    record
        .preflight
        .obligations
        .insert(crate::config::native_policy::SourceObligation::FreshRecording);
    let report = record.report(true);
    assert_eq!(report["status"], "applied_no_change");
    assert_eq!(report["requires_fresh_recording"], false);
    assert_eq!(report["requires_fresh_replay"], false);
    assert_eq!(report["verified"], false);
}
