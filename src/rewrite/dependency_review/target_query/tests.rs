use super::*;
use crate::policy_evidence::{RunWitnessOwner, TargetMetadata, WitnessStore};

#[test]
fn split_observation_catalog_supports_authenticated_bounded_reads_and_rejects_tampering() {
    let temp = tempfile::tempdir().unwrap();
    let local = temp.path().join(".traffic-e2e/local");
    fs::create_dir_all(local.join("secrets")).unwrap();
    fs::write(
        local.join(crate::repository::LOCAL_ENCRYPTION_KEY_FROM_LOCAL),
        crate::request_headers::generate_encryption_key().unwrap(),
    )
    .unwrap();
    let directory = local.join("runtime/attempt");
    let session = uuid::Uuid::new_v4().to_string();
    let store = WitnessStore::new_bound(&directory, &session, "policy").unwrap();
    store
        .record_target(
            "statement",
            TargetMetadata {
                case_id: String::new(),
                run_owner: Some(RunWitnessOwner {
                    session_id: session.clone(),
                }),
                surface: Surface::DependencyRequest,
                role: TargetRole::IndependentTargetObservation,
                resource: None,
                operation: "COM_QUERY".into(),
                clocks: Default::default(),
            },
            &directory,
            br#"{"sql":"SELECT id FROM entries WHERE id=?","params":[7]}"#,
        )
        .unwrap();
    let manifest = store.sealed_manifest().unwrap();
    assert!(manifest.observations.is_none());
    let catalog = directory.join(&manifest.graph_artifact.as_ref().unwrap().artifact);
    let report = directory.join("replay.json");
    fs::write(
        &report,
        serde_json::to_vec(&json!({
            "version":7,"session_id":session,"target_observation_policy_fingerprint":"policy",
            "policy_witnesses":manifest
        }))
        .unwrap(),
    )
    .unwrap();
    let observation = crate::policy_evidence::target_observation_id(
        "statement",
        Surface::DependencyRequest,
        TargetRole::IndependentTargetObservation,
    );
    let read = |session, pointer| request(&report, &directory, 7, session, &observation, pointer);
    let result = read(&session, "/sql").unwrap();
    assert_eq!(
        result["selected_value"],
        "SELECT id FROM entries WHERE id=?"
    );
    assert_eq!(result["selection_status"], "present");
    assert_eq!(result["formal_rule_proof"], false);
    assert_eq!(
        read(&session, "/missing").unwrap()["selection_status"],
        "missing"
    );
    assert!(read("foreign-session", "/sql").is_err());
    fs::write(catalog, "{}").unwrap();
    assert!(read(&session, "/sql").is_err());
}
