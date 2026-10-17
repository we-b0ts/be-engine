use super::*;
mod observations;

fn setup() -> (tempfile::TempDir, PathBuf, WitnessStore, WitnessMetadata) {
    let temp = tempfile::tempdir().unwrap();
    let local = temp.path().join(".traffic-e2e/local");
    std::fs::create_dir_all(local.join("secrets")).unwrap();
    std::fs::write(
        local.join(crate::repository::LOCAL_ENCRYPTION_KEY_FROM_LOCAL),
        crate::request_headers::generate_encryption_key().unwrap(),
    )
    .unwrap();
    let artifacts = local.join("runtime/attempt");
    let store = WitnessStore::new(&artifacts).unwrap();
    let metadata = WitnessMetadata {
        surface: Surface::DependencyRequest,
        source_role: SourceRole::DependencyRequest,
        target_role: TargetRole::IndependentTargetObservation,
        source: SourceIdentity {
            exchange_id: None,
            case_id: "case".into(),
            connection_id: Some("lane".into()),
            sequence: Some(1),
        },
        resource: None,
        operation: "SET".into(),
        slot: Slot::Value,
        clocks: Default::default(),
    };
    (temp, artifacts, store, metadata)
}

#[test]
fn sealed_private_witnesses_preserve_roles_bytes_and_complete_coverage() {
    let (_temp, artifacts, store, metadata) = setup();
    let source = b"private-source-body";
    let target = b"private-target-body";
    let reference = store
        .record_observation(
            metadata.clone(),
            &artifacts,
            source,
            Some(target),
            Some("request-1"),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        store
            .record_observation(
                metadata,
                &artifacts,
                source,
                Some(target),
                Some("request-1")
            )
            .unwrap(),
        Some(reference.clone())
    );
    let manifest = store.sealed_manifest().unwrap();
    assert!(manifest.complete && manifest.sealed);
    assert_eq!(
        (manifest.observed, manifest.recorded, manifest.omitted),
        (2, 2, 0)
    );
    let report = artifacts.join("replay.json");
    let path = verify(&report, &manifest).unwrap();
    assert!(
        !String::from_utf8_lossy(&std::fs::read(&path).unwrap()).contains("private-source-body")
    );
    assert!(
        !serde_json::to_string(&manifest)
            .unwrap()
            .contains("private-target-body")
    );
    assert_eq!(
        read(&path, &reference, &artifacts).unwrap(),
        (source.to_vec(), Some(target.to_vec()))
    );
    let mut modified = reference;
    modified.metadata.operation = "GET".into();
    assert!(read(&path, &modified, &artifacts).is_err());
}

#[test]
fn bounded_storage_and_unsealed_snapshots_cannot_authorize_plans() {
    let (_temp, artifacts, store, metadata) = setup();
    let report = artifacts.join("replay.json");
    assert!(verify(&report, &store.manifest().unwrap()).is_err());
    assert!(
        store
            .record(metadata, &artifacts, &vec![0; 1024 * 1024 + 1], Some(b"x"))
            .unwrap()
            .is_none()
    );
    let manifest = store.sealed_manifest().unwrap();
    assert!(!manifest.complete);
    assert_eq!(manifest.omitted, 1);
    assert!(verify(&report, &manifest).is_err());
}

#[test]
fn maximum_source_and_target_payloads_remain_readable() {
    let (_temp, artifacts, store, metadata) = setup();
    let source = vec![255; 1024 * 1024];
    let target = vec![0; 1024 * 1024];
    let witness = store
        .record(metadata, &artifacts, &source, Some(&target))
        .unwrap()
        .unwrap();
    assert!(witness.length <= 4 * 1024 * 1024);
    let manifest = store.sealed_manifest().unwrap();
    let path = verify(&artifacts.join("replay.json"), &manifest).unwrap();
    assert_eq!(
        read(&path, &witness, &artifacts).unwrap(),
        (source, Some(target))
    );
}

#[test]
fn publication_carries_private_artifact_without_changing_relative_identity() {
    let (_temp, artifacts, store, metadata) = setup();
    store
        .record(metadata, &artifacts, b"left", Some(b"right"))
        .unwrap();
    let manifest = store.sealed_manifest().unwrap();
    let source = artifacts.join("replay.json");
    std::fs::write(
        &source,
        serde_json::json!({"policy_witnesses":manifest}).to_string(),
    )
    .unwrap();
    let published = artifacts.join("published");
    std::fs::create_dir_all(&published).unwrap();
    let destination = published.join("replay.json");
    stage(&source, &destination).unwrap();
    assert!(verify(&destination, &manifest).is_ok());
    std::fs::write(artifact_path(&destination, &manifest).unwrap(), "tampered").unwrap();
    assert!(verify(&destination, &manifest).is_err());
}

#[test]
fn derived_dependency_delivery_is_not_an_independent_target_observation() {
    let (_temp, artifacts, store, mut metadata) = setup();
    metadata.surface = Surface::DependencyResponse;
    metadata.source_role = SourceRole::DependencyResponse;
    assert!(
        store
            .record(metadata.clone(), &artifacts, b"source", Some(b"derived"))
            .is_err()
    );
    metadata.target_role = TargetRole::DerivedDelivery;
    assert!(
        store
            .record(metadata, &artifacts, b"source", Some(b"derived"))
            .is_ok()
    );
}
