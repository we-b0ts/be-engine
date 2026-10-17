use super::*;
use serde_json::json;

fn bound(artifacts: &Path) -> WitnessStore {
    std::fs::write(artifacts.join("replay.json"), json!({"session_id":"replay", "replay_policy":{"fingerprint":"policy"}, "cases":[{"case_id":"case", "case_dir":artifacts, "target_request_started_at":null}]}).to_string()).unwrap();
    WitnessStore::new_bound(artifacts, "replay", "policy").unwrap()
}

#[test]
fn candidate_groups_preserve_all_pairs_orphan_requests_and_authentication() {
    let (_temp, artifacts, _unused, mut metadata) = setup();
    let store = bound(&artifacts);
    store
        .record_target(
            "target",
            TargetMetadata::from_pair(&metadata),
            &artifacts,
            b"genuine-target",
        )
        .unwrap();
    store
        .record_target(
            "orphan",
            TargetMetadata::from_pair(&metadata),
            &artifacts,
            b"unmatched-target",
        )
        .unwrap();
    for sequence in 1..=5 {
        metadata.source.sequence = Some(sequence);
        for _ in 0..3 {
            store
                .associate(&metadata, "target", &artifacts, Some(&[sequence as u8]))
                .unwrap();
        }
    }
    let manifest = store.sealed_manifest().unwrap();
    let graph = manifest.graph().unwrap();
    assert_eq!(
        (
            graph.sources.len(),
            graph.targets.len(),
            graph.associations.len(),
            graph.groups.len(),
            graph.groups[0].sources.len()
        ),
        (5, 2, 0, 1, 5)
    );
    assert!(manifest.complete);
    let wire = serde_json::to_value(&manifest).unwrap();
    assert!(wire.get("observations").is_none());
    assert!(serde_json::to_vec(&wire).unwrap().len() < 2048);
    let restored: WitnessManifest = serde_json::from_value(wire).unwrap();
    assert!(restored.witness_entries().is_err());
    verify(&artifacts.join("replay.json"), &restored).unwrap();
    assert_eq!(restored.witnesses().unwrap().len(), 10);
    let path = verify(&artifacts.join("replay.json"), &manifest).unwrap();
    let pairs = manifest.witnesses().unwrap();
    assert_eq!(
        pairs.iter().filter(|p| p.target_sha256.is_some()).count(),
        5
    );
    for pair in &pairs {
        read(&path, pair, &artifacts).unwrap();
    }
    let mut forged = pairs[0].clone();
    forged.metadata.source.sequence = Some(999);
    assert!(read(&path, &forged, &artifacts).is_err());
    let mut forged = manifest.clone();
    forged.observations = Some(manifest.graph().unwrap().clone());
    forged.observations.as_mut().unwrap().groups[0]
        .sources
        .pop();
    assert!(verify(&artifacts.join("replay.json"), &forged).is_err());
    let directory = artifacts.join(&manifest.graph_artifact.as_ref().unwrap().artifact);
    std::fs::write(directory, b"{}").unwrap();
    assert!(verify(&artifacts.join("replay.json"), &restored).is_err());
}

#[test]
fn large_source_response_uses_original_record_and_detects_mutation() {
    let (_temp, artifacts, _unused, mut metadata) = setup();
    let store = bound(&artifacts);
    metadata.surface = Surface::DependencyResponse;
    metadata.source_role = SourceRole::DependencyResponse;
    metadata.target_role = TargetRole::Unavailable;
    metadata.operation = "COM_QUERY".into();
    metadata.source.connection_id = Some("00000000-0000-0000-0000-000000000001".into());
    metadata.resource = Some(crate::policy::Resource {
        protocol: crate::policy::Protocol::Mysql,
        endpoint: crate::policy::Endpoint {
            host: "sql.invalid".into(),
            port: 3306,
        },
        database: None,
        username: None,
    });
    let event = json!({"event_type":"mysql_exchange", "command":"COM_QUERY", "sql":"SELECT data FROM entries", "response":{"status":"resultset", "columns":[], "rows":[[{"kind":"string","value":"x".repeat(2*1024*1024)}]]}});
    let bytes = serde_json::to_vec(&event).unwrap();
    let source = artifacts.join("dependencies.jsonl");
    std::fs::write(&source, &bytes).unwrap();
    let raw = crate::replay::mysql_source_witness(&event, metadata.surface).unwrap();
    store
        .register_source_record(
            &metadata.source,
            crate::policy::Protocol::Mysql,
            SourceRecord {
                path: source.clone(),
                stamp: crate::dependency_index::FileStamp::read(&source).unwrap(),
                location: crate::dependency_index::RecordLocation {
                    line: 1,
                    offset: 0,
                    length: bytes.len() as u64,
                    sha256: digest(&bytes).trim_start_matches("sha256:").into(),
                },
            },
        )
        .unwrap();
    store
        .record(metadata, &artifacts, &raw, None)
        .unwrap()
        .unwrap();
    let manifest = store.sealed_manifest().unwrap();
    let path = verify(&artifacts.join("replay.json"), &manifest).unwrap();
    assert!(manifest.complete);
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
    let pair = manifest.witnesses().unwrap().remove(0);
    assert_eq!(read(&path, &pair, &artifacts).unwrap().0, raw);
    std::fs::write(source, b"changed").unwrap();
    assert!(verify(&artifacts.join("replay.json"), &manifest).is_err());
    assert!(read(&path, &pair, &artifacts).is_err());
}

#[test]
fn large_target_is_chunked_segmented_portable_and_never_borrows_source() {
    let (_temp, artifacts, _unused, metadata) = setup();
    let store = bound(&artifacts);
    store.segment_limit_for_test(2 * 1024 * 1024);
    let payload = vec![b'x'; 3 * 1024 * 1024 + 7];
    store
        .record_observation(
            metadata,
            &artifacts,
            b"source",
            Some(&payload),
            Some("target"),
        )
        .unwrap()
        .unwrap();
    let manifest = store.sealed_manifest().unwrap();
    assert!(manifest.complete);
    assert!(manifest.graph().unwrap().segments.len() >= 3);
    let report = artifacts.join("replay.json");
    let path = verify(&report, &manifest).unwrap();
    let pair = manifest
        .witnesses()
        .unwrap()
        .into_iter()
        .find(|p| p.target_sha256.is_some())
        .unwrap();
    assert_eq!(read(&path, &pair, &artifacts).unwrap().1.unwrap(), payload);
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report).unwrap()).unwrap();
    value["policy_witnesses"] = serde_json::to_value(&manifest).unwrap();
    std::fs::write(&report, value.to_string()).unwrap();
    let output = artifacts.join("export");
    std::fs::create_dir(&output).unwrap();
    let published = output.join("replay.json");
    std::fs::copy(&report, &published).unwrap();
    stage(&report, &published).unwrap();
    let path = verify(&published, &manifest).unwrap();
    assert_eq!(read(&path, &pair, &artifacts).unwrap().1.unwrap(), payload);
    let extra = manifest.graph().unwrap().segments.last().unwrap();
    std::fs::write(output.join(&extra.artifact), b"tampered").unwrap();
    assert!(verify(&published, &manifest).is_err());
}
