//! Third-party evidence projections exercise storage without a built-in protocol.
use super::*;
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use traffic_protocol::evidence::{
    EvidenceAdapter, EvidenceRegistry,
    index::{IndexEndpoint, IndexProjection, LookupProjection, StreamProjection},
};

struct Provider(&'static str);

impl EvidenceAdapter for Provider {
    fn schema(&self) -> &'static str {
        self.0
    }
    fn event_types(&self) -> &'static [&'static str] {
        &["external_packet"]
    }
    fn supports_replay(&self, event: &Value) -> bool {
        event["packet"] == "original-payload"
    }
    fn proof_selector(&self, event: &Value) -> Value {
        json!({"event_type":event["event_type"], "native_key":event["native_key"]})
    }
    fn index_projection(&self, event: &Value) -> anyhow::Result<IndexProjection> {
        let mut projection = IndexProjection::record(self.proof_selector(event));
        projection.metadata = json!({"revision":self.0});
        projection.lookups.push(LookupProjection {
            index: "external-lookup".into(),
            key: Some("opaque-key".into()),
            connection: Some("opaque-lane".into()),
            summary: json!({"native_key":event["native_key"]}),
        });
        projection.endpoints.push(IndexEndpoint {
            host: "external.test".into(),
            port: 7654,
            protocol: "external".into(),
        });
        if let Some(lane) = event["push_lane"].as_str() {
            projection.stream = Some(StreamProjection {
                identity: json!({"opaque":lane}),
                duration_ms: 7,
                timestamp: None,
                metadata: json!({"native_key":event["native_key"]}),
            });
        }
        Ok(projection)
    }
}

fn registry(revision: &'static str) -> EvidenceRegistry {
    let mut evidence = EvidenceRegistry::default();
    evidence
        .register("external", Arc::new(Provider(revision)))
        .unwrap();
    evidence
}

#[test]
fn index_fallbacks_do_not_reserve_executable_event_names() {
    let event = json!({"event_type":"external_packet", "packet":"original-payload"});
    let mut evidence = EvidenceRegistry::default();
    evidence
        .register_index_fallback("historical", Arc::new(Provider("external/v1")))
        .unwrap();
    assert!(evidence.owner(&event).is_none());
    assert!(!evidence.supports_replay(&event));
    assert!(!evidence.supports_interaction_inventory(&event));
    assert_eq!(
        evidence.index_projection(&event).unwrap().metadata["revision"],
        "external/v1"
    );
    evidence
        .register("external", Arc::new(Provider("external/v2")))
        .unwrap();
    assert_eq!(evidence.owner(&event), Some("external"));
    assert!(evidence.supports_replay(&event));
    assert_eq!(
        evidence.index_projection(&event).unwrap().metadata["revision"],
        "external/v2"
    );
}

#[test]
fn lookup_builder_preserves_provider_namespaces_and_authenticated_source_locations() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("dependencies.jsonl");
    let record = json!({"event_type":"external_packet", "native_key":19,
        "packet":"original-payload", "capture":{"semantic_required":true}});
    let raw = format!("{record}\n");
    std::fs::write(&path, &raw).unwrap();
    let stamp = FileStamp::read(&path).unwrap();
    let evidence = registry("external/v1");
    let mut builder = Builder::with_evidence(stamp.clone(), evidence.clone(), proof::is_evidence);
    builder.observe(1, raw.as_bytes(), Some(&record)).unwrap();
    let index = builder.finish().unwrap();
    let entries = index.records("external-lookup");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].key, "opaque-key");
    assert_eq!(entries[0].summary, json!({"native_key":19}));
    assert_eq!(index.endpoints[0].protocol, "external");
    let proof = &index.proof_records.as_ref().unwrap()[0].selector;
    assert_eq!(proof["native_key"], 19);
    assert!(proof.get("packet").is_none());
    assert!(!evidence.supports_replay(proof));
    let source = RecordSource::new(&path, stamp, Arc::new(Mutex::new(RecordReader::new(4096))));
    let original: Value = source
        .reference(entries[0].location.clone())
        .load()
        .unwrap();
    assert_eq!(original, record);
    assert!(evidence.supports_replay(&original));
}

#[test]
fn global_projection_keeps_opaque_stream_lanes_and_rebuilds_after_provider_revision_changes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("global-dependencies.jsonl");
    let records = [
        json!({"event_type":"external_packet", "native_key":1, "packet":"original-payload"}),
        json!({"event_type":"external_packet", "native_key":2, "packet":"original-payload", "push_lane":"a"}),
        json!({"event_type":"external_packet", "native_key":3, "packet":"original-payload", "push_lane":"b"}),
    ];
    let raw = records
        .iter()
        .map(|record| format!("{record}\n"))
        .collect::<String>();
    std::fs::write(&path, &raw).unwrap();
    let validations = AtomicUsize::new(0);
    let validate = |record: &Value| {
        anyhow::ensure!(
            record["packet"] == "original-payload",
            "validation received compact metadata"
        );
        validations.fetch_add(1, Ordering::Relaxed);
        Ok(())
    };
    for (revision, expected_validations) in
        [("external/v1", 3), ("external/v1", 3), ("external/v2", 6)]
    {
        let (index, root) = global::load_global_index_with_evidence(
            &path,
            validate,
            &AtomicBool::new(false),
            &registry(revision),
        )
        .unwrap();
        assert_eq!(validations.load(Ordering::Relaxed), expected_validations);
        assert_eq!(index.providers["external"], revision);
        assert_eq!(index.records.count, 1);
        assert_eq!(index.notifications.len(), 2);
        assert_ne!(
            index.notifications[0].identity,
            index.notifications[1].identity
        );
        let entries = global::global_records(&index, &root)
            .unwrap()
            .read_page(0)
            .unwrap();
        assert_eq!(entries[0].native["revision"], revision);
        assert!(entries[0].record.get("packet").is_none());
        let source = RecordSource::new(
            &path,
            index.stamp.clone(),
            Arc::new(Mutex::new(RecordReader::new(4096))),
        );
        assert_eq!(
            source
                .reference(entries[0].location.clone())
                .load::<Value>()
                .unwrap(),
            records[0]
        );
        for (lane, original) in index.notifications.iter().zip(&records[1..]) {
            let pages = Paged::<global::NotificationEntry>::restore(
                lane.pages.clone().resolve(&root).unwrap(),
            )
            .unwrap();
            let notification = pages.read_page(0).unwrap().remove(0);
            assert_eq!(notification.duration_ms, 7);
            assert_eq!(notification.native["native_key"], original["native_key"]);
            assert_eq!(
                source
                    .reference(notification.location)
                    .load::<Value>()
                    .unwrap(),
                *original
            );
        }
        assert_eq!(std::fs::read_to_string(&path).unwrap(), raw);
    }
}

#[tokio::test]
async fn recording_summary_publishes_indexes_with_its_installed_evidence_registry() {
    let directory = tempfile::tempdir().unwrap();
    let record =
        json!({"event_type":"external_packet", "native_key":19, "packet":"original-payload"});
    let evidence = Arc::new(registry("external/v1"));
    std::fs::write(
        directory.path().join("dependencies.jsonl"),
        format!("{record}\n"),
    )
    .unwrap();
    crate::recorder::summary::write_case_dependency_summary(directory.path(), evidence.clone())
        .await
        .unwrap();
    let case: FileIndex = store::read_json(&directory.path().join(FRAGMENT)).unwrap();
    assert_eq!(case.records("external-lookup").len(), 1);
    assert_eq!(case.records("external-lookup")[0].summary["native_key"], 19);

    std::fs::write(
        directory.path().join("global-dependencies.jsonl"),
        format!("{record}\n"),
    )
    .unwrap();
    crate::recorder::summary::write_global_dependency_summary(directory.path(), evidence)
        .await
        .unwrap();
    let global: global::GlobalIndex =
        store::read_json(&directory.path().join(global::GLOBAL_FRAGMENT)).unwrap();
    assert_eq!(
        global.providers.get("external").map(String::as_str),
        Some("external/v1")
    );
    let entries = global::global_records(&global, directory.path())
        .unwrap()
        .read_page(0)
        .unwrap();
    assert_eq!(entries[0].native["revision"], "external/v1");
    assert!(entries[0].record.get("packet").is_none());
}
