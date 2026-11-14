use super::*;
use crate::replay::report::global_evidence::{
    artifact::ArtifactReference,
    notifications::NotificationEvidence,
    protocol::ProtocolEvidence,
    regular::RegularEvidence,
    regular_store::{Builder, Identity, Row},
    regular_usage::Position,
};

fn unified(fixture: &Fixture) -> Value {
    let (index, _) = crate::dependency_index::global::load_global_index(
        &fixture.source,
        crate::protocols::replay::source::validate_index_record,
    )
    .unwrap();
    let identity = Identity {
        source_sha256: index.sha256,
        source_bytes: index.stamp.size,
        policy: "policy".into(),
        protocol: "redis".into(),
        layout: vec![2],
        semantics: None,
    };
    let reference =
        ArtifactReference::retain(&fixture.report, identity.key().unwrap(), |staging| {
            let mut builder = Builder::new(staging, identity);
            for (index, value) in fixture.expected.iter().take(2).enumerate() {
                builder.push(Row {
                    position: Position { section: 0, index },
                    visible: true,
                    value: value.clone(),
                })?;
            }
            builder.finish()
        })
        .unwrap();
    let regular: RegularEvidence = serde_json::from_value(json!({"inventory":reference,"recorded":2,
        "baseline_visible":2,"remaining":1,"changes":[{"position":{"section":0,"index":0},"before":true,"after":false}]})).unwrap();
    let notifications = NotificationEvidence::prepare(&fixture.report, fixture.session()).unwrap();
    let evidence = ProtocolEvidence::new(
        "redis",
        regular,
        crate::protocols::replay::report::redis::fields(notifications).unwrap(),
    );
    let report = json!({"finalized":true,"global_evidence":{"redis":evidence},
        "redis":{"unused_global_count":fixture.expected.len()-1,"unused_global":[fixture.expected.last().unwrap()]}});
    fs::write(&fixture.report, serde_json::to_vec(&report).unwrap()).unwrap();
    report
}

#[test]
fn shared_regular_visibility_notifications_and_case_overlay_compose_without_materializing_pages() {
    let fixture = Fixture::new();
    unified(&fixture);
    let expected = &fixture.expected[1..];
    for offset in [0, 1, 250, 597, 599, 600, 601] {
        for limit in [1, 3, 1000] {
            let page =
                read_global_dependency_page(&fixture.report, "redis", offset, limit).unwrap();
            assert_eq!(page.total, expected.len());
            assert_eq!(
                page.items,
                expected
                    .iter()
                    .skip(offset)
                    .take(limit)
                    .cloned()
                    .collect::<Vec<_>>()
            );
        }
    }
    let export = tempfile::tempdir().unwrap();
    let destination = export.path().join("replay-report.json");
    let rebound = stage_global_evidence(&fixture.report, &destination)
        .unwrap()
        .unwrap();
    fs::write(&destination, serde_json::to_vec(&rebound).unwrap()).unwrap();
    let expected = expected.to_vec();
    fixture.root.close().unwrap();
    assert_eq!(
        read_global_dependency_page(&destination, "redis", 0, 1000)
            .unwrap()
            .items,
        expected
    );
}

#[test]
fn protocol_section_cannot_relabel_an_authentic_other_protocol_inventory() {
    let fixture = Fixture::new();
    let mut report = unified(&fixture);
    let mut evidence = report["global_evidence"]["redis"].clone();
    evidence["protocol"] = json!("mysql");
    evidence.as_object_mut().unwrap().remove("notifications");
    report["global_evidence"]["mysql"] = evidence;
    fs::write(&fixture.report, serde_json::to_vec(&report).unwrap()).unwrap();
    assert!(read_global_dependency_page(&fixture.report, "mysql", 0, 1).is_err());
}
