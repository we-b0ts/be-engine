//! A new native evidence layout uses the ordinary publication and Case checks.
use super::*;
use anyhow::Result;
use serde_json::json;
use traffic_protocol::{
    ProtocolId,
    report::{
        ReportCodec, ReportSection,
        diagnostics::{Difference, Direction, Field, Observation},
    },
};

struct Custom;
impl DiagnosticSchema for Custom {
    fn section<'a>(&self, report: &'a Value, _: &str) -> &'a Value {
        &report["vendor"]
    }
    fn fields(&self) -> &'static [Field] {
        &[Field {
            name: "rejections",
            reason: "value_differs",
            direction: Direction::Paired,
            label: Some("position"),
        }]
    }
    fn matched_rows<'a>(&self, report: &'a Value, _: &str) -> &'a Value {
        &report["vendor"]["served"]
    }
    fn operation(&self, event: &Value) -> String {
        event["verb"].as_str().unwrap_or("unknown").into()
    }
    fn paired_difference(&self, event: &Value) -> Option<Difference> {
        let observation = |side: &str| Observation {
            presence: "present".into(),
            signature: Some(json!({"value": event[side]})),
        };
        Some(Difference {
            kind: "vendor_value_mismatch".into(),
            expected: observation("before"),
            actual: observation("after"),
        })
    }
}
impl ReportCodec for Custom {
    fn diagnostics(&self) -> &dyn DiagnosticSchema {
        self
    }
    fn decode(&self, _: &Path, _: &Value) -> Result<Option<Box<dyn ReportSection>>> {
        Ok(None)
    }
    fn decode_extensions(
        &self,
        _: &Path,
        _: &BTreeMap<String, Value>,
    ) -> Result<Box<dyn ReportSection>> {
        anyhow::bail!("custom test report has no Global extensions")
    }
}

#[tokio::test]
async fn injected_native_schema_reaches_final_report_publication() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("report.json");
    let mut codecs = CodecRegistry::default();
    codecs
        .register(ProtocolId::new("vendor-rpc"), std::sync::Arc::new(Custom))
        .unwrap();
    let report = json!({"vendor": {
        "rejections": [
            {"case_id": null, "verb": "WRITE", "position": "value", "before": "startup", "after": "context"},
            {"case_id": "case-a", "verb": "WRITE", "position": "value", "before": "source", "after": "target"}
        ],
        "served": [{"case_id": "case-a", "verb": "READ", "target_event_index": 7}]
    }});
    assert!(report_has_case_dirty_events(&report, &codecs));
    crate::replay::report::write_final_report_value(path.clone(), &report, &codecs)
        .await
        .unwrap();
    let evidence = read_dependency_evidence(&path).unwrap();
    assert_eq!(
        evidence.case_event_counts["vendor-rpc"]["value_differs: value"],
        1
    );
    let representative = evidence.clusters[0].representative.as_ref().unwrap();
    assert_eq!(representative.difference.kind, "vendor_value_mismatch");
    assert_eq!(
        representative.difference.expected.signature,
        Some(json!({"value": "source"}))
    );
    assert_eq!(representative.target_matches[0].operation, "READ");
    assert_eq!(representative.target_matches[0].target_event_index, 7);
}

#[test]
fn open_protocol_reports_include_dirty_evidence_without_a_builtin_schema() {
    let codecs = CodecRegistry::default();
    let report = json!({"dependency_protocols": {"custom-rpc": {
        "unmatched": [
            {"case_id": null, "command": "INIT"},
            {"case_id": "case-a", "command": "READ", "payload": "private"}
        ],
        "unused_case": [{"case_id": "case-a", "index": 9}],
        "matched": [{"case_id": "case-a", "command": "READ", "target_event_index": 2}]
    }}});
    assert!(report_has_case_dirty_events(&report, &codecs));
    let evidence = build_dependency_evidence(&report, &codecs);
    assert_eq!(
        evidence.case_event_counts["custom-rpc"]["unmatched_target"],
        1
    );
    assert_eq!(
        evidence.case_event_counts["custom-rpc"]["unused_recorded"],
        1
    );
    let representative = evidence
        .clusters
        .iter()
        .find(|cluster| cluster.reason == "unmatched_target")
        .unwrap()
        .representative
        .as_ref()
        .unwrap();
    assert!(
        representative
            .difference
            .actual
            .signature
            .as_ref()
            .unwrap()
            .get("payload")
            .is_none()
    );
    assert_eq!(representative.target_matches[0].target_event_index, 2);
}

#[test]
fn historical_codecs_keep_current_native_differences_and_match_receipts_visible() {
    let providers = crate::protocols::default_providers();
    let report = json!({
        "unmatched_queries":[{"case_id":"case-a", "command":"COM_QUERY", "sql":"SELECT legacy"}],
        "matched_queries":[{"case_id":"case-a", "command":"COM_QUERY", "sql":"SELECT old", "target_event_index":1}],
        "dependency_protocols": {
            "mysql": {
                "unmatched":[{"case_id":"case-a", "command":"COM_QUERY", "sql":"SELECT native"}],
                "matched":[{"case_id":"case-a", "command":"COM_QUERY", "sql":"SELECT current", "target_event_index":2}]
            },
            "http": {"unused_case":[{"case_id":"case-a", "method":"GET", "uri":"/current"}]},
            "redis": {"unmatched":[{"case_id":"case-a", "command":"GET"}]}
        }
    });
    let evidence = build_dependency_evidence(&report, providers.report_codecs());
    assert!(report_has_case_dirty_events(
        &report,
        providers.report_codecs()
    ));
    assert_eq!(evidence.case_event_counts["mysql"]["unmatched_target"], 2);
    assert_eq!(evidence.case_event_counts["http"]["unused_recorded"], 1);
    assert_eq!(evidence.case_event_counts["redis"]["unmatched_target"], 1);
    let mysql = evidence
        .clusters
        .iter()
        .find(|cluster| cluster.protocol == "mysql")
        .unwrap();
    let matches = &mysql.representative.as_ref().unwrap().target_matches;
    assert_eq!(matches.len(), 2);
    assert!(matches.iter().all(|row| row.sql_fingerprint.is_some()));
    assert_eq!(matches[0].target_event_index, 1);
    assert_eq!(matches[1].target_event_index, 2);
}

#[test]
fn a_schema_using_standard_native_locations_is_collected_once() {
    struct Native;
    impl ReportCodec for Native {}
    let mut codecs = CodecRegistry::default();
    codecs
        .register(ProtocolId::new("custom"), std::sync::Arc::new(Native))
        .unwrap();
    let report = json!({"dependency_protocols":{"custom":{
        "unmatched":[{"case_id":"case-a", "command":"READ"}]
    }}});
    let evidence = build_dependency_evidence(&report, &codecs);
    assert_eq!(evidence.case_event_counts["custom"]["unmatched_target"], 1);
}
