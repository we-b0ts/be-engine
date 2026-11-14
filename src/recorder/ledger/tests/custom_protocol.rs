use super::*;
use serde::Serialize;
use serde_json::{Value, json};
use traffic_protocol::{
    capture::{CaptureEvidence, CaptureFacts},
    evidence::{EvidenceAdapter, EvidenceRegistry},
};

#[derive(Serialize)]
struct CustomExchange {
    stream: String,
    offset: u64,
    outcome: crate::DependencyExchangeOutcome,
    response: crate::recorder::BodyCapture,
}

impl CaptureEvidence for CustomExchange {
    fn event_type(&self) -> &'static str {
        "custom_exchange"
    }
    fn capture_facts(&self) -> CaptureFacts {
        CaptureFacts::dependency(
            ProtocolRef::new("custom", json!({"stream":self.stream,"offset":self.offset})).unwrap(),
            self.outcome.label(),
            !self.response.truncated,
        )
    }
}

struct CustomEvidence;
impl EvidenceAdapter for CustomEvidence {
    fn schema(&self) -> &'static str {
        "custom/v1"
    }
    fn event_types(&self) -> &'static [&'static str] {
        &["custom_exchange"]
    }
    fn supports_replay(&self, event: &Value) -> bool {
        event["response"]["truncated"] == false
    }
}

#[derive(Serialize)]
struct InvalidOutcome {
    outcome: &'static str,
}

impl CaptureEvidence for InvalidOutcome {
    fn event_type(&self) -> &'static str {
        "custom_exchange"
    }
    fn capture_facts(&self) -> CaptureFacts {
        CaptureFacts::dependency(
            ProtocolRef::new("custom", json!({"request":7})).unwrap(),
            "response",
            true,
        )
    }
}

#[tokio::test]
async fn a_new_native_event_uses_shared_lifecycle_scope_sealing_and_registered_support() {
    for installed in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let case_id = Uuid::new_v4();
        let case = temp.path().join("cases").join(case_id.to_string());
        let mut evidence = EvidenceRegistry::default();
        if installed {
            evidence
                .register("custom", Arc::new(CustomEvidence))
                .unwrap();
        }
        let mut ledger = super::super::persistence::LedgerWriter::new(
            temp.path(),
            Uuid::new_v4(),
            "custom-capture-policy".into(),
            traffic_recording::RecordingClock::default(),
            Arc::new(evidence),
        );
        let mut files = crate::recorder::jsonl::JsonlWriterPool::new(
            crate::recorder::jsonl::JsonlBufferSettings {
                capacity: 4096,
                flush_interval: Duration::from_secs(1),
            },
        );
        let event = CustomExchange {
            stream: "requests".into(),
            offset: 7,
            outcome: crate::DependencyExchangeOutcome::Response,
            response: crate::recorder::capture_body(b"custom-output", usize::MAX),
        };
        ledger.register_input(case_id, format!("cases/{case_id}"), true);
        assert!(
            ledger
                .append(
                    &mut files,
                    &InvalidOutcome { outcome: "invalid" },
                    None,
                    None,
                    None
                )
                .await
                .is_err()
        );
        ledger
            .append(
                &mut files,
                &event,
                None,
                Some(crate::dependency::attribution::DependencyOwner::Case {
                    origin_case_id: case_id,
                    task_instance: None,
                }),
                None,
            )
            .await
            .unwrap();
        ledger.case_scope(&case).await.unwrap();
        ledger
            .seal(&mut files, CaptureCoverage::default(), true)
            .await
            .unwrap();
        let manifest: RecordingManifest = serde_json::from_slice(
            &std::fs::read(temp.path().join("dependency-manifest.json")).unwrap(),
        )
        .unwrap();
        assert!(manifest.sealed && manifest.capture_complete);
        assert_eq!(manifest.coverage.admitted, 1);
        assert_eq!(manifest.coverage.terminal, 1);
        assert_eq!(manifest.semantic_inventory.total_mandatory, 1);
        assert_eq!(
            manifest.semantic_inventory.unsupported_by_scope.is_empty(),
            installed
        );
        let row: Value = serde_json::from_str(
            std::fs::read_to_string(temp.path().join("dependencies.jsonl"))
                .unwrap()
                .trim(),
        )
        .unwrap();
        assert_eq!(row["event_type"], "custom_exchange");
        assert_eq!(
            row["capture"]["protocol_ref"],
            json!({"protocol":"custom","stream":"requests","offset":7})
        );
        assert_eq!(row["capture"]["semantic_required"], true);
        assert_eq!(row["capture"]["sequence"], 1);
        let scope: ScopeIndex =
            serde_json::from_slice(&std::fs::read(case.join("dependency-scope.json")).unwrap())
                .unwrap();
        assert_eq!(scope.locations.len(), 1);
        assert_eq!(
            scope.locations[0].exchange_id.to_string(),
            row["capture"]["exchange_id"]
        );
    }
}
