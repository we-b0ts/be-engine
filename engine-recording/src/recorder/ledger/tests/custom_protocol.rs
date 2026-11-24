use super::*;
use serde::Serialize;
use serde_json::{Value, json};
use traffic_protocol::{
    capture::{CaptureEvidence, CaptureFacts},
    evidence::{EvidenceAdapter, EvidenceRegistry},
    observation::{NativeSummary, RecordingSummary, TrafficInteraction},
};

#[derive(Serialize)]
struct CustomExchange {
    stream: String,
    offset: u64,
    #[serde(skip_serializing)]
    outcome: crate::DependencyExchangeOutcome,
    response: crate::recorder::BodyCapture,
}

impl CaptureEvidence for CustomExchange {
    fn event_type(&self) -> &'static str {
        "custom_exchange"
    }
    fn capture_facts(&self) -> CaptureFacts {
        let mut facts = CaptureFacts::dependency(
            ProtocolRef::new("custom", json!({"stream":self.stream,"offset":self.offset})).unwrap(),
            self.outcome.label(),
            !self.response.truncated,
        );
        facts.outcome = self.outcome;
        facts
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
    fn interaction(&self, event: &Value) -> Option<TrafficInteraction> {
        Some(TrafficInteraction {
            protocol: "custom".into(),
            endpoint: Some("custom.test:18452".into()),
            operation: event["stream"].as_str()?.to_owned(),
        })
    }
    fn recording_summary(&self) -> Option<Box<dyn RecordingSummary>> {
        Some(Box::new(CustomMetrics::default()))
    }
    fn process_summary_types(&self) -> &'static [&'static str] {
        &["custom_metrics"]
    }
    fn process_summary_key(&self, _event: &Value) -> Option<&'static str> {
        Some("custom_metrics")
    }
    fn process_summary(&self, name: &str) -> Option<Box<dyn NativeSummary>> {
        (name == "custom_metrics")
            .then(|| Box::new(CustomMetrics::default()) as Box<dyn NativeSummary>)
    }
}

#[derive(Default)]
struct CustomMetrics {
    calls: u64,
}
impl RecordingSummary for CustomMetrics {
    fn observe(&mut self, _: &Value) {
        self.calls += 1;
    }
    fn finish(self: Box<Self>) -> anyhow::Result<std::collections::BTreeMap<String, Value>> {
        Ok(std::collections::BTreeMap::from([(
            "custom_metrics".into(),
            self.value(),
        )]))
    }
}
impl NativeSummary for CustomMetrics {
    fn observe(&mut self, _event: &Value, _endpoint: Option<&str>) {
        self.calls += 1;
    }
    fn value(&self) -> Value {
        json!({"calls":self.calls})
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
    use crate::DependencyExchangeOutcome::{NoResponse, Response};
    for (installed, outcome) in [
        (false, Response),
        (true, Response),
        (false, NoResponse),
        (true, NoResponse),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let case_id = Uuid::new_v4();
        let case = temp.path().join("cases").join(case_id.to_string());
        let mut evidence = EvidenceRegistry::default();
        if installed {
            evidence
                .register("custom", Arc::new(CustomEvidence))
                .unwrap();
        }
        let mut ledger = traffic_recorder::test_support::LedgerWriter::new(
            temp.path(),
            Uuid::new_v4(),
            "custom-capture-policy".into(),
            traffic_recorder::RecordingClock::default(),
            Arc::new(evidence.clone()),
            false,
        )
        .await
        .unwrap();
        let mut files = crate::recorder::jsonl::JsonlWriterPool::new(
            crate::recorder::jsonl::JsonlBufferSettings {
                capacity: 4096,
                flush_interval: Duration::from_secs(1),
            },
        );
        let event = CustomExchange {
            stream: "requests".into(),
            offset: 7,
            outcome,
            response: crate::recorder::capture_body(
                if outcome == NoResponse {
                    b""
                } else {
                    b"custom-output"
                },
                usize::MAX,
            ),
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
        crate::recorder::summary::write_case_dependency_summary(&case, Arc::new(evidence))
            .await
            .unwrap();
        let summary: Value =
            serde_json::from_slice(&std::fs::read(case.join("dependencies-summary.json")).unwrap())
                .unwrap();
        assert_eq!(summary["total_events"], 1);
        assert_eq!(summary.get("custom_metrics").is_some(), installed);
        if installed {
            assert_eq!(summary["custom_metrics"]["calls"], 1);
        }
        assert_eq!(manifest.coverage.admitted, 1);
        assert_eq!(manifest.coverage.terminal, 1);
        assert_eq!(manifest.semantic_inventory.total_mandatory, 1);
        assert_eq!(
            manifest.semantic_inventory.unsupported_by_scope.is_empty(),
            installed
        );
        let row: Value = serde_json::from_str(
            crate::recorder::test_io::read_to_string_sync(temp.path().join("dependencies.jsonl"))
                .unwrap()
                .trim(),
        )
        .unwrap();
        assert_eq!(row["event_type"], "custom_exchange");
        assert_eq!(row["outcome"], serde_json::to_value(outcome).unwrap());
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

#[tokio::test]
async fn the_normal_recording_writer_accepts_new_native_events_and_their_summary_format() {
    let mut providers = crate::protocols::default_providers().as_ref().clone();
    providers
        .register_evidence("custom", Arc::new(CustomEvidence))
        .unwrap();
    let (_temp, state) = state_with_providers(Arc::new(providers)).await;
    let event = CustomExchange {
        stream: "requests".into(),
        offset: 7,
        outcome: crate::DependencyExchangeOutcome::Response,
        response: crate::recorder::capture_body(b"custom-output", usize::MAX),
    };
    state
        .recorder()
        .try_record_event(
            event,
            start(&state),
            Some(crate::recorder::GlobalDependencyAttribution {
                reason: "background_rule",
                phase: "runtime",
                matched_by: "periodic-cache-refresh".into(),
            }),
            false,
        )
        .unwrap();
    state.recorder().finish_run().await.unwrap();
    let rows = records(&state).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["capture"]["attribution"]["kind"], "process");
    assert_eq!(rows[0]["capture"]["protocol_ref"]["protocol"], "custom");
    let summary: Value = serde_json::from_slice(
        &std::fs::read(
            state
                .recorder()
                .run_dir
                .join("source-process-traffic-summary.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let rule = &summary["background"]["rules"][0];
    assert_eq!(rule["custom_metrics"]["calls"], 1);
    assert_eq!(rule["observations"][0]["protocol"], "custom");
    assert_eq!(rule["observations"][0]["operation"], "requests");
}
