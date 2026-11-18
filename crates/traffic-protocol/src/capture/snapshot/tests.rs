use super::*;
use serde_json::json;
use traffic_model::{
    DependencyExchangeOutcome, DependencyTermination, TerminationKind, TerminationScope,
    TerminationSide, recording::ProtocolRef,
};

#[derive(Serialize)]
struct NativeEvent {
    #[serde(flatten)]
    native: Value,
    #[serde(skip)]
    outcome: DependencyExchangeOutcome,
}

impl CaptureEvidence for NativeEvent {
    fn event_type(&self) -> &'static str {
        "custom_exchange"
    }

    fn capture_facts(&self) -> CaptureFacts {
        let mut facts = CaptureFacts::dependency(
            ProtocolRef::new("custom", json!({"wire":7})).unwrap(),
            self.outcome.label(),
            true,
        );
        facts.outcome = self.outcome;
        facts
    }
}

#[test]
fn native_facts_supply_outcomes_without_a_payload_format_dependency() {
    let event = NativeEvent {
        native: json!({"reply_mode":204}),
        outcome: DependencyExchangeOutcome::NoResponse,
    };
    let snapshot = CaptureSnapshot::capture(&event).unwrap();
    assert_eq!(
        snapshot.facts().outcome,
        DependencyExchangeOutcome::NoResponse
    );
    assert_eq!(
        snapshot.payload(),
        &json!({"event_type":"custom_exchange", "reply_mode":204})
    );
    assert_eq!(super::super::payload(&event).unwrap(), *snapshot.payload());
}

#[test]
fn the_shared_envelope_rejects_conflicting_outcomes_and_engine_termination() {
    let mut event = NativeEvent {
        native: json!({"outcome":"no_response"}),
        outcome: DependencyExchangeOutcome::NoResponse,
    };
    assert!(CaptureSnapshot::capture(&event).is_ok());
    event.native["outcome"] = json!("response");
    assert!(CaptureSnapshot::capture(&event).is_err());
    event.native = json!({"reply_mode":204});
    event.outcome = DependencyExchangeOutcome::Terminated(DependencyTermination {
        side: TerminationSide::Engine,
        kind: TerminationKind::Reset,
        scope: TerminationScope::Connection,
    });
    assert!(CaptureSnapshot::capture(&event).is_err());
}
