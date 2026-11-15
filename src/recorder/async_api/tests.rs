//! Native extensions share selection, deduplication and completion accounting.
use super::*;
use serde_json::json;
use std::sync::Arc;

#[derive(Debug)]
struct ExtensionRule(ResourceCompletion);
impl CompletionRule for ExtensionRule {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn requires_response_selection(&self) -> bool {
        true
    }
    fn response_matches(&self, body: Option<&Value>) -> bool {
        body.is_some_and(|body| body["accepted"] == true)
    }
    fn all_ends_matched(&self) -> bool {
        self.0.is_complete()
    }
    fn observe_recorded(&self, event: &Value) -> Result<Option<AsyncSignal>> {
        Ok(self.0.observe(
            event["resources"].as_u64().unwrap() as u32,
            "extension_event",
        ))
    }
}
#[derive(serde::Serialize)]
struct Event {
    id: Uuid,
    resources: u32,
}
impl CompletionEvent for Event {
    fn identity(&self) -> Option<Uuid> {
        Some(self.id)
    }
    fn evaluate(&self, rule: &dyn CompletionRule) -> Option<AsyncSignal> {
        rule.as_any()
            .downcast_ref::<ExtensionRule>()?
            .0
            .observe(self.resources, "extension_event")
    }
}

#[test]
fn extension_events_use_early_selection_deduplication_and_original_generations() {
    let scope = AsyncScope::new(
        "extension".into(),
        vec![(3, Arc::new(ExtensionRule(ResourceCompletion::new(2))))],
    )
    .unwrap();
    let event = Event {
        id: Uuid::new_v4(),
        resources: 1,
    };
    assert!(scope.observe_at(&event, 7).is_none());
    let (selected, early) = scope.select_response(Some(&json!({"accepted":true})));
    assert!(selected);
    assert_eq!(early.unwrap().resource_index, Some(0));
    assert_eq!(scope.scenario_index(), Some(3));
    assert_eq!(scope.selected_signal_generation(), Some(7));
    assert!(!scope.all_ends_matched());
    assert!(scope.observe_at(&event, 8).is_none());
    assert_eq!(scope.selected_signal_generation(), Some(7));
    assert_eq!(
        scope
            .observe_recorded(&json!({"resources": 2}))
            .unwrap()
            .unwrap()
            .resource_index,
        Some(1)
    );
    assert!(scope.all_ends_matched());
}

#[test]
fn extension_resources_cannot_complete_an_undeclared_slot() {
    let completion = ResourceCompletion::new(1);
    assert!(completion.observe(2, "extension_event").is_none());
    assert!(!completion.is_complete());
    assert!(completion.observe(1, "extension_event").is_some());
    assert!(completion.is_complete());
}

impl traffic_protocol::capture::CaptureEvidence for Event {
    fn event_type(&self) -> &'static str {
        "extension_event"
    }
    fn capture_facts(&self) -> traffic_protocol::capture::CaptureFacts {
        traffic_protocol::capture::CaptureFacts::dependency(
            traffic_model::recording::ProtocolRef::exchange("extension", self.id),
            "response",
            true,
        )
    }
}

#[test]
fn captured_extension_events_enter_the_same_early_completion_and_deduplication_path() {
    let scope = AsyncScope::new(
        "extension".into(),
        vec![(0, Arc::new(ExtensionRule(ResourceCompletion::new(1))))],
    )
    .unwrap();
    let event = Event {
        id: Uuid::new_v4(),
        resources: 1,
    };
    let snapshot = traffic_protocol::capture::CaptureSnapshot::capture(&event).unwrap();
    let completion = CapturedCompletion {
        event: &snapshot,
        identity: Some(event.id),
    };
    assert!(scope.observe_at(&completion, 3).is_none());
    assert!(
        scope
            .select_response(Some(&json!({"accepted":true})))
            .1
            .is_some()
    );
    assert!(scope.all_ends_matched());
    assert_eq!(scope.selected_signal_generation(), Some(3));
    assert!(scope.observe_at(&completion, 4).is_none());
}
