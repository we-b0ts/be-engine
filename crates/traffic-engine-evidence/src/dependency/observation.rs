//! Recording schema and source ownership views.
pub use traffic_model::recording::*;

#[cfg(any(test, feature = "test-support"))]
use super::attribution::DependencyOwner;
#[cfg(any(test, feature = "test-support"))]
use chrono::Utc;
#[cfg(any(test, feature = "test-support"))]
use uuid::Uuid;

#[cfg(any(test, feature = "test-support"))]
pub fn fixture_capture(kind: &str) -> CaptureMetadata {
    let epoch = Uuid::from_u128(1);
    CaptureMetadata {
        transformations: Vec::new(),
        exchange_id: Uuid::new_v4(),
        sequence: 1,
        process_epoch: epoch,
        phase: if kind == "startup" {
            CapturePhase::Startup
        } else {
            CapturePhase::Runtime
        },
        observed_case: None,
        admitted_case: None,
        started_at: Utc::now(),
        protocol_ref: ProtocolRef::observation(Uuid::new_v4(), "fixture"),
        attribution: match kind {
            "startup" => DependencyOwner::Startup {
                process_epoch: epoch,
                initialization_unit: "fixture_initialization".into(),
            },
            "process" => DependencyOwner::Process {
                process_epoch: epoch,
                source_task: "fixture_task".into(),
                invocation: None,
            },
            "case" => DependencyOwner::Case {
                origin_case_id: Uuid::new_v4(),
                task_instance: None,
            },
            _ => DependencyOwner::Unattributed {
                reason: "fixture_unattributed".into(),
            },
        },
        matched_rule_id: None,
        matched_rule_ids: Vec::new(),
        effect_index: 0,
        semantic_required: true,
    }
}
