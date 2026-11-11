//! Recording schema and source ownership views.
pub use traffic_model::recording::*;

#[cfg(test)]
use super::attribution::DependencyOwner;
#[cfg(test)]
use chrono::Utc;
#[cfg(test)]
use uuid::Uuid;

#[cfg(test)]
pub(crate) fn fixture_capture(kind: &str) -> CaptureMetadata {
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
        protocol_ref: ProtocolRef::Observation {
            event_id: Uuid::new_v4(),
            kind: "fixture".into(),
        },
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
