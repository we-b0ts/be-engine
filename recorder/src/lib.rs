//! Recording admission, durable event queues, finite capture receipts and sealing.

pub use traffic_recording_store::{artifact_file, storage};
mod clock;
mod extensions;
pub use clock::RecordingClock;
pub use extensions::RecordingExtensions;
pub use traffic_protocol::capture::CaptureSnapshot as CapturedEvent;
mod event;
mod jsonl {
    pub use traffic_recording_store::writer::{
        BufferedJsonlWriter, JsonlBufferSettings, JsonlWriterPool,
    };
}
pub mod ledger;
mod session;
pub mod source_process;
#[cfg(test)]
mod tests;
mod writer;

pub use event::{CaseContext, DependencyConnectFailureEvent, ProxyErrorEvent};
pub use jsonl::JsonlBufferSettings;
pub use writer::{CaptureOptions, RecordEnvelope, RecorderWriter};

use serde::{Deserialize, Serialize};
use traffic_model::{attribution::DependencyOwner, recording::CapturePhase};
use traffic_protocol::evidence::EvidenceRegistry;
use uuid::Uuid;

/// The host retains its admission and activity reservations while queued storage
/// borrows this view. Dropping the queued scope releases those original guards.
pub trait CaptureScope: Send + Sync {
    fn context(&self) -> CaptureContext<'_>;
}

pub struct CaptureContext<'a> {
    pub cases: &'a [(CaseContext, &'static str)],
    pub bootstrap_open: bool,
    pub ambiguous_active_cases: usize,
    pub process_owned_rule: Option<&'a str>,
    pub process_rule_ids: &'a [String],
    pub unattributed_reason: Option<&'static str>,
    pub observed_case: Option<Uuid>,
    pub shutdown_case_id: Option<Uuid>,
    pub phase: CapturePhase,
    pub capture: Option<&'a ledger::CaptureReservation>,
}

pub struct GlobalDependencyAttribution {
    pub reason: &'static str,
    pub phase: &'static str,
    pub matched_by: String,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrafficJsonlMode {
    #[default]
    Full,
    Errors,
    Off,
}

impl TrafficJsonlMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Errors => "errors",
            Self::Off => "off",
        }
    }
}

pub fn should_write_traffic_event(
    mode: TrafficJsonlMode,
    event: &impl traffic_protocol::capture::CaptureEvidence,
) -> bool {
    match mode {
        TrafficJsonlMode::Full => true,
        TrafficJsonlMode::Off => false,
        TrafficJsonlMode::Errors => event.capture_facts().traffic_error,
    }
}

pub fn supports_replay(
    event: &serde_json::Value,
    owner: &DependencyOwner,
    registry: &EvidenceRegistry,
) -> bool {
    if event["event_type"] == "dependency_connect_failure" {
        return matches!(owner, DependencyOwner::Case { .. })
            && event["replay_safe"] != false
            && event["capture_complete"] != false
            && event["_capture_complete"] != false;
    }
    registry.supports_replay(event)
}

#[cfg(feature = "test-support")]
pub mod test_support {
    pub use crate::jsonl::JsonlWriterPool;
    pub use crate::ledger::persistence::LedgerWriter;
}
