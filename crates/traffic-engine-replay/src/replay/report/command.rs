use serde::Serialize;
use uuid::Uuid;

use super::{ReplaySource, TargetKey};

#[derive(Debug, Clone, Serialize)]
pub struct CommandMatchedReport {
    pub case_id: Option<String>,
    pub source: ReplaySource,
    pub index: usize,
    pub target: TargetKey,
    pub connection_id: Uuid,
    pub sequence: u64,
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shared_origin: Option<SharedCommandOrigin>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_event_index: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SharedCommandOrigin {
    pub rule_id: String,
    pub case_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CommandRequestReport<D = ()> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_observation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_event_index: Option<usize>,
    pub case_id: Option<String>,
    pub target: TargetKey,
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_fingerprint: Option<String>,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<CommandMatchDiagnostic<D>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CommandMatchDiagnostic<D = ()> {
    EvidenceUnavailable {
        reason: String,
    },
    NoScopedCandidate,
    Mismatch {
        fields: Vec<String>,
    },
    LaneBlocked {
        candidate: Box<CommandExchangeRefReport>,
        blocked_by: Box<CommandExchangeRefReport>,
    },
    #[serde(untagged)]
    Native(D),
}

pub use traffic_replay::command::ExchangeRef as CommandExchangeRefReport;

#[derive(Debug, Clone, Serialize)]
pub struct CommandUnusedReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_exchange_id: Option<Uuid>,
    pub index: usize,
    pub case_id: Option<String>,
    pub source: ReplaySource,
    pub target: TargetKey,
    pub connection_id: Uuid,
    pub sequence: u64,
    pub command: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CommandSnapshotOverlayReport {
    pub rule_name: String,
    pub evidence_fingerprint: String,
    pub reusable_seeds: usize,
    pub derived_seeds: usize,
    pub matching_global_exchanges: usize,
    pub matching_case_exchanges: usize,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct EmptyReport {}

#[derive(Debug, Clone, Serialize)]
pub struct CommandProtocolReport<D = (), E = EmptyReport> {
    #[serde(flatten)]
    pub extensions: E,
    pub connections: usize,
    pub matched_count: usize,
    pub matched: Vec<CommandMatchedReport>,
    pub unmatched: Vec<CommandRequestReport<D>>,
    pub unsupported: Vec<CommandRequestReport<D>>,
    pub unsafe_events: Vec<CommandRequestReport<D>>,
    pub unused_case: Vec<CommandUnusedReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unused_global_count: Option<usize>,
    pub unused_global: Vec<CommandUnusedReport>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub snapshot_overlays: Vec<CommandSnapshotOverlayReport>,
    pub warnings: Vec<String>,
}

impl<D, E> CommandProtocolReport<D, E> {
    pub fn unused_run_count(&self) -> usize {
        self.unused_global_count.unwrap_or(self.unused_global.len())
    }
    pub fn unmatched_or_unsafe(&self) -> usize {
        self.unmatched.len() + self.unsupported.len() + self.unsafe_events.len()
    }

    pub fn is_dirty(&self) -> bool {
        self.unmatched
            .iter()
            .any(|request| request.case_id.is_some())
            || self
                .unsupported
                .iter()
                .any(|request| request.case_id.is_some())
            || self
                .unsafe_events
                .iter()
                .any(|request| request.case_id.is_some())
            || !self.unused_case.is_empty()
    }

    #[cfg(test)]
    pub fn case_is_dirty(&self, case_id: &str) -> bool {
        self.unmatched
            .iter()
            .any(|request| request.case_id.as_deref() == Some(case_id))
            || self
                .unsupported
                .iter()
                .any(|request| request.case_id.as_deref() == Some(case_id))
            || self
                .unsafe_events
                .iter()
                .any(|request| request.case_id.as_deref() == Some(case_id))
            || self
                .unused_case
                .iter()
                .any(|exchange| exchange.case_id.as_deref() == Some(case_id))
    }
}

impl<D, E: Default> Default for CommandProtocolReport<D, E> {
    fn default() -> Self {
        Self {
            extensions: E::default(),
            connections: 0,
            matched_count: 0,
            matched: Vec::new(),
            unmatched: Vec::new(),
            unsupported: Vec::new(),
            unsafe_events: Vec::new(),
            unused_case: Vec::new(),
            unused_global_count: None,
            unused_global: Vec::new(),
            snapshot_overlays: Vec::new(),
            warnings: Vec::new(),
        }
    }
}

impl<D, E> std::ops::Deref for CommandProtocolReport<D, E> {
    type Target = E;
    fn deref(&self) -> &E {
        &self.extensions
    }
}
