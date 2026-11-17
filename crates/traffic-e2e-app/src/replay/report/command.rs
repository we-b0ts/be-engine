use serde::Serialize;
use uuid::Uuid;

use super::{ReplaySource, TargetKey};

#[derive(Debug, Clone, Serialize)]
pub(crate) struct CommandMatchedReport {
    pub(crate) case_id: Option<String>,
    pub(crate) source: ReplaySource,
    pub(crate) index: usize,
    pub(crate) target: TargetKey,
    pub(crate) connection_id: Uuid,
    pub(crate) sequence: u64,
    pub(crate) command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) shared_origin: Option<SharedCommandOrigin>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) target_event_index: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct SharedCommandOrigin {
    pub(crate) rule_id: String,
    pub(crate) case_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct CommandRequestReport<D = ()> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) target_observation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) target_event_index: Option<usize>,
    pub(crate) case_id: Option<String>,
    pub(crate) target: TargetKey,
    pub(crate) command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) request_fingerprint: Option<String>,
    pub(crate) reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) diagnostic: Option<CommandMatchDiagnostic<D>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum CommandMatchDiagnostic<D = ()> {
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

pub(crate) use traffic_replay::command::ExchangeRef as CommandExchangeRefReport;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct CommandUnusedReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) source_exchange_id: Option<Uuid>,
    pub(crate) index: usize,
    pub(crate) case_id: Option<String>,
    pub(crate) source: ReplaySource,
    pub(crate) target: TargetKey,
    pub(crate) connection_id: Uuid,
    pub(crate) sequence: u64,
    pub(crate) command: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct CommandSnapshotOverlayReport {
    pub rule_name: String,
    pub evidence_fingerprint: String,
    pub reusable_seeds: usize,
    pub derived_seeds: usize,
    pub matching_global_exchanges: usize,
    pub matching_case_exchanges: usize,
}

#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct EmptyReport {}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct CommandProtocolReport<D = (), E = EmptyReport> {
    #[serde(flatten)]
    pub(crate) extensions: E,
    pub(crate) connections: usize,
    pub(crate) matched_count: usize,
    pub(crate) matched: Vec<CommandMatchedReport>,
    pub(crate) unmatched: Vec<CommandRequestReport<D>>,
    pub(crate) unsupported: Vec<CommandRequestReport<D>>,
    pub(crate) unsafe_events: Vec<CommandRequestReport<D>>,
    pub(crate) unused_case: Vec<CommandUnusedReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) unused_global_count: Option<usize>,
    pub(crate) unused_global: Vec<CommandUnusedReport>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) snapshot_overlays: Vec<CommandSnapshotOverlayReport>,
    pub(crate) warnings: Vec<String>,
}

impl<D, E> CommandProtocolReport<D, E> {
    pub(crate) fn unused_run_count(&self) -> usize {
        self.unused_global_count.unwrap_or(self.unused_global.len())
    }
    pub(crate) fn unmatched_or_unsafe(&self) -> usize {
        self.unmatched.len() + self.unsupported.len() + self.unsafe_events.len()
    }

    pub(crate) fn is_dirty(&self) -> bool {
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
    pub(crate) fn case_is_dirty(&self, case_id: &str) -> bool {
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
