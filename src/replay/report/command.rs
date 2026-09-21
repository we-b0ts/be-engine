use serde::Serialize;
use uuid::Uuid;

use super::{ReplaySource, TargetKey};

#[derive(Debug, Clone, Serialize)]
pub(in crate::replay) struct CommandMatchedReport {
    pub(in crate::replay) case_id: Option<String>,
    pub(in crate::replay) source: ReplaySource,
    pub(in crate::replay) index: usize,
    pub(in crate::replay) target: TargetKey,
    pub(in crate::replay) connection_id: Uuid,
    pub(in crate::replay) sequence: u64,
    pub(in crate::replay) command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) target_event_index: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub(in crate::replay) struct CommandRequestReport {
    pub(in crate::replay) case_id: Option<String>,
    pub(in crate::replay) target: TargetKey,
    pub(in crate::replay) command: String,
    pub(in crate::replay) reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) diagnostic: Option<CommandMatchDiagnostic>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(in crate::replay) enum CommandMatchDiagnostic {
    NoScopedCandidate,
    Mismatch {
        fields: Vec<String>,
    },
    LaneBlocked {
        candidate: Box<CommandExchangeRefReport>,
        blocked_by: Box<CommandExchangeRefReport>,
    },
}

#[derive(Debug, Clone, Serialize)]
pub(in crate::replay) struct CommandExchangeRefReport {
    pub(in crate::replay) case_id: Option<String>,
    pub(in crate::replay) source: ReplaySource,
    pub(in crate::replay) connection_id: Uuid,
    pub(in crate::replay) sequence: u64,
    pub(in crate::replay) command: String,
}

#[derive(Debug, Clone, Serialize)]
pub(in crate::replay) struct CommandUnusedReport {
    pub(in crate::replay) index: usize,
    pub(in crate::replay) case_id: Option<String>,
    pub(in crate::replay) source: ReplaySource,
    pub(in crate::replay) target: TargetKey,
    pub(in crate::replay) connection_id: Uuid,
    pub(in crate::replay) sequence: u64,
    pub(in crate::replay) command: String,
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
pub(in crate::replay) struct CommandProtocolReport {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(in crate::replay) time_shifts: Vec<crate::replay::redis::time_shift::TimeShiftObservation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) unordered_value:
        Option<crate::replay::redis::value::evidence::OrderEvidence>,
    pub(in crate::replay) connections: usize,
    pub(in crate::replay) matched_count: usize,
    pub(in crate::replay) matched: Vec<CommandMatchedReport>,
    pub(in crate::replay) unmatched: Vec<CommandRequestReport>,
    pub(in crate::replay) unsupported: Vec<CommandRequestReport>,
    pub(in crate::replay) unsafe_events: Vec<CommandRequestReport>,
    pub(in crate::replay) unused_case: Vec<CommandUnusedReport>,
    pub(in crate::replay) unused_global: Vec<CommandUnusedReport>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(in crate::replay) snapshot_overlays: Vec<CommandSnapshotOverlayReport>,
    pub(in crate::replay) warnings: Vec<String>,
}

impl CommandProtocolReport {
    pub(in crate::replay) fn is_dirty(&self) -> bool {
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

    pub(in crate::replay) fn case_is_dirty(&self, case_id: &str) -> bool {
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
