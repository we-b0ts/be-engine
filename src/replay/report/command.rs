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
    pub(in crate::replay) shared_origin: Option<SharedCommandOrigin>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) target_event_index: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub(in crate::replay) struct SharedCommandOrigin {
    pub(in crate::replay) rule_id: String,
    pub(in crate::replay) case_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub(in crate::replay) struct CommandRequestReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) target_observation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) target_event_index: Option<usize>,
    pub(in crate::replay) case_id: Option<String>,
    pub(in crate::replay) target: TargetKey,
    pub(in crate::replay) command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) request_fingerprint: Option<String>,
    pub(in crate::replay) reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) diagnostic: Option<CommandMatchDiagnostic>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(in crate::replay) enum CommandMatchDiagnostic {
    EvidenceUnavailable {
        reason: String,
    },
    NoScopedCandidate,
    Mismatch {
        fields: Vec<String>,
    },
    RedisAppendStreamMismatch {
        #[serde(flatten)]
        details: Box<crate::replay::redis::append::AppendMismatch>,
    },
    RedisAppendStreamBoundaryMismatch {
        #[serde(flatten)]
        details: Box<crate::replay::redis::append::AppendBoundaryMismatch>,
    },
    RedisStateObservationMismatch {
        rule_id: String,
        source_key_fingerprint: String,
        source_epoch_mutation: Option<Box<CommandExchangeRefReport>>,
        reason: String,
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
    pub(in crate::replay) activity_refreshes: Vec<crate::replay::redis::activity::ActivityAudit>,
    pub(in crate::replay) activity_refreshes_omitted: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(in crate::replay) state_observations:
        Vec<crate::replay::redis::observations::ObservationAudit>,
    pub(in crate::replay) state_observations_omitted: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) target_event_index_scope: Option<&'static str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(in crate::replay) append_streams: Vec<crate::replay::redis::append::AppendAudit>,
    pub(in crate::replay) append_streams_omitted: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) pubsub: Option<PubSubReport>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) unused_global_count: Option<usize>,
    pub(in crate::replay) unused_global: Vec<CommandUnusedReport>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(in crate::replay) snapshot_overlays: Vec<CommandSnapshotOverlayReport>,
    pub(in crate::replay) warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(in crate::replay) struct PubSubReport {
    pub recorded_pushes: usize,
    pub delivered_pushes: usize,
    pub recorded_rpc_callbacks: usize,
    pub delivered_rpc_callbacks: usize,
    pub failed_pushes: usize,
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

    #[cfg(test)]
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
