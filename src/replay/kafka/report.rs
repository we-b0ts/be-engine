use serde::Serialize;

use super::super::{ReplaySource, TargetKey};

#[derive(Debug, Clone, Serialize)]
pub(in crate::replay) struct KafkaMatchedReport {
    pub(in crate::replay) case_id: Option<String>,
    pub(in crate::replay) source: ReplaySource,
    pub(in crate::replay) index: usize,
    pub(in crate::replay) target: TargetKey,
    pub(in crate::replay) operation: String,
    pub(in crate::replay) topic: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) target_event_index: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub(in crate::replay) struct KafkaRequestReport {
    pub(in crate::replay) case_id: Option<String>,
    pub(in crate::replay) target: TargetKey,
    pub(in crate::replay) operation: String,
    pub(in crate::replay) topic: Option<String>,
    pub(in crate::replay) reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub(in crate::replay) struct KafkaUnusedReport {
    pub(in crate::replay) index: usize,
    pub(in crate::replay) case_id: Option<String>,
    pub(in crate::replay) source: ReplaySource,
    pub(in crate::replay) target: TargetKey,
    pub(in crate::replay) operation: String,
    pub(in crate::replay) topic: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct KafkaProtocolReport {
    pub(in crate::replay) connections: usize,
    pub(in crate::replay) matched_count: usize,
    pub(in crate::replay) matched: Vec<KafkaMatchedReport>,
    pub(in crate::replay) unmatched: Vec<KafkaRequestReport>,
    pub(in crate::replay) unsupported: Vec<KafkaRequestReport>,
    pub(in crate::replay) unsafe_events: Vec<KafkaRequestReport>,
    pub(in crate::replay) unused_case: Vec<KafkaUnusedReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) unused_global_count: Option<usize>,
    pub(in crate::replay) unused_global: Vec<KafkaUnusedReport>,
}

impl KafkaProtocolReport {
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
