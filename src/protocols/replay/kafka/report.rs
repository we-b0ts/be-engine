use serde::Serialize;

use crate::replay::{ReplaySource, TargetKey};

#[derive(Debug, Clone, Serialize)]
pub(crate) struct KafkaMatchedReport {
    pub(crate) case_id: Option<String>,
    pub(crate) source: ReplaySource,
    pub(crate) index: usize,
    pub(crate) target: TargetKey,
    pub(crate) operation: String,
    pub(crate) topic: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) target_event_index: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct KafkaRequestReport {
    pub(crate) case_id: Option<String>,
    pub(crate) target: TargetKey,
    pub(crate) operation: String,
    pub(crate) topic: Option<String>,
    pub(crate) reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct KafkaUnusedReport {
    pub(crate) index: usize,
    pub(crate) case_id: Option<String>,
    pub(crate) source: ReplaySource,
    pub(crate) target: TargetKey,
    pub(crate) operation: String,
    pub(crate) topic: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct KafkaProtocolReport {
    pub(crate) connections: usize,
    pub(crate) matched_count: usize,
    pub(crate) matched: Vec<KafkaMatchedReport>,
    pub(crate) unmatched: Vec<KafkaRequestReport>,
    pub(crate) unsupported: Vec<KafkaRequestReport>,
    pub(crate) unsafe_events: Vec<KafkaRequestReport>,
    pub(crate) unused_case: Vec<KafkaUnusedReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) unused_global_count: Option<usize>,
    pub(crate) unused_global: Vec<KafkaUnusedReport>,
}

impl KafkaProtocolReport {
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
