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
pub(in crate::replay) struct KafkaProtocolReport {
    pub(in crate::replay) connections: usize,
    pub(in crate::replay) matched: Vec<KafkaMatchedReport>,
    pub(in crate::replay) unmatched: Vec<KafkaRequestReport>,
    pub(in crate::replay) unsupported: Vec<KafkaRequestReport>,
    pub(in crate::replay) unsafe_events: Vec<KafkaRequestReport>,
    pub(in crate::replay) unused_case: Vec<KafkaUnusedReport>,
    pub(in crate::replay) unused_bootstrap: Vec<KafkaUnusedReport>,
}
