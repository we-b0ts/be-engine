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
}

#[derive(Debug, Clone, Serialize)]
pub(in crate::replay) struct CommandRequestReport {
    pub(in crate::replay) case_id: Option<String>,
    pub(in crate::replay) target: TargetKey,
    pub(in crate::replay) command: String,
    pub(in crate::replay) reason: String,
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

#[derive(Debug, Clone, Default, Serialize)]
pub(in crate::replay) struct CommandProtocolReport {
    pub(in crate::replay) connections: usize,
    pub(in crate::replay) matched: Vec<CommandMatchedReport>,
    pub(in crate::replay) unmatched: Vec<CommandRequestReport>,
    pub(in crate::replay) unsupported: Vec<CommandRequestReport>,
    pub(in crate::replay) unsafe_events: Vec<CommandRequestReport>,
    pub(in crate::replay) unused_case: Vec<CommandUnusedReport>,
    pub(in crate::replay) unused_bootstrap: Vec<CommandUnusedReport>,
    pub(in crate::replay) warnings: Vec<String>,
}

impl CommandProtocolReport {
    pub(in crate::replay) fn is_dirty(&self) -> bool {
        !self.unmatched.is_empty()
            || !self.unsupported.is_empty()
            || !self.unsafe_events.is_empty()
            || !self.unused_case.is_empty()
            || !self.unused_bootstrap.is_empty()
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
