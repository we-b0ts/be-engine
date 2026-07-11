use serde::Serialize;
use uuid::Uuid;

use super::{ReplaySource, TargetKey};

#[derive(Debug, Clone, Serialize)]
pub(in crate::replay) struct CacheMatchedReport {
    pub(in crate::replay) case_id: Option<String>,
    pub(in crate::replay) source: ReplaySource,
    pub(in crate::replay) index: usize,
    pub(in crate::replay) target: TargetKey,
    pub(in crate::replay) connection_id: Uuid,
    pub(in crate::replay) sequence: u64,
    pub(in crate::replay) command: String,
}

#[derive(Debug, Clone, Serialize)]
pub(in crate::replay) struct CacheRequestReport {
    pub(in crate::replay) case_id: Option<String>,
    pub(in crate::replay) target: TargetKey,
    pub(in crate::replay) command: String,
    pub(in crate::replay) reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub(in crate::replay) struct CacheUnusedReport {
    pub(in crate::replay) index: usize,
    pub(in crate::replay) case_id: Option<String>,
    pub(in crate::replay) source: ReplaySource,
    pub(in crate::replay) target: TargetKey,
    pub(in crate::replay) connection_id: Uuid,
    pub(in crate::replay) sequence: u64,
    pub(in crate::replay) command: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub(in crate::replay) struct CacheProtocolsReport {
    pub(in crate::replay) redis: CacheProtocolReport,
    pub(in crate::replay) memcached: CacheProtocolReport,
}

#[derive(Debug, Clone, Default, Serialize)]
pub(in crate::replay) struct CacheProtocolReport {
    pub(in crate::replay) connections: usize,
    pub(in crate::replay) matched: Vec<CacheMatchedReport>,
    pub(in crate::replay) unmatched: Vec<CacheRequestReport>,
    pub(in crate::replay) unsupported: Vec<CacheRequestReport>,
    pub(in crate::replay) unsafe_events: Vec<CacheRequestReport>,
    pub(in crate::replay) unused_case: Vec<CacheUnusedReport>,
    pub(in crate::replay) unused_bootstrap: Vec<CacheUnusedReport>,
    pub(in crate::replay) warnings: Vec<String>,
}
