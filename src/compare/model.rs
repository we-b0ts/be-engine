use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::recorder::HeaderMapSnapshot;

#[derive(Debug, Clone, Serialize)]
pub(super) struct CompareBodyCapture {
    pub(super) encoding: &'static str,
    pub(super) original_len: Option<usize>,
    pub(super) stored_len: usize,
    pub(super) truncated: bool,
    pub(super) data: String,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct CompareRequestRecord {
    pub(super) timestamp: DateTime<Utc>,
    pub(super) client_addr: Option<String>,
    pub(super) method: String,
    pub(super) uri: String,
    pub(super) authority: Option<String>,
    pub(super) matched_rule: String,
    pub(super) headers: HeaderMapSnapshot,
    pub(super) body: CompareBodyCapture,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct CompareResponseRecord {
    pub(super) timestamp: DateTime<Utc>,
    pub(super) upstream: String,
    pub(super) status: Option<u16>,
    pub(super) headers: Option<HeaderMapSnapshot>,
    pub(super) body: Option<CompareBodyCapture>,
    pub(super) duration_ms: u128,
    pub(super) error: Option<String>,
}

#[derive(Debug)]
pub(super) struct CompareCase {
    pub(super) id: uuid::Uuid,
    pub(super) rule: String,
    pub(super) group: String,
    pub(super) pattern: String,
    pub(super) request: CompareRequestRecord,
    pub(super) baseline: CompareResponseRecord,
    pub(super) candidate: CompareResponseRecord,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct CaseKind {
    pub(super) version: u8,
    pub(super) kind: &'static str,
}

impl Default for CaseKind {
    fn default() -> Self {
        Self {
            version: 1,
            kind: "online_compare",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub(super) struct ApiCounts {
    pub(super) published: usize,
    pub(super) failed: usize,
    pub(super) suppressed_by_case_limit: usize,
    pub(super) last_observed_at: Option<DateTime<Utc>>,
    pub(super) last_baseline_status: Option<u16>,
    pub(super) last_candidate_status: Option<u16>,
    pub(super) last_baseline_error: Option<String>,
    pub(super) last_candidate_error: Option<String>,
}

pub(super) type ApiCountMap = BTreeMap<String, ApiCounts>;
