use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::recorder::{CaseBodyCapture, HeaderMapSnapshot};

#[derive(Debug, Clone, Serialize)]
pub(super) struct ComparisonRecordingBody {
    pub(super) encoding: &'static str,
    pub(super) original_len: Option<usize>,
    pub(super) stored_len: usize,
    pub(super) truncated: bool,
    pub(super) data: String,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct ComparisonRecordingRequest {
    pub(super) protocol: &'static str,
    pub(super) timestamp: DateTime<Utc>,
    pub(super) client_addr: Option<String>,
    pub(super) method: String,
    pub(super) uri: String,
    pub(super) authority: Option<String>,
    pub(super) matched_rule: String,
    pub(super) api_pattern: String,
    pub(super) headers: HeaderMapSnapshot,
    pub(super) body: ComparisonRecordingBody,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) protocol_version: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) request_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) api_key: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct ComparisonRecordingResponse {
    pub(super) version: u8,
    pub(super) timestamp: DateTime<Utc>,
    pub(super) upstream: String,
    pub(super) status: Option<u16>,
    pub(super) headers: Option<HeaderMapSnapshot>,
    pub(super) body: Option<CaseBodyCapture>,
    pub(super) duration_ms: u128,
    pub(super) error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) protocol_version: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) serialization: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) rpc_status: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) rpc_body_decoded: Option<bool>,
}

#[derive(Debug)]
pub(super) struct ComparisonRecordingCase {
    pub(super) id: uuid::Uuid,
    pub(super) group: String,
    pub(super) request: ComparisonRecordingRequest,
    pub(super) baseline: ComparisonRecordingResponse,
    pub(super) candidate: ComparisonRecordingResponse,
    pub(super) baseline_recheck: Option<ComparisonRecordingResponse>,
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
            kind: "comparison_recording",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub(super) struct ApiCounts {
    pub(super) published: usize,
    pub(super) failed: usize,
    pub(super) verification_failed: usize,
    pub(super) failure_limit_reached: bool,
    pub(super) suppressed_by_case_limit: usize,
    pub(super) suppressed_by_failure_limit: usize,
    pub(super) last_observed_at: Option<DateTime<Utc>>,
    pub(super) last_baseline_status: Option<u16>,
    pub(super) last_baseline_recheck_status: Option<u16>,
    pub(super) last_candidate_status: Option<u16>,
    pub(super) last_baseline_error: Option<String>,
    pub(super) last_baseline_recheck_error: Option<String>,
    pub(super) last_candidate_error: Option<String>,
}

pub(super) type ApiCountMap = BTreeMap<String, ApiCounts>;
