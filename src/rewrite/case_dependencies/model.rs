use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::Serialize;
use serde_json::Value;

use super::super::model::RewriteCommandSpec;

#[derive(Debug, Clone)]
pub struct RewriteCaseDependenciesOptions {
    pub target_root: PathBuf,
    pub case_dir: PathBuf,
    pub target_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RewriteCaseDependenciesReport {
    Summary {
        case_dir: PathBuf,
        total_events: usize,
        targeted_events: usize,
        ungrouped_events: usize,
        targets_total: usize,
        targets: Vec<RewriteCaseDependencyTargetSummary>,
        next_step: String,
    },
    Detail {
        case_dir: PathBuf,
        target: RewriteCaseDependencyTarget,
        event_count: usize,
        event_types: BTreeMap<String, usize>,
        commands: BTreeMap<String, usize>,
        #[serde(flatten)]
        protocol_detail: RewriteCaseDependencyProtocolDetail,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteCaseDependencyTargetSummary {
    pub target_id: String,
    pub protocol: String,
    pub target: String,
    pub event_count: usize,
    pub commands: BTreeMap<String, usize>,
    pub detail_command: RewriteCommandSpec,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteCaseDependencyTarget {
    pub target_id: String,
    pub protocol: String,
    pub target: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "detail_kind", rename_all = "snake_case")]
pub enum RewriteCaseDependencyProtocolDetail {
    Redis {
        operations: Vec<RewriteRedisOperationDetail>,
    },
    Memcached {
        operations: Vec<RewriteMemcachedOperationDetail>,
    },
    Generic,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteRedisOperationDetail {
    pub command: String,
    pub count: usize,
    pub outcomes: BTreeMap<String, usize>,
    pub response_kinds: BTreeMap<String, usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub representative_exchanges: Vec<RewriteRedisExchangeDetail>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub omitted_representative_exchanges: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteRedisExchangeDetail {
    pub keys: Vec<RewriteCapturePreview>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub omitted_keys: usize,
    pub args: Vec<RewriteCapturePreview>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub omitted_args: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<RewriteCapturePreview>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_value: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteMemcachedOperationDetail {
    pub command: String,
    pub count: usize,
    pub outcomes: BTreeMap<String, usize>,
    pub response_statuses: BTreeMap<String, usize>,
    pub hits: usize,
    pub misses: usize,
    pub response_bytes: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub representative_exchanges: Vec<RewriteMemcachedExchangeDetail>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub omitted_representative_exchanges: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteMemcachedExchangeDetail {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<RewriteCapturePreview>,
    pub response_status: String,
    pub response_classification: String,
    pub response_bytes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RewriteCapturePreview {
    pub encoding: String,
    pub data: String,
    pub original_len: usize,
    pub truncated: bool,
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}
