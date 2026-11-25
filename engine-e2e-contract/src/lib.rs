//! Shared inputs and published results for managed E2E execution.

use std::{collections::BTreeMap, path::PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use traffic_engine_environment::runtime_output::RuntimeOutputLocation;
use traffic_policy_content::model::{
    ResponseBodyAssertionReport, ResponseDifferenceKind, ResponseGatewayProtocol,
};
use traffic_policy_schema::response::ResponseBodyCodec;

mod event_session;
pub use event_session::{
    E2eEventSessionOptions, E2eEventSessionProgress, E2eEventSessionResult, E2eEventSessionState,
    E2eEventSessionStatus,
};

#[derive(Debug, Clone)]
pub struct E2eRunContext {
    pub target_root: PathBuf,
    pub case_source: PathBuf,
    pub run_key: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum E2eResponseGate {
    Passed,
    Nonpassing,
    Incomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum E2eReplayGate {
    Complete,
    Incomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum E2eDependencyGate {
    Clean,
    Dirty,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct E2eVerificationGates {
    pub responses: E2eResponseGate,
    pub replay: E2eReplayGate,
    pub dependencies: E2eDependencyGate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eRunResult {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine_fingerprint: Option<String>,
    pub run_key: String,
    pub sequence: u64,
    pub status: String,
    pub passed: bool,
    pub gates: E2eVerificationGates,
    pub diagnosis: E2eDiagnosis,
    pub progress: PathBuf,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runtime_outputs: Vec<RuntimeOutputLocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eApiRunResult {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine_fingerprint: Option<String>,
    pub run_key: String,
    pub api: String,
    pub attempt: u64,
    pub status: String,
    pub passed: bool,
    pub gates: E2eVerificationGates,
    pub diagnosis: E2eDiagnosis,
    pub progress: PathBuf,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runtime_outputs: Vec<RuntimeOutputLocation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct E2eDiagnosisCounts {
    pub selected: usize,
    pub executed: usize,
    pub response_passed: usize,
    pub response_nonpassing: usize,
    pub response_incomplete: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct E2eFailureCluster {
    pub pointer_pattern: String,
    pub difference_kind: ResponseDifferenceKind,
    pub affected_cases: usize,
    pub occurrences: usize,
    pub representative_case_id: String,
    pub representative_pointer: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct E2eResponseDifferenceDiagnosis {
    pub total_differences: usize,
    pub indexed_differences: usize,
    pub omitted_differences: usize,
    pub failure_clusters: Vec<E2eFailureCluster>,
    pub omitted_failure_clusters: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct E2eRepresentativeDifference {
    pub case_id: String,
    pub pointer: String,
    pub difference_kind: ResponseDifferenceKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_protocol: Option<ResponseGatewayProtocol>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_codec: Option<ResponseBodyCodec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_diagnosis: Option<ResponseBodyAssertionReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<E2eResponseUnavailableReason>,
    pub expected: E2eValueObservation,
    pub actual: E2eValueObservation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum E2eResponseUnavailableReason {
    DependencyUnmatched,
    TargetConnectionClosed,
    TargetConnectionFailed,
    TargetRequestTimedOut,
    TargetResponseReadFailed,
    RequestPreparationFailed,
    HttpExecutionFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum E2eValuePresence {
    Present,
    Missing,
    Unavailable,
    NotApplicable,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct E2eValueObservation {
    pub presence: E2eValuePresence,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    /// Format-only hint extracted before bounding/redaction; never proof of a signature.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub jwt_candidate: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct E2eDiagnosis {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case_selection: Option<Value>,
    /// Session finalization is independent of selected-case coverage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_finalized: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub execution_failures: Vec<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress_rejections: Option<Value>,
    pub counts: E2eDiagnosisCounts,
    pub response_differences: E2eResponseDifferenceDiagnosis,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub representative: Option<E2eRepresentativeDifference>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lifecycle_errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchRuleEvidence {
    pub session_id: String,
    pub sequence: u64,
    pub recording_run_id: String,
    pub source_revision: String,
    pub source_inventory_id: String,
    pub dependency_attribution_snapshot: String,
    pub execution_identity: String,
    pub engine_fingerprint: String,
    pub case_inventory_id: String,
    pub case_source: PathBuf,
    pub report: PathBuf,
    pub report_sha256: String,
    pub assertions: PathBuf,
    pub aggregate: PathBuf,
    pub runner_state: PathBuf,
    pub cases: BTreeMap<String, PathBuf>,
}
