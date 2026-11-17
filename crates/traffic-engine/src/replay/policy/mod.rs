//! Shared Replay policy lifecycle and value-rule services supplied by the application.
use std::{collections::BTreeMap, fmt::Debug, path::Path, sync::Arc};

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use traffic_protocol::connection::NativeFuture;

use super::{ReplayCase, execution_plan::PreparedCaseRules};

mod hypotheses;
pub use hypotheses::{HypothesisAttempt, HypothesisContext};
pub mod values;
pub use values::ValueRuleHost;
mod evidence_policy;
pub use evidence_policy::ReplayEvidencePolicyFreshness;

#[derive(Debug, Clone, Serialize)]
pub struct PolicyReport {
    pub fingerprint: String,
    pub unused_applicable_dependency_rule_ids: Vec<String>,
    #[serde(flatten)]
    pub details: BTreeMap<String, Value>,
}

pub trait ReplayPolicy: Debug + Send + Sized + 'static {
    type Contracts: RequestRuleRuntime;

    fn load(path: &Path, cases: &BTreeMap<String, ReplayCase>, observe: bool) -> Result<Self>;
    fn contracts(&self) -> &Self::Contracts;
    fn contracts_mut(&mut self) -> &mut Self::Contracts;
    fn fingerprint(&self) -> &str;
    fn report(&self) -> PolicyReport;
    fn begin_case(&mut self, case: &str);
    fn observe_source(
        &mut self,
        case: &str,
        raw: &[u8],
        index: Option<&crate::dependency_index::FileIndex>,
    ) -> Result<()>;
    fn async_rules(&self) -> crate::recorder::async_api::CompletionPolicy;
}

pub trait RequestRuleRuntime: Debug + Clone + Send + Sync + 'static {
    type PreparedInput: Send + 'static;

    fn native_rules(&self) -> Arc<dyn ValueRuleHost>;
    fn configure_pre_match(&mut self, enabled: bool);
    fn configure_witnesses(
        &mut self,
        witnesses: crate::policy_evidence::WitnessStore,
        observe: bool,
    ) -> Result<()>;
    fn prepare_case_rules(&self, case: &str) -> Result<PreparedCaseRules>;
    fn request_begin(&self, case: &str) -> Result<()>;
    fn request_times(&self, case: &str) -> traffic_contract::time::ClockPair;
    fn case_flags(&self, case: &str) -> BTreeMap<String, Value>;
    fn clear_case_values(&self, case: &str);
    fn control_is_read_only(&self, _command: &str) -> bool {
        false
    }
    fn control(
        &self,
        case: Option<&str>,
        command: &str,
        parameters: &BTreeMap<String, traffic_value::Value>,
    ) -> Result<Option<Value>>;
    fn prepare_derived_inputs(
        &self,
        case: &str,
        sent_at: DateTime<Utc>,
        actual: &Value,
    ) -> Result<Self::PreparedInput>;
    fn commit_derived_inputs(&self, prepared: Self::PreparedInput) -> Result<()>;
    fn hypothesis_attempts(&self) -> Vec<HypothesisAttempt>;
    fn hypothesis_coverage_error(&self) -> Option<String>;
    fn hypothesis_journal_manifest(
        &self,
    ) -> Option<crate::policy_evidence::hypotheses::JournalManifest>;
    fn pre_match_reports(&self) -> Vec<crate::value_contract::pre_match::Candidate>;
    fn await_hypotheses_durable(&self) -> NativeFuture<'_, ()>;
}
