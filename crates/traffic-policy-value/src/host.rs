//! Phase-independent value services supplied by the execution owner.
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde_json::Value;
use std::sync::Arc;
use traffic_contract::{
    compare::{AnchorClocks, Comparison},
    identity::{IdentityDecision, IdentityDelivery, IdentityPair},
};

pub struct ValueDecision {
    pub comparison: Comparison,
    pub identity: Option<IdentityDecision>,
}

pub trait ValueRuleHost: std::fmt::Debug + Send + Sync {
    fn translate_document(
        &self,
        _scope: &str,
        _source: &Value,
        _delivered: &mut Value,
        _clocks: AnchorClocks,
    ) -> Result<()> {
        Ok(())
    }
    fn document_policy(&self, _clocks: AnchorClocks) -> Option<Arc<dyn crate::DocumentPolicy>> {
        None
    }
    fn begin_case(&self, case: &str);
    fn clear_case_values(&self, case: &str);
    fn case_flags(&self, _case: &str) -> std::collections::BTreeMap<String, Value> {
        Default::default()
    }
    fn control_is_read_only(&self, _command: &str) -> bool {
        false
    }
    fn control(
        &self,
        _case: Option<&str>,
        _command: &str,
        _parameters: &std::collections::BTreeMap<String, traffic_value::Value>,
    ) -> Result<Option<Value>> {
        Ok(None)
    }
    fn preview_identity_pairs(
        &self,
        scope: &str,
        pairs: &[IdentityPair],
        case_owned: bool,
    ) -> Result<IdentityDecision>;
    fn identity_deliveries(
        &self,
        scope: &str,
        selected: &[IdentityDelivery<'_>],
    ) -> Result<(Vec<Value>, IdentityDecision)>;
    fn commit_comparison(&self, comparison: Comparison, identity: IdentityDecision) -> Result<()>;
    fn contract_clocks(
        &self,
        case: Option<&str>,
        source_dependency: Option<DateTime<Utc>>,
        target_dependency: Option<DateTime<Utc>>,
        source_delivery: Option<DateTime<Utc>>,
        target_delivery: Option<DateTime<Utc>>,
    ) -> AnchorClocks;
}
