//! Shared correspondence state and value services used by native execution.
use std::sync::{Arc, Mutex};

use anyhow::{Result, ensure};
use chrono::{DateTime, Utc};
use serde_json::Value;
use traffic_contract::{
    compare::{AnchorClocks, Comparison},
    identity::{
        IdentityDecision, IdentityDelivery, IdentityPair, IdentityStore, PreparedIdentityDelivery,
    },
    time::ClockPair,
};

#[derive(Clone, Default)]
pub(crate) struct ValueState {
    pub identities: Arc<Mutex<IdentityStore>>,
    pub time_copies: Arc<Mutex<crate::value_contract::time_copies::TimeCopyStore>>,
}

impl std::fmt::Debug for ValueState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ValueState").finish_non_exhaustive()
    }
}

pub(crate) struct ValueDecision {
    pub comparison: Comparison,
    pub identity: Option<IdentityDecision>,
}

impl ValueState {
    pub fn preview(&self, scope: &str, pairs: &[IdentityPair]) -> Result<IdentityDecision> {
        let decision = IdentityDecision::prepare(scope, pairs.to_vec())?;
        self.identities
            .lock()
            .expect("identity contracts")
            .validate(&decision)?;
        Ok(decision)
    }

    pub fn commit(&self, decision: IdentityDecision) -> Result<()> {
        if !decision.is_empty() {
            self.identities
                .lock()
                .expect("identity contracts")
                .commit(decision)?;
        }
        Ok(())
    }

    pub fn deliveries(
        &self,
        scope: &str,
        selected: &[IdentityDelivery<'_>],
    ) -> Result<(Vec<Value>, IdentityDecision)> {
        if selected.is_empty() {
            return Ok((vec![], IdentityDecision::prepare(scope, vec![])?));
        }
        ensure!(
            selected.len() <= 4096,
            "identity delivery leaf bound exceeded"
        );
        let prepared = selected
            .iter()
            .copied()
            .map(PreparedIdentityDelivery::prepare)
            .collect::<Result<Vec<_>>>()?;
        self.identities
            .lock()
            .expect("identity contracts")
            .deliveries(scope, &prepared)
    }

    pub fn clear(&self, scope: &str) {
        self.identities
            .lock()
            .expect("identity contracts")
            .begin_case(scope);
    }
}

pub(crate) trait IdentityDeliveryHost {
    fn translate_identity_plan(
        &self,
        case: &str,
        source: &Value,
        delivered: &mut Value,
        global: &crate::policy::CompiledJsonPolicy,
    ) -> Result<(IdentityDecision, Vec<String>)>;
}

pub(crate) trait ValueRuleHost: std::fmt::Debug + Send + Sync {
    fn translate_document(
        &self,
        _scope: &str,
        _source: &Value,
        _delivered: &mut Value,
        _clocks: AnchorClocks,
    ) -> Result<()> {
        Ok(())
    }
    fn document_policy(
        &self,
        _clocks: AnchorClocks,
    ) -> Option<Arc<dyn traffic_replay::rules::DocumentPolicy>> {
        None
    }
    fn begin_case(&self, case: &str);
    fn clear_identities(&self, case: &str);
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

/// Strict sessions still share finite, case-local identity accounting.
impl ValueRuleHost for ValueState {
    fn begin_case(&self, case: &str) {
        self.clear(case);
    }
    fn clear_identities(&self, case: &str) {
        self.clear(case);
    }
    fn preview_identity_pairs(
        &self,
        scope: &str,
        pairs: &[IdentityPair],
        _: bool,
    ) -> Result<IdentityDecision> {
        self.preview(scope, pairs)
    }
    fn identity_deliveries(
        &self,
        scope: &str,
        selected: &[IdentityDelivery<'_>],
    ) -> Result<(Vec<Value>, IdentityDecision)> {
        self.deliveries(scope, selected)
    }
    fn commit_comparison(&self, comparison: Comparison, identity: IdentityDecision) -> Result<()> {
        ensure!(
            comparison.passed(),
            "failed value comparison cannot commit identities"
        );
        self.commit(identity)
    }
    fn contract_clocks(
        &self,
        _: Option<&str>,
        source_dependency: Option<DateTime<Utc>>,
        target_dependency: Option<DateTime<Utc>>,
        source_delivery: Option<DateTime<Utc>>,
        target_delivery: Option<DateTime<Utc>>,
    ) -> AnchorClocks {
        AnchorClocks::for_request(
            ClockPair::default(),
            ClockPair {
                source: source_dependency,
                target: target_dependency,
            },
            ClockPair {
                source: source_delivery,
                target: target_delivery,
            },
        )
    }
}
