//! Application correspondence and read-provenance stores supplied to Replay.
use crate::replay::policy::ValueRuleHost;
use anyhow::{Result, ensure};
use chrono::{DateTime, Utc};
use serde_json::Value;
use std::sync::{Arc, Mutex};
use traffic_contract::{
    compare::{AnchorClocks, Comparison},
    identity::{IdentityDecision, IdentityPair, IdentityStore},
    time::ClockPair,
};
use traffic_policy_value::identity::IdentityDelivery;

#[derive(Clone, Default)]
pub struct ValueState {
    pub identities: Arc<Mutex<IdentityStore>>,
    pub time_copies: Arc<Mutex<crate::value_contract::time_copies::TimeCopyStore>>,
}

impl std::fmt::Debug for ValueState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ValueState").finish_non_exhaustive()
    }
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
            .map(|selected| selected.prepare(traffic_extensions::policies()))
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

/// Strict sessions still share finite, case-local identity accounting.
impl ValueRuleHost for ValueState {
    fn metadata(&self) -> &(dyn traffic_contract::compare::RuleMetadata + 'static) {
        &crate::value_contract::json::PolicyMetadata
    }

    fn begin_case(&self, case: &str) {
        self.clear(case);
    }
    fn clear_case_values(&self, case: &str) {
        self.clear(case);
    }
    fn case_flags(&self, _: &str) -> std::collections::BTreeMap<String, Value> {
        std::collections::BTreeMap::from([("has_response_time_copies".into(), Value::Bool(false))])
    }
    fn control_is_read_only(&self, command: &str) -> bool {
        command == "response_time_copies"
    }
    fn control(
        &self,
        case: Option<&str>,
        command: &str,
        _: &std::collections::BTreeMap<String, traffic_value::Value>,
    ) -> Result<Option<Value>> {
        if command != "response_time_copies" {
            return Ok(None);
        }
        ensure!(
            case.is_some(),
            "response provenance requires the active case"
        );
        Ok(Some(serde_json::json!({"ok":true,
            "time_copies":crate::value_contract::time_copies::DeliveredTimeCopies::default()})))
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
