//! Case-local identity mappings shared by decoded dependency protocol adapters.
mod audit;
mod candidates;
#[cfg(test)]
mod conditional_redis_tests;
mod config;
mod http;
mod identities;
#[cfg(test)]
mod lset_tests;
mod mysql;
#[cfg(test)]
mod mysql_table_tests;
mod path_candidates;
mod path_segment;
mod redis;
mod redis_json;
mod scopes;
mod source;
#[cfg(test)]
pub(crate) use audit::from_report;
#[cfg(test)]
pub(crate) use source::from_event as recorded_capture;
mod source_coverage;
mod strings;
pub(crate) use audit::{DynamicBindingReport, from_native_report};
pub(crate) use candidates::CaptureCandidate;
#[cfg(test)]
pub(crate) use config::validate;
pub use config::{
    DynamicValueCapture, DynamicValueFormat, DynamicValueRule, DynamicValueTarget,
    DynamicValueType, PathSegmentCapture, PathSegmentField, RedisCaptureReference,
    RedisDerivedIdentity,
};
pub(crate) use http::HttpInput;
pub(crate) use redis::RedisIdentity;

use crate::replay::TargetKey;
use anyhow::{Result, ensure};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct IdentityPair {
    pub source: String,
    pub target: String,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct DynamicDecision {
    pub(super) pairs: Vec<(String, IdentityPair)>,
}

#[cfg(test)]
type NormalizedArguments = (Vec<Vec<u8>>, Vec<Vec<u8>>);

// Raw captures retain causal resource scope and Source text for substring delivery.
// Equality and injectivity are enforced only by identity_owner's common store.
type CaseBindings = BTreeMap<String, BTreeMap<String, Vec<IdentityPair>>>;

#[derive(Debug, Clone, Default)]
pub(crate) struct DynamicValues {
    rules: Arc<Vec<DynamicValueRule>>,
    routes: Arc<BTreeMap<String, String>>,
    conditions: Arc<BTreeMap<String, BTreeSet<String>>>,
    native_guards: Arc<BTreeMap<String, super::native_projection::NativeScopeGuard>>,
    native_cases: Arc<BTreeMap<String, BTreeSet<String>>>,
    bindings: Arc<Mutex<CaseBindings>>,
    identity_owner: super::request_contract::RequestContracts,
    candidates: Arc<Mutex<Vec<CaptureCandidate>>>,
    applicable: Arc<Mutex<BTreeSet<String>>>,
}

impl DynamicValues {
    pub(crate) fn enabled(&self) -> bool {
        !self.rules.is_empty()
    }
    pub(crate) fn new(rules: Vec<DynamicValueRule>, routes: BTreeMap<String, String>) -> Self {
        Self {
            rules: Arc::new(rules),
            routes: Arc::new(routes),
            conditions: Arc::default(),
            native_guards: Arc::default(),
            native_cases: Arc::default(),
            bindings: Arc::new(Mutex::new(BTreeMap::new())),
            identity_owner: super::request_contract::RequestContracts::default(),
            candidates: Arc::new(Mutex::new(Vec::new())),
            applicable: Arc::new(Mutex::new(BTreeSet::new())),
        }
    }
    pub(crate) fn set_request(&mut self, case_id: &str, request: &serde_json::Value) {
        self.set_native_request(case_id, request);
        let allowed = super::case_condition::matching_rule_ids(
            request,
            self.rules
                .iter()
                .filter(|rule| {
                    self.routes
                        .get(case_id)
                        .is_some_and(|path| rule.matches_route(path))
                })
                .filter_map(|rule| {
                    rule.when
                        .as_ref()
                        .map(|condition| (rule.id.as_str(), condition))
                }),
        );
        Arc::make_mut(&mut self.conditions).insert(case_id.into(), allowed);
    }
    fn matches_case(&self, rule: &DynamicValueRule, case_id: &str) -> bool {
        (!self.native_guards.contains_key(&rule.id)
            || self
                .native_cases
                .get(case_id)
                .is_some_and(|rules| rules.contains(&rule.id)))
            && self
                .routes
                .get(case_id)
                .is_some_and(|path| rule.matches_route(path))
            && (rule.when.is_none()
                || self
                    .conditions
                    .get(case_id)
                    .is_some_and(|ids| ids.contains(&rule.id)))
    }
    pub(crate) fn begin_case(&self, case_id: &str) {
        self.identity_owner.clear_identities(case_id);
        self.candidates
            .lock()
            .expect("capture candidates")
            .retain(|candidate| candidate.case_id != case_id);
        self.bindings
            .lock()
            .expect("dynamic bindings")
            .remove(case_id);
    }
    pub(crate) fn commit(&self, case_id: &str, decision: DynamicDecision) -> Result<()> {
        self.commit_shared_identities(case_id, &decision)?;
        self.commit_after_identities(case_id, decision);
        Ok(())
    }
    pub(crate) fn commit_after_identities(&self, case_id: &str, decision: DynamicDecision) {
        let mut bindings = self.bindings.lock().expect("dynamic bindings");
        for (rule, pair) in decision.pairs {
            let pairs = bindings
                .entry(case_id.into())
                .or_default()
                .entry(rule)
                .or_default();
            if !pairs.contains(&pair) {
                pairs.push(pair);
            }
        }
    }
    #[cfg(test)]
    fn selected<'a>(&'a self, case_id: &str, target: &TargetKey) -> Vec<&'a DynamicValueRule> {
        self.rules
            .iter()
            .filter(|rule| {
                !self.native_guards.contains_key(&rule.id)
                    && self.matches_case(rule, case_id)
                    && rule.targets.iter().any(|endpoint| endpoint.matches(target))
            })
            .collect()
    }
    #[cfg(test)]
    fn pairs(
        &self,
        case_id: &str,
        target: &TargetKey,
        pending: &DynamicDecision,
    ) -> Vec<IdentityPair> {
        let bindings = self.bindings.lock().expect("dynamic bindings");
        self.selected(case_id, target)
            .iter()
            .filter(|rule| rule.value_type == DynamicValueType::String)
            .flat_map(|rule| {
                bindings
                    .get(case_id)
                    .and_then(|rules| rules.get(&rule.id))
                    .into_iter()
                    .flatten()
                    .cloned()
                    .chain(
                        pending
                            .pairs
                            .iter()
                            .filter(|(id, _)| id == &rule.id)
                            .map(|(_, pair)| pair.clone()),
                    )
            })
            .collect()
    }
    fn check_pair(
        &self,
        case_id: &str,
        rule: &DynamicValueRule,
        pair: &IdentityPair,
        pending: &DynamicDecision,
    ) -> Result<()> {
        rule.validate_value(&pair.source)?;
        rule.validate_value(&pair.target)?;
        let bindings = self.bindings.lock().expect("dynamic bindings");
        let pairs = bindings
            .get(case_id)
            .and_then(|rules| rules.get(&rule.id))
            .into_iter()
            .flatten()
            .chain(
                pending
                    .pairs
                    .iter()
                    .filter(|(id, _)| id == &rule.id)
                    .map(|(_, pair)| pair),
            );
        let pairs = pairs.collect::<Vec<_>>();
        ensure!(
            pairs.len() < 256 || pairs.contains(&pair),
            "dynamic capture exceeds 256 identities per case/rule"
        );
        drop(bindings);
        self.check_shared_pair(case_id, rule, pair, pending)
    }
    #[cfg(test)]
    pub(crate) fn normalize_arguments(
        &self,
        case_id: Option<&str>,
        target: &TargetKey,
        source: &[Vec<u8>],
        actual: &[Vec<u8>],
    ) -> Option<Result<NormalizedArguments>> {
        let pairs = self.pairs(case_id?, target, &DynamicDecision::default());
        if !source
            .iter()
            .any(|value| strings::contains_identity(value, &pairs))
        {
            return None;
        }
        Some((|| {
            ensure!(
                source.len() == actual.len(),
                "dynamic request argument count differs"
            );
            Ok((
                source
                    .iter()
                    .map(|value| strings::normalize(value, &pairs, false))
                    .collect::<Result<_>>()?,
                actual
                    .iter()
                    .map(|value| strings::normalize(value, &pairs, true))
                    .collect::<Result<_>>()?,
            ))
        })())
    }
}

#[cfg(test)]
mod path_tests;
#[cfg(test)]
mod redis_tests;
#[cfg(test)]
mod tests;
