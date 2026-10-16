//! Case-local identity mappings shared by decoded dependency protocol adapters.
mod audit;
mod candidates;
mod config;
mod http;
mod mysql;
#[cfg(test)]
mod mysql_table_tests;
mod path_candidates;
mod path_segment;
mod redis;
mod redis_json;
mod source;
mod strings;
pub(in crate::replay) use audit::{DynamicBindingReport, from_report};
pub(in crate::replay) use candidates::CaptureCandidate;
pub(in crate::replay) use config::validate;
pub use config::{
    DynamicValueCapture, DynamicValueFormat, DynamicValueRule, DynamicValueTarget,
    DynamicValueType, PathSegmentCapture, PathSegmentField, RedisCaptureReference,
    RedisDerivedIdentity,
};
pub(in crate::replay) use http::HttpInput;
pub(in crate::replay) use source::from_event as recorded_capture;
pub(in crate::replay) use strings::capture as capture_string;

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
pub(in crate::replay) struct DynamicDecision {
    pub(super) pairs: Vec<(String, IdentityPair)>,
}

type NormalizedArguments = (Vec<Vec<u8>>, Vec<Vec<u8>>);

type CaseBindings = BTreeMap<String, BTreeMap<String, Vec<IdentityPair>>>;

#[derive(Debug, Clone, Default)]
pub(in crate::replay) struct DynamicValues {
    rules: Arc<Vec<DynamicValueRule>>,
    routes: Arc<BTreeMap<String, String>>,
    conditions: Arc<BTreeMap<String, BTreeSet<String>>>,
    bindings: Arc<Mutex<CaseBindings>>,
    candidates: Arc<Mutex<Vec<CaptureCandidate>>>,
    applicable: Arc<Mutex<BTreeSet<String>>>,
}

impl DynamicValues {
    pub(in crate::replay) fn enabled(&self) -> bool {
        !self.rules.is_empty()
    }
    pub(in crate::replay) fn new(
        rules: Vec<DynamicValueRule>,
        routes: BTreeMap<String, String>,
    ) -> Self {
        Self {
            rules: Arc::new(rules),
            routes: Arc::new(routes),
            conditions: Arc::default(),
            bindings: Arc::new(Mutex::new(BTreeMap::new())),
            candidates: Arc::new(Mutex::new(Vec::new())),
            applicable: Arc::new(Mutex::new(BTreeSet::new())),
        }
    }
    pub(in crate::replay::policy) fn set_request(
        &mut self,
        case_id: &str,
        request: &serde_json::Value,
    ) {
        let allowed = super::case_condition::matching_rule_ids(
            request,
            self.rules
                .iter()
                .filter(|rule| {
                    self.routes
                        .get(case_id)
                        .is_some_and(|path| super::pattern::path_pattern_matches(&rule.api, path))
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
        self.routes
            .get(case_id)
            .is_some_and(|path| super::pattern::path_pattern_matches(&rule.api, path))
            && (rule.when.is_none()
                || self
                    .conditions
                    .get(case_id)
                    .is_some_and(|ids| ids.contains(&rule.id)))
    }
    pub(in crate::replay) fn begin_case(&self, case_id: &str) {
        self.candidates
            .lock()
            .expect("capture candidates")
            .retain(|candidate| candidate.case_id != case_id);
        self.bindings
            .lock()
            .expect("dynamic bindings")
            .remove(case_id);
    }
    pub(in crate::replay) fn commit(&self, case_id: &str, decision: DynamicDecision) {
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
    fn selected<'a>(&'a self, case_id: &str, target: &TargetKey) -> Vec<&'a DynamicValueRule> {
        self.rules
            .iter()
            .filter(|rule| {
                self.matches_case(rule, case_id)
                    && rule.targets.iter().any(|endpoint| endpoint.matches(target))
            })
            .collect()
    }
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
        for previous in pairs {
            ensure!(
                previous.source != pair.source || previous.target == pair.target,
                "dynamic identity changed its target reference"
            );
            ensure!(
                previous.target != pair.target || previous.source == pair.source,
                "distinct dynamic identities collapsed"
            );
        }
        Ok(())
    }
    pub(in crate::replay) fn normalize_arguments(
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
