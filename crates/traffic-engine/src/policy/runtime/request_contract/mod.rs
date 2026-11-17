//! Dependency request contracts: comparison copies, protected witnesses and case-local state.
mod case_plan;
pub(crate) mod config;
mod derived_inputs;
mod service;
pub(crate) use derived_inputs::PreparedDerivedInputs;
pub(crate) mod evidence;
mod global_value;
pub(crate) mod hypotheses;
pub(crate) use hypotheses::{HypothesisAttempt, HypothesisContext};
mod identity;
mod identity_inputs;
pub(crate) mod key;
mod signing_keys;
mod value_decision;
pub(crate) use key::KeyBindingReport;
#[cfg(test)]
mod overlap;
mod script;
mod source_applicability;
mod source_records;
mod source_session;
mod time;
mod time_copies;
mod unified;
use super::config::ReplayDependencyRule;
use crate::replay::{ReplayCase, TargetKey};
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
pub(crate) use evidence::Candidate;
pub(crate) use evidence::discover;
#[cfg(test)]
pub(crate) use overlap::validate as validate_overlaps;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

#[derive(Debug, Clone)]
struct CaseAnchor {
    method: String,
    path: String,
    source_uri: String,
    source_input_error: Option<&'static str>,
    recorded: Option<DateTime<Utc>>,
    actual: Option<DateTime<Utc>>,
    dir: PathBuf,
    dependencies_path: PathBuf,
    #[allow(dead_code)]
    conditions: BTreeSet<String>,
    source_body: Option<Value>,
}
impl CaseAnchor {
    fn from_request(dir: &Path, request: &Value, rules: &[ReplayDependencyRule]) -> Self {
        let source_body = unified::source_body(request);
        let source_input_error = identity_inputs::capture_error(request, source_body.as_ref());
        Self {
            method: request["method"].as_str().unwrap_or_default().into(),
            path: super::pattern::uri_path(request["uri"].as_str().unwrap_or_default()),
            source_uri: request["uri"].as_str().unwrap_or_default().into(),
            source_input_error,
            recorded: request["timestamp"]
                .as_str()
                .and_then(|value| value.parse().ok()),
            actual: None,
            dir: dir.into(),
            dependencies_path: dir.join("dependencies.jsonl"),
            conditions: super::case_condition::matching_rule_ids(
                request,
                rules.iter().filter_map(|rule| {
                    rule.when
                        .as_ref()
                        .map(|condition| (rule.id.as_str(), condition))
                }),
            ),
            source_body,
        }
    }
}

#[derive(Default)]
struct State {
    source_plan_facts: BTreeMap<String, BTreeSet<case_plan::SourceFact>>,
    primary_protocols: BTreeMap<String, Option<crate::protocol_contract::ProtocolKind>>,
    hypothesis_attempts: Vec<HypothesisAttempt>,
    #[allow(dead_code)]
    hypothesis_checkpoints: BTreeSet<String>,
    hypothesis_error: Option<String>,
    pre_matches: Vec<crate::value_contract::pre_match::Candidate>,
    key_binds: BTreeMap<String, usize>,
    identity_references: BTreeMap<String, usize>,
    cases: BTreeMap<String, CaseAnchor>,
    identity_inputs: BTreeMap<String, Arc<identity_inputs::InputIndex>>,
    source_request_digests: BTreeMap<String, String>,
    derived_inputs: BTreeMap<String, derived_inputs::AuthorizedInputs>,
    applicable: BTreeSet<String>,
    usage: BTreeMap<String, usize>,
    time_validations: BTreeMap<String, usize>,
    candidates: Vec<Candidate>,
}
#[derive(Clone, Default)]
pub struct RequestContracts {
    #[allow(dead_code)]
    hypothesis_context: Option<Arc<HypothesisContext>>,
    hypothesis_journal: Option<crate::policy_evidence::hypotheses::Journal>,
    pre_match_enabled: bool,
    compiled: Option<Arc<crate::policy::CompiledPolicy>>,
    input_origin: Option<derived_inputs::InputOrigin>,
    witnesses: Option<crate::policy_evidence::WitnessStore>,
    rules: Arc<Vec<ReplayDependencyRule>>,
    rule_catalogue: Arc<case_plan::RuleCatalogue>,
    #[allow(dead_code)]
    keys: Arc<BTreeMap<(String, String), crate::request_rules::keys::ResolvedSigningKey>>,
    state: Arc<Mutex<State>>,
    pub(crate) values: crate::value_contract::state::ValueState,
}
impl std::fmt::Debug for RequestContracts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestContracts")
            .field("rules", &self.rules.len())
            .finish_non_exhaustive()
    }
}
#[derive(Debug, Clone, Default)]
pub(crate) struct Decision {
    pre_matches: Vec<crate::value_contract::pre_match::Candidate>,
    pub(crate) identity: Option<crate::value_contract::identities::IdentityDecision>,
    identity_references: usize,
    pub ids: Vec<String>,
    time_validations: usize,
    unified_time_validations: BTreeMap<String, usize>,
}
impl RequestContracts {
    #[allow(dead_code)]
    #[cfg(test)]
    pub(crate) fn restore_request_clock_for_test(&self, case: &str, actual: DateTime<Utc>) {
        self.state
            .lock()
            .unwrap()
            .cases
            .get_mut(case)
            .unwrap()
            .actual = Some(actual);
    }
    pub(crate) fn load(
        rules: &[ReplayDependencyRule],
        policy: &Path,
        cases: &BTreeMap<String, ReplayCase>,
    ) -> Result<Self> {
        let keys =
            signing_keys::resolve(rules, || crate::config::resolve_unified_policy_root(policy))?;
        let mut state = State::default();
        for (id, case) in cases {
            if !case.dir.join("request.json").is_file() {
                continue;
            }
            let raw = std::fs::read(case.dir.join("request.json"))?;
            state
                .primary_protocols
                .insert(id.clone(), case_plan::input_protocol(&raw));
            state
                .source_request_digests
                .insert(id.clone(), crate::policy_evidence::digest(&raw));
            let request: Value = serde_json::from_slice(&raw)?;
            state.cases.insert(
                id.clone(),
                CaseAnchor {
                    dependencies_path: case.dependencies_path.clone(),
                    ..CaseAnchor::from_request(&case.dir, &request, rules)
                },
            );
        }
        Ok(Self {
            hypothesis_context: None,
            hypothesis_journal: None,
            pre_match_enabled: false,
            compiled: None,
            rule_catalogue: Arc::default(),
            witnesses: None,
            input_origin: Some(derived_inputs::InputOrigin::Policy(policy.to_owned())),
            rules: Arc::new(
                rules
                    .iter()
                    .filter(|r| is_request_rule(r))
                    .cloned()
                    .collect::<Vec<_>>()
                    .into(),
            ),
            keys: Arc::new(keys),
            state: Arc::new(Mutex::new(state)),
            values: Default::default(),
        })
    }
    #[allow(dead_code)]
    pub(crate) fn signing_keys(&self) -> Vec<crate::request_rules::keys::ResolvedSigningKey> {
        self.keys
            .values()
            .cloned()
            .chain(
                self.global_json()
                    .into_iter()
                    .flat_map(|global| global.signatures.resolved_keys()),
            )
            .collect()
    }
    pub(crate) fn begin_case(&self, id: &str) {
        let mut state = self.state.lock().expect("request contracts");
        if let Some(case) = state.cases.get_mut(id) {
            case.actual = None;
        }
        state.candidates.retain(|c| c.case_id != id);
        state.derived_inputs.remove(id);
        drop(state);
        self.values
            .time_copies
            .lock()
            .expect("time copies")
            .begin_case(id);
        self.clear_identities(id);
    }
    pub(crate) fn request_begin(&self, id: &str) -> Result<()> {
        let mut state = self.state.lock().expect("request contracts");
        if let Some(case) = state.cases.get_mut(id) {
            ensure!(
                case.actual.is_none(),
                "case request time is already anchored"
            );
            case.actual = Some(Utc::now());
        }
        Ok(())
    }
    fn anchor(&self, case: &str) -> Result<CaseAnchor> {
        self.state
            .lock()
            .expect("request contracts")
            .cases
            .get(case)
            .cloned()
            .context("request rule has no case metadata")
    }
    pub(crate) fn request_times(
        &self,
        case: &str,
    ) -> crate::primary_protocol::assertion::RequestTimes {
        self.anchor(case)
            .map(|anchor| crate::primary_protocol::assertion::RequestTimes {
                source: anchor.recorded,
                target: anchor.actual,
            })
            .unwrap_or_default()
    }
    #[allow(dead_code)]
    #[cfg(test)]
    pub(crate) fn set_request_times(
        &self,
        case: &str,
        times: crate::primary_protocol::assertion::RequestTimes,
    ) {
        let mut state = self.state.lock().expect("request contracts");
        let anchor = state.cases.get_mut(case).expect("test case metadata");
        anchor.recorded = times.source;
        anchor.actual = times.target;
    }
    pub(crate) fn commit(&self, decision: Decision) -> Result<()> {
        self.commit_hypothesis_attempts(&decision.pre_matches)?;
        if let Some(identity) = decision.identity {
            self.commit_identity(identity)?;
        }
        let mut state = self.state.lock().expect("request contracts");
        for candidate in decision.pre_matches {
            if !state.pre_matches.contains(&candidate) {
                state.pre_matches.push(candidate);
            }
        }
        for id in decision.ids {
            *state.identity_references.entry(id.clone()).or_default() +=
                decision.identity_references;
            *state.time_validations.entry(id.clone()).or_default() += decision
                .unified_time_validations
                .get(&id)
                .copied()
                .unwrap_or(decision.time_validations);
            *state.usage.entry(id).or_default() += 1;
        }
        Ok(())
    }
    pub(crate) fn enabled(&self) -> bool {
        !self.rules.is_empty()
            || self.pre_match_enabled
            || self.witnesses.is_some()
            || self.compiled.as_ref().is_some_and(|policy| {
                policy.global_json.is_some()
                    || policy.mysql.is_some()
                    || policy.redis.is_some()
                    || policy.http.is_some()
                    || policy
                        .rules
                        .iter()
                        .any(|rule| rule.rule.surface != crate::policy::Surface::ApiResponse)
            })
    }
    pub(crate) fn candidates(&self) -> Vec<Candidate> {
        self.state
            .lock()
            .expect("request contracts")
            .candidates
            .clone()
    }
    pub(crate) fn reports(&self) -> Vec<super::report::DependencyRuleReport> {
        let state = self.state.lock().expect("request contracts");
        self.rules
            .iter()
            .map(|rule| {
                let matches = state.usage.get(&rule.id).copied().unwrap_or_default();
                super::report::DependencyRuleReport {
                    id: rule.id.clone(),
                    protocol: rule.protocol,
                    kind: Some("dependency_request"),
                    applicable: state.applicable.contains(&rule.id),
                    matches,
                    binds: state.key_binds.get(&rule.id).copied().unwrap_or_default(),
                    references: state
                        .identity_references
                        .get(&rule.id)
                        .copied()
                        .unwrap_or_default(),
                    validations: matches,
                    time_validations: state
                        .time_validations
                        .get(&rule.id)
                        .copied()
                        .unwrap_or_default(),
                }
            })
            .collect()
    }
    pub(crate) fn global_format_reports(&self) -> Vec<super::report::GlobalFormatReport> {
        let Some(policy) = &self.compiled else {
            return vec![];
        };
        let state = self.state.lock().expect("request contracts");
        [
            (
                policy
                    .global_json
                    .as_ref()
                    .is_some_and(|json| !json.fields.is_empty()),
                crate::policy::GLOBAL_JSON_ID,
            ),
            (
                state
                    .applicable
                    .contains(crate::value_contract::time::automatic::RULE_ID)
                    || state
                        .usage
                        .contains_key(crate::value_contract::time::automatic::RULE_ID),
                crate::value_contract::time::automatic::RULE_ID,
            ),
            (policy.mysql.is_some(), "global.mysql"),
            (policy.redis.is_some(), crate::policy::GLOBAL_REDIS_ID),
            (policy.http.is_some(), crate::policy::GLOBAL_HTTP_ID),
        ]
        .into_iter()
        .filter(|(exists, _)| *exists)
        .map(|(_, id)| super::report::GlobalFormatReport {
            id: id.into(),
            applicable: state.applicable.contains(id),
            validations: state.usage.get(id).copied().unwrap_or_default(),
            time_validations: state.time_validations.get(id).copied().unwrap_or_default(),
        })
        .collect()
    }
}
pub(crate) fn is_request_rule(rule: &ReplayDependencyRule) -> bool {
    matches!(
        rule.redis,
        Some(super::redis_value::RedisSelector::Requests(_))
    ) || rule.http.as_ref().is_some_and(|h| h.multipart.is_some())
}
#[cfg(test)]
pub(crate) fn validate(rule: &ReplayDependencyRule) -> Result<()> {
    if !is_request_rule(rule) {
        return Ok(());
    }
    ensure!(
        rule.replay_scope == super::config::ReplayScope::Case
            && (rule.case_selector.is_some() || rule.protocol == DependencyProtocol::Redis),
        "request contracts require an explicit inbound case method/path and case scope"
    );
    ensure!(
        rule.protocol == DependencyProtocol::Redis
            && rule.target.host.is_none()
            && rule.target.port.is_none()
            || rule
                .target
                .host
                .as_ref()
                .is_some_and(|host| !host.is_empty() && !host.contains(['*', '/', ' ']))
                && rule.target.port.is_some_and(|port| port > 0),
        "request contracts require an exact endpoint"
    );
    crate::config::process_owned_dependencies::validate_optional_source_evidence(
        &rule.source_evidence,
    )?;
    if let Some(super::redis_value::RedisSelector::Requests(redis)) = &rule.redis {
        redis.validate()?;
    }
    if let Some(http) = &rule.http
        && http.multipart.is_some()
    {
        ensure!(
            http.query.is_empty(),
            "multipart contracts cannot carry another HTTP normalization"
        );
    }
    Ok(())
}

#[cfg(test)]
use super::config::DependencyProtocol;
