//! Dependency request contracts: comparison copies, protected witnesses and case-local state.
pub(crate) mod config;
pub(in crate::replay::policy) mod evidence;
mod http_body;
mod http_json;
mod http_value;
mod jwt;
pub(in crate::replay::policy) mod key;
mod memcached;
mod mysql;
mod mysql_selection;
pub(in crate::replay::policy) mod native_projection;
mod signing_keys;
mod value_decision;
pub(in crate::replay) use key::KeyBindingReport;
mod overlap;
mod redis;
mod unified_response;
mod url;
pub(in crate::replay) use unified_response::PreparedRedisDelivery;
pub(crate) use unified_response::redis_bulk_payload;
mod script;
mod source_applicability;
mod source_records;
mod source_session;
mod time;
mod unified;
pub(in crate::replay::policy) use overlap::validate as validate_overlaps;
pub(in crate::replay) use unified::RedisRequestContext;
#[cfg(test)]
mod tests;
use super::config::{DependencyProtocol, ReplayDependencyRule};
use crate::replay::{ReplayCase, TargetKey};
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
pub(in crate::replay) use evidence::Candidate;
pub(crate) use evidence::discover;
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
    recorded: Option<DateTime<Utc>>,
    actual: Option<DateTime<Utc>>,
    dir: PathBuf,
    conditions: BTreeSet<String>,
    source_body: Option<Value>,
}
type SequenceKey = (String, String, Vec<u8>);

#[derive(Default)]
struct State {
    key_bindings: BTreeMap<key::BindingScope, BTreeMap<String, String>>,
    key_binding_proofs: BTreeSet<KeyBindingReport>,
    key_binds: BTreeMap<String, usize>,
    identity_references: BTreeMap<String, usize>,
    cases: BTreeMap<String, CaseAnchor>,
    applicable: BTreeSet<String>,
    redis_applicability: source_applicability::RedisApplicability,
    usage: BTreeMap<String, usize>,
    time_validations: BTreeMap<String, usize>,
    unavailable_value_slots: BTreeMap<String, usize>,
    candidates: Vec<Candidate>,
    sequences: BTreeMap<SequenceKey, Sequence>,
    nonces: BTreeMap<(String, String, String), BTreeMap<String, String>>,
}
#[derive(Debug, Clone, Default)]
struct Sequence {
    actual_key: Option<Vec<u8>>,
    next: usize,
    times: Vec<time::ComparedTime>,
}
#[derive(Clone, Default)]
pub(in crate::replay) struct RequestContracts {
    compiled: Option<Arc<crate::policy::CompiledPolicy>>,
    mysql_selection: Arc<mysql_selection::MysqlSelection>,
    witnesses: Option<crate::policy_evidence::WitnessStore>,
    rules: Arc<Vec<ReplayDependencyRule>>,
    keys: Arc<BTreeMap<(String, String), crate::request_rules::keys::ResolvedSigningKey>>,
    state: Arc<Mutex<State>>,
}
impl std::fmt::Debug for RequestContracts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestContracts")
            .field("rules", &self.rules.len())
            .finish_non_exhaustive()
    }
}
#[derive(Debug, Clone, Default)]
pub(in crate::replay) struct Decision {
    key_bindings: Vec<key::PendingBinding>,
    identity_references: usize,
    pub ids: Vec<String>,
    time_validations: usize,
    sequence: Option<(SequenceKey, Sequence)>,
    nonces: Vec<((String, String, String), String, String)>,
    unified_time_validations: BTreeMap<String, usize>,
}
impl RequestContracts {
    #[cfg(test)]
    pub(in crate::replay) fn restore_request_clock_for_test(
        &self,
        case: &str,
        actual: DateTime<Utc>,
    ) {
        self.state
            .lock()
            .unwrap()
            .cases
            .get_mut(case)
            .unwrap()
            .actual = Some(actual);
    }
    pub(in crate::replay::policy) fn load(
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
            let request: Value =
                serde_json::from_slice(&std::fs::read(case.dir.join("request.json"))?)?;
            state.cases.insert(
                id.clone(),
                CaseAnchor {
                    method: request["method"].as_str().unwrap_or_default().into(),
                    path: super::pattern::uri_path(request["uri"].as_str().unwrap_or_default()),
                    recorded: request["timestamp"].as_str().and_then(|v| v.parse().ok()),
                    actual: None,
                    dir: case.dir.clone(),
                    conditions: super::case_condition::matching_rule_ids(
                        &request,
                        rules.iter().filter_map(|rule| {
                            rule.when
                                .as_ref()
                                .map(|condition| (rule.id.as_str(), condition))
                        }),
                    ),
                    source_body: unified::source_body(&request),
                },
            );
        }
        Ok(Self {
            compiled: None,
            mysql_selection: Arc::default(),
            witnesses: None,
            rules: Arc::new(
                rules
                    .iter()
                    .filter(|r| is_request_rule(r))
                    .cloned()
                    .collect(),
            ),
            keys: Arc::new(keys),
            state: Arc::new(Mutex::new(state)),
        })
    }
    pub(in crate::replay::policy) fn signing_keys(
        &self,
    ) -> Vec<crate::request_rules::keys::ResolvedSigningKey> {
        self.keys.values().cloned().collect()
    }
    pub(in crate::replay) fn begin_case(&self, id: &str) {
        let mut state = self.state.lock().expect("request contracts");
        if let Some(case) = state.cases.get_mut(id) {
            case.actual = None;
        }
        state.sequences.retain(|(case, _, _), _| case != id);
        state.nonces.retain(|(case, _, _), _| case != id);
        state.key_bindings.retain(|scope, _| !scope.belongs_to(id));
        state.key_binding_proofs.retain(|proof| proof.case_id != id);
        state.candidates.retain(|c| c.case_id != id);
    }
    pub(in crate::replay) fn request_begin(&self, id: &str) -> Result<()> {
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
    pub(in crate::replay) fn request_times(
        &self,
        case: &str,
    ) -> crate::replay::assertion::RequestTimes {
        self.anchor(case)
            .map(|anchor| crate::replay::assertion::RequestTimes {
                source: anchor.recorded,
                target: anchor.actual,
            })
            .unwrap_or_default()
    }
    #[cfg(test)]
    pub(in crate::replay) fn set_request_times(
        &self,
        case: &str,
        times: crate::replay::assertion::RequestTimes,
    ) {
        let mut state = self.state.lock().expect("request contracts");
        let anchor = state.cases.get_mut(case).expect("test case metadata");
        anchor.recorded = times.source;
        anchor.actual = times.target;
    }
    fn selected(
        &self,
        case: &str,
        target: &TargetKey,
        protocol: DependencyProtocol,
    ) -> Vec<&ReplayDependencyRule> {
        let Ok(anchor) = self.anchor(case) else {
            return vec![];
        };
        self.rules
            .iter()
            .filter(|r| {
                r.protocol == protocol
                    && (r.when.is_none() || anchor.conditions.contains(&r.id))
                    && r.target
                        .host
                        .as_ref()
                        .is_some_and(|host| host.eq_ignore_ascii_case(&target.host))
                    && r.target.port == Some(target.port)
                    && r.case_selector.as_ref().is_none_or(|selector| {
                        selector.method == anchor.method
                            && super::pattern::path_pattern_matches(&selector.path, &anchor.path)
                    })
            })
            .collect()
    }
    pub(in crate::replay) fn commit(&self, decision: Decision) {
        let mut state = self.state.lock().expect("request contracts");
        for id in decision.ids {
            *state.key_binds.entry(id.clone()).or_default() += decision.key_bindings.len();
            *state.identity_references.entry(id.clone()).or_default() +=
                decision.identity_references;
            *state.time_validations.entry(id.clone()).or_default() += decision
                .unified_time_validations
                .get(&id)
                .copied()
                .unwrap_or(decision.time_validations);
            *state.usage.entry(id).or_default() += 1;
        }
        if let Some((key, sequence)) = decision.sequence {
            state.sequences.insert(key, sequence);
        }
        for (key, source, actual) in decision.nonces {
            state.nonces.entry(key).or_default().insert(source, actual);
        }
        for (scope, source, actual) in decision.key_bindings {
            state
                .key_bindings
                .entry(scope)
                .or_default()
                .insert(source, actual);
        }
    }
    pub(in crate::replay) fn enabled(&self) -> bool {
        !self.rules.is_empty()
            || self.witnesses.is_some()
            || self.compiled.as_ref().is_some_and(|policy| {
                policy
                    .rules
                    .iter()
                    .any(|rule| rule.rule.surface != crate::policy::Surface::ApiResponse)
            })
    }
    pub(in crate::replay) fn candidates(&self) -> Vec<Candidate> {
        self.state
            .lock()
            .expect("request contracts")
            .candidates
            .clone()
    }
    pub(in crate::replay) fn reports(&self) -> Vec<super::report::DependencyRuleReport> {
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
            .chain(self.unified_reports(&state))
            .collect()
    }
    #[allow(clippy::too_many_arguments)]
    pub(in crate::replay) fn preview_multipart(
        &self,
        case: &str,
        target: &TargetKey,
        method: &str,
        path: &str,
        source: &[u8],
        source_headers: &BTreeMap<String, Vec<String>>,
        actual: &[u8],
        headers: &BTreeMap<String, Vec<String>>,
    ) -> Option<Result<Decision>> {
        let rules: Vec<_> = self
            .selected(case, target, DependencyProtocol::Http)
            .into_iter()
            .filter(|r| {
                self.native_rule_scope_matches(
                    &r.id,
                    Some(case),
                    crate::policy::Protocol::Http,
                    target,
                    None,
                    None,
                ) && r.http.as_ref().is_some_and(|h| {
                    h.multipart.is_some()
                        && h.method == method
                        && super::pattern::path_pattern_matches(&h.path, path)
                })
            })
            .collect();
        if rules.is_empty() {
            return None;
        }
        Some((|| {
            let mut source_identity = source_headers.clone();
            let mut actual_identity = headers.clone();
            source_identity.retain(|name, _| !name.eq_ignore_ascii_case("content-type"));
            actual_identity.retain(|name, _| !name.eq_ignore_ascii_case("content-type"));
            ensure!(
                crate::replay::http::request_headers::exact_contract_match(
                    &source_identity,
                    &actual_identity
                ),
                "multipart identity headers differ"
            );
            crate::replay::http::multipart::compare(source, source_headers, actual, headers)?;
            Ok(Decision {
                ids: rules.iter().map(|r| r.id.clone()).collect(),
                ..Default::default()
            })
        })())
    }
}
pub(in crate::replay::policy) fn is_request_rule(rule: &ReplayDependencyRule) -> bool {
    matches!(
        rule.redis,
        Some(super::redis_value::RedisSelector::Requests(_))
    ) || rule.http.as_ref().is_some_and(|h| {
        h.multipart.is_some() || !h.json.time.is_empty() || !h.json.fields.is_empty()
    })
}
pub(in crate::replay::policy) fn validate(rule: &ReplayDependencyRule) -> Result<()> {
    if !is_request_rule(rule) {
        return Ok(());
    }
    ensure!(
        rule.replay_scope == super::config::ReplayScope::Case && rule.case_selector.is_some(),
        "request contracts require an explicit inbound case method/path and case scope"
    );
    ensure!(
        rule.target
            .host
            .as_ref()
            .is_some_and(|host| !host.is_empty() && !host.contains(['*', '/', ' ']))
            && rule.target.port.is_some_and(|port| port > 0),
        "request contracts require an exact endpoint"
    );
    crate::config::process_owned_dependencies::validate_source_evidence(&rule.source_evidence)?;
    if let Some(super::redis_value::RedisSelector::Requests(redis)) = &rule.redis {
        redis.validate()?;
    }
    if let Some(http) = &rule.http {
        if http.multipart.is_some() {
            ensure!(
                http.json.is_empty() && http.query.is_empty() && http.headers.is_empty(),
                "multipart contracts cannot carry another HTTP normalization"
            );
        } else if !http.json.fields.is_empty() {
            ensure!(
                http.json.time.is_empty() && http.json.unordered.is_empty(),
                "HTTP generated body fields use separate nonoverlapping value rules for times and ordering"
            );
        } else {
            http_json::validate(http)?;
        }
    }
    Ok(())
}
