//! Dependency request contracts: comparison copies, protected witnesses and case-local state.
pub(crate) mod config;
pub(in crate::replay::policy) mod evidence;
mod overlap;
mod redis;
mod script;
pub(in crate::replay::policy) use overlap::validate as validate_overlaps;
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
}
type SequenceKey = (String, String, Vec<u8>);

#[derive(Default)]
struct State {
    cases: BTreeMap<String, CaseAnchor>,
    applicable: BTreeSet<String>,
    usage: BTreeMap<String, usize>,
    time_validations: BTreeMap<String, usize>,
    candidates: Vec<Candidate>,
    sequences: BTreeMap<SequenceKey, Sequence>,
    nonces: BTreeMap<(String, String, String), BTreeMap<String, String>>,
}
#[derive(Debug, Clone, Default)]
struct Sequence {
    next: usize,
    times: Vec<(f64, f64)>,
}
#[derive(Clone, Default)]
pub(in crate::replay) struct RequestContracts {
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
    pub ids: Vec<String>,
    time_validations: usize,
    sequence: Option<(SequenceKey, Sequence)>,
    nonces: Vec<((String, String, String), String, String)>,
}
impl RequestContracts {
    pub(in crate::replay::policy) fn load(
        rules: &[ReplayDependencyRule],
        policy: &Path,
        cases: &BTreeMap<String, ReplayCase>,
    ) -> Result<Self> {
        let root = policy
            .parent()
            .and_then(Path::parent)
            .unwrap_or(Path::new("."))
            .to_path_buf();
        let mut keys = BTreeMap::new();
        for rule in rules {
            if let Some(super::redis_value::RedisSelector::Requests(selector)) = &rule.redis {
                for command in &selector.commands {
                    for field in command.argument_values.values() {
                        if let config::ArgumentRule::Json(json) = field {
                            for (pointer, field) in &json.json {
                                if let config::JsonField::Jwt(field) = field {
                                    keys.insert(
                                        (rule.id.clone(), pointer.clone()),
                                        crate::request_rules::keys::ResolvedSigningKey::resolve(
                                            &root,
                                            &field.jwt.signing_key_source,
                                        )?,
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
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
                },
            );
        }
        Ok(Self {
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
                    && r.target
                        .host
                        .as_ref()
                        .is_some_and(|host| host.eq_ignore_ascii_case(&target.host))
                    && r.target.port == Some(target.port)
                    && r.case_selector.as_ref().is_some_and(|selector| {
                        selector.method == anchor.method
                            && super::pattern::path_pattern_matches(&selector.path, &anchor.path)
                    })
            })
            .collect()
    }
    pub(in crate::replay) fn commit(&self, decision: Decision) {
        let mut state = self.state.lock().expect("request contracts");
        for id in decision.ids {
            *state.time_validations.entry(id.clone()).or_default() += decision.time_validations;
            *state.usage.entry(id).or_default() += 1;
        }
        if let Some((key, sequence)) = decision.sequence {
            state.sequences.insert(key, sequence);
        }
        for (key, source, actual) in decision.nonces {
            state.nonces.entry(key).or_default().insert(source, actual);
        }
    }
    pub(in crate::replay) fn enabled(&self) -> bool {
        !self.rules.is_empty()
    }
    pub(in crate::replay) fn observe_source(&self, case: &str, bytes: &[u8]) -> Result<()> {
        if !self.enabled() {
            return Ok(());
        }
        for line in bytes.split(|b| *b == b'\n').filter(|line| !line.is_empty()) {
            let event: Value = serde_json::from_slice(line)?;
            if event["global_dependency_reason"].is_string() {
                continue;
            }
            let protocol = match event["event_type"].as_str() {
                Some("redis_exchange") => DependencyProtocol::Redis,
                Some("http_exchange") => DependencyProtocol::Http,
                _ => continue,
            };
            let target = if protocol == DependencyProtocol::Redis {
                TargetKey {
                    host: event["target_host"].as_str().unwrap_or_default().into(),
                    port: event["target_port"].as_u64().unwrap_or_default() as u16,
                }
            } else {
                let Ok(authority) = event["authority"]
                    .as_str()
                    .unwrap_or_default()
                    .parse::<hyper::http::uri::Authority>()
                else {
                    continue;
                };
                TargetKey {
                    host: authority.host().into(),
                    port: authority.port_u16().unwrap_or(
                        if event["scheme"]
                            .as_str()
                            .is_some_and(|s| s.contains("https"))
                        {
                            443
                        } else {
                            80
                        },
                    ),
                }
            };
            for rule in self.selected(case, &target, protocol) {
                let matches = if let Some(super::redis_value::RedisSelector::Requests(selector)) =
                    &rule.redis
                {
                    selector.database == event["database"]
                        && selector
                            .commands
                            .iter()
                            .filter(|c| event["command"] == c.command)
                            .any(|command| {
                                event["args"]
                                    .as_array()
                                    .and_then(|args| {
                                        args.iter()
                                            .map(evidence::decode)
                                            .collect::<Result<Vec<_>>>()
                                            .ok()
                                    })
                                    .is_some_and(|args| {
                                        command.validate_arguments(&args).is_ok()
                                            && command
                                                .key(&args)
                                                .is_some_and(|key| selector.key.matches(key))
                                    })
                            })
                } else {
                    rule.http.as_ref().is_some_and(|h| {
                        event["method"] == h.method
                            && super::pattern::path_pattern_matches(
                                &h.path,
                                &super::pattern::uri_path(
                                    event["uri"].as_str().unwrap_or_default(),
                                ),
                            )
                    })
                };
                if matches {
                    self.state
                        .lock()
                        .expect("request contracts")
                        .applicable
                        .insert(rule.id.clone());
                }
            }
        }
        Ok(())
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
                    binds: 0,
                    references: 0,
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
                r.http.as_ref().is_some_and(|h| {
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
    ) || rule.http.as_ref().is_some_and(|h| h.multipart.is_some())
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
        ensure!(
            http.json.is_empty() && http.query.is_empty() && http.headers.is_empty(),
            "multipart contracts cannot carry another HTTP normalization"
        );
    }
    Ok(())
}
