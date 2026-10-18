use std::collections::{BTreeMap, BTreeSet};
mod http_native;
mod memcached;
pub(in crate::replay::policy) mod mysql_contract;
pub(in crate::replay::policy) mod mysql_native;
pub(in crate::replay::policy) mod mysql_response;
pub(in crate::replay::policy) mod mysql_selectors;
pub(super) mod mysql_values;
mod source_session;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::Value;

use super::config::{
    DependencyProtocol, DynamicValueRule, LoadedReplayPolicy, ReplayDependencyRule,
    load_replay_policy,
};
use super::pattern::{path_pattern_matches, query_values, text_pattern_matches, uri_path};
use super::report::{DependencyRuleReport, RecordedDependencyRuleSource, ReplayPolicyReport};
use super::value::{validate_relative_time, validate_value};
use crate::replay::{
    RecordedMysqlValue, ReplayCase, ReplaySessionIdentity, TargetKey, normalize_host, normalize_sql,
};

#[derive(Debug, Clone, Default)]
struct CaseIdentity {
    method: Option<String>,
    path: Option<String>,
    conditions: BTreeSet<String>,
}

#[derive(Debug, Clone, Default)]
struct DependencyRuleUsage {
    matches: usize,
    binds: usize,
    references: usize,
    validations: usize,
    time_validations: usize,
}

#[derive(Debug, Clone, Default)]
pub(in crate::replay) struct DependencyRuleDecision {
    usage: BTreeMap<String, DependencyRuleUsage>,
    bindings: Vec<(String, Value)>,
    pub(in crate::replay) dynamic_query_params: Vec<String>,
    pub(in crate::replay) value_contracts: Vec<super::request_contract::Decision>,
}

impl DependencyRuleDecision {
    pub(in crate::replay::policy) fn merge_value_comparison(
        &mut self,
        comparison: crate::value_contract::json::Comparison,
        native: &[&crate::policy::CompiledNativeRule],
    ) {
        let other = mysql_native::decision(comparison, native);
        for (id, usage) in other.usage {
            self.usage.entry(id).or_default().time_validations += usage.time_validations;
        }
        self.value_contracts.extend(other.value_contracts);
    }
}

#[derive(Debug)]
pub(in crate::replay) struct ReplayPolicyRuntime {
    pub(in crate::replay) request_contracts: super::request_contract::RequestContracts,
    pub(in crate::replay) dynamic_values: super::dynamic_values::DynamicValues,
    loaded: LoadedReplayPolicy,
    mysql_selectors: mysql_selectors::MysqlSelectors,
    cases: BTreeMap<String, CaseIdentity>,
    applicable_dependency_rule_ids: BTreeSet<String>,
    recorded_mysql_rule_applicability: BTreeMap<String, BTreeSet<RecordedDependencyRuleSource>>,
    usage: BTreeMap<String, DependencyRuleUsage>,
    bindings: BTreeMap<String, BTreeMap<String, Value>>,
}

#[derive(Debug)]
pub(in crate::replay) struct HttpPolicyContext<'a> {
    pub(in crate::replay) request_times: crate::replay::assertion::RequestTimes,
    pub(in crate::replay) case_id: Option<&'a str>,
    pub(in crate::replay) target: &'a TargetKey,
    pub(in crate::replay) method: &'a str,
    pub(in crate::replay) recorded_uri: &'a str,
    pub(in crate::replay) actual_uri: &'a str,
}

#[derive(Debug)]
pub(in crate::replay) struct MysqlPolicyContext<'a> {
    pub(in crate::replay) request_times: crate::replay::assertion::RequestTimes,
    pub(in crate::replay) case_id: Option<&'a str>,
    pub(in crate::replay) identity: &'a ReplaySessionIdentity,
    pub(in crate::replay) command: &'a str,
    pub(in crate::replay) recorded_sql: Option<&'a str>,
    pub(in crate::replay) sql: Option<&'a str>,
    pub(in crate::replay) recorded: Option<&'a [RecordedMysqlValue]>,
    pub(in crate::replay) actual: Option<&'a [RecordedMysqlValue]>,
}

#[derive(Debug)]
pub(in crate::replay) struct MemcachedPolicyContext<'a> {
    pub(in crate::replay) case_id: Option<&'a str>,
    pub(in crate::replay) target: &'a TargetKey,
    pub(in crate::replay) command: &'a str,
    pub(in crate::replay) key: Option<&'a [u8]>,
    pub(in crate::replay) recorded_value: Option<&'a [u8]>,
    pub(in crate::replay) actual_value: Option<&'a [u8]>,
    pub(in crate::replay) recorded_observed_at: DateTime<Utc>,
    pub(in crate::replay) recorded_duration_ms: u64,
    pub(in crate::replay) actual_observed_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
// Replay policy retains route identity and projects explicit Source body conditions.
// All other canonical and future request.json fields are intentionally ignored.
struct RecordedCaseRequest {
    method: String,
    uri: String,
}

#[derive(Debug, Deserialize)]
struct RecordedCaseDescriptor {
    kind: RecordedCaseKind,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RecordedCaseKind {
    Http,
    MotanRpc,
}

impl ReplayPolicyRuntime {
    #[cfg(test)]
    pub(in crate::replay) fn load(
        path: &Path,
        cases: &BTreeMap<String, ReplayCase>,
    ) -> Result<Self> {
        Self::load_with_sources(path, cases, true)
    }

    pub(in crate::replay) fn load_with_sources(
        path: &Path,
        cases: &BTreeMap<String, ReplayCase>,
        observe_sources: bool,
    ) -> Result<Self> {
        let loaded = load_replay_policy(path)?;
        let mut case_identities = BTreeMap::new();
        for case in cases.values() {
            let request_path = case.dir.join("request.json");
            let expected_response_path = case.dir.join("expected-response.json");
            let alternate_expected_response_path = case.dir.join("expected_response.json");
            ensure!(
                expected_response_path.is_file() || alternate_expected_response_path.is_file(),
                "replay policy requires expected-response.json for assertion-only use under {}",
                case.dir.display()
            );
            case_identities.insert(
                case.id.clone(),
                load_case_identity(&case.dir, &request_path)?,
            );
        }
        let mut dynamic_values = super::dynamic_values::DynamicValues::new(
            loaded.document.dynamic_values.clone(),
            case_identities
                .iter()
                .filter_map(|(id, case)| case.path.as_ref().map(|path| (id.clone(), path.clone())))
                .collect(),
        );
        if let Some(compiled) = &loaded.compiled {
            dynamic_values.configure_native(&compiled.native);
        }
        if loaded
            .compiled
            .as_ref()
            .is_some_and(|policy| !policy.native.is_empty())
            || loaded
                .document
                .dynamic_values
                .iter()
                .any(|rule| rule.when.is_some())
            || loaded
                .document
                .dependency_rules
                .iter()
                .any(|rule| rule.when.is_some())
        {
            for case in cases
                .values()
                .filter(|case| case.dir.join("request.json").is_file())
            {
                let request: Value =
                    serde_json::from_slice(&fs::read(case.dir.join("request.json"))?)?;
                dynamic_values.set_request(&case.id, &request);
                if let Some(identity) = case_identities.get_mut(&case.id) {
                    identity.conditions = super::case_condition::matching_rule_ids(
                        &request,
                        loaded.document.dependency_rules.iter().filter_map(|rule| {
                            rule.when
                                .as_ref()
                                .map(|condition| (rule.id.as_str(), condition))
                        }),
                    );
                }
            }
        }
        let usage = loaded
            .document
            .dependency_rules
            .iter()
            .map(|rule| (rule.id.clone(), DependencyRuleUsage::default()))
            .collect();
        let mut runtime = Self {
            mysql_selectors: mysql_selectors::MysqlSelectors::new(
                &loaded.document.dependency_rules,
            )?,
            request_contracts: super::request_contract::RequestContracts::load(
                &loaded.document.dependency_rules,
                path,
                cases,
            )?,
            dynamic_values,
            loaded,
            cases: case_identities,
            applicable_dependency_rule_ids: BTreeSet::new(),
            recorded_mysql_rule_applicability: BTreeMap::new(),
            usage,
            bindings: BTreeMap::new(),
        };
        runtime
            .request_contracts
            .configure_compiled(runtime.loaded.compiled.clone())?;
        if observe_sources
            && (runtime.dynamic_values.enabled() || runtime.request_contracts.enabled())
        {
            for case in cases.values() {
                let bytes = fs::read(case.dir.join("dependencies.jsonl"))?;
                runtime.dynamic_values.observe_source(&case.id, &bytes)?;
                runtime.request_contracts.observe_source(&case.id, &bytes)?;
            }
        }
        Ok(runtime)
    }

    pub(in crate::replay) fn observe_recorded_mysql_exchange(
        &mut self,
        case_id: Option<&str>,
        identity: &ReplaySessionIdentity,
        command: &str,
        sql: Option<&str>,
        exchange_index: Option<usize>,
    ) {
        let Some(case_id) = case_id else {
            return;
        };
        let Some(case) = self.cases.get(case_id) else {
            return;
        };
        for rule in self.loaded.document.dependency_rules.iter().filter(|rule| {
            rule.protocol == DependencyProtocol::Mysql
                && rule_matches_case(rule, case)
                && self.mysql_selectors.matches(rule, identity, command, sql)
        }) {
            self.applicable_dependency_rule_ids.insert(rule.id.clone());
            if let Some(index) = exchange_index {
                self.recorded_mysql_rule_applicability
                    .entry(rule.id.clone())
                    .or_default()
                    .insert(RecordedDependencyRuleSource {
                        case_id: case_id.into(),
                        index,
                    });
            }
        }
    }

    pub(in crate::replay) fn observe_recorded_http_exchange(
        &mut self,
        case_id: Option<&str>,
        target: &TargetKey,
        method: &str,
        uri: &str,
    ) {
        let Some(case) = case_id.and_then(|case_id| self.cases.get(case_id)) else {
            return;
        };
        self.applicable_dependency_rule_ids.extend(
            self.loaded
                .document
                .dependency_rules
                .iter()
                .filter(|rule| {
                    rule.protocol == DependencyProtocol::Http
                        && rule.replay_scope != super::config::ReplayScope::RecordingRun
                        && rule.http.as_ref().is_some_and(|h| h.json.is_empty())
                        && rule_matches_case(rule, case)
                        && rule_matches_http(rule, target, method, uri)
                })
                .map(|rule| rule.id.clone()),
        );
    }

    pub(in crate::replay) fn observe_recorded_memcached_exchange(
        &mut self,
        case_id: Option<&str>,
        target: &TargetKey,
        command: &str,
        key: Option<&[u8]>,
    ) {
        let Some(case) = case_id.and_then(|case_id| self.cases.get(case_id)) else {
            return;
        };
        self.applicable_dependency_rule_ids.extend(
            self.loaded
                .document
                .dependency_rules
                .iter()
                .filter(|rule| {
                    rule.protocol == DependencyProtocol::Memcached
                        && rule_matches_case(rule, case)
                        && rule_matches_memcached(rule, target, command, key)
                })
                .map(|rule| rule.id.clone()),
        );
    }

    pub(in crate::replay) fn reject_http_ignore_overlap(&self, ignored: &[String]) -> Result<()> {
        let overlaps = self
            .loaded
            .document
            .dependency_rules
            .iter()
            .filter_map(|rule| rule.http.as_ref())
            .flat_map(|http| http.query.keys())
            .filter(|name| {
                ignored
                    .iter()
                    .any(|ignored| ignored.eq_ignore_ascii_case(name))
            })
            .cloned()
            .collect::<BTreeSet<_>>();
        ensure!(
            overlaps.is_empty(),
            "HTTP query params cannot be both replay-policy fields and global ignores: {}",
            overlaps.into_iter().collect::<Vec<_>>().join(", ")
        );
        Ok(())
    }

    pub(in crate::replay) fn begin_case(&mut self, case_id: &str) {
        self.dynamic_values.begin_case(case_id);
        self.request_contracts.begin_case(case_id);
        self.bindings.remove(case_id);
    }

    pub(in crate::replay) fn preview_mysql(
        &self,
        context: &MysqlPolicyContext<'_>,
        _now: DateTime<Utc>,
    ) -> Result<DependencyRuleDecision, String> {
        let Some(case_id) = context.case_id else {
            return exact_mysql_params(context.recorded, context.actual);
        };
        let Some(case) = self.cases.get(case_id) else {
            return Err(format!(
                "replay policy has no request metadata for case {case_id}"
            ));
        };
        let matching_rules = self
            .loaded
            .document
            .dependency_rules
            .iter()
            .filter(|rule| {
                rule.protocol == DependencyProtocol::Mysql
                    && rule
                        .mysql
                        .as_ref()
                        .is_some_and(|mysql| mysql.response_time_shift.is_empty())
                    && rule_matches_case(rule, case)
                    && self.mysql_selectors.matches(
                        rule,
                        context.identity,
                        context.command,
                        context.sql,
                    )
                    && self.mysql_selectors.matches_sql(rule, context.recorded_sql)
            })
            .collect::<Vec<_>>();
        if matching_rules.is_empty() {
            return exact_mysql_params(context.recorded, context.actual);
        }
        let (Some(recorded), Some(actual)) = (context.recorded, context.actual) else {
            return Err(
                "replay policy selected MySQL params but recorded or actual params are absent"
                    .to_string(),
            );
        };
        if recorded.len() != actual.len() {
            return Err(format!(
                "MySQL param count differed: recorded {}, actual {}",
                recorded.len(),
                actual.len()
            ));
        }
        let mut fields = BTreeMap::new();
        for rule in &matching_rules {
            let mysql = rule.mysql.as_ref().expect("validated MySQL policy");
            for (index, field) in &mysql.params {
                if fields.insert(*index, (rule.id.as_str(), field)).is_some() {
                    return Err(format!(
                        "multiple replay policy rules select MySQL params[{index}]"
                    ));
                }
            }
        }
        for index in fields.keys() {
            if *index >= actual.len() {
                return Err(format!(
                    "replay policy selects MySQL params[{index}] but param count is {}",
                    actual.len()
                ));
            }
        }
        let mut decision = DependencyRuleDecision::default();
        for (index, (recorded_value, actual_value)) in recorded.iter().zip(actual).enumerate() {
            if let Some((rule_id, field)) = fields.get(&index) {
                if recorded_value.kind != actual_value.kind {
                    return Err(format!(
                        "dynamic MySQL params[{index}] changed kind from {:?} to {:?}",
                        recorded_value.kind, actual_value.kind
                    ));
                }
                if recorded_value.value.is_none()
                    || recorded_value.raw.is_some()
                    || actual_value.raw.is_some()
                {
                    return Err(format!(
                        "replay policy requires scalar MySQL params[{index}] in both recorded and actual calls"
                    ));
                }
                let value = actual_value.value.as_ref().ok_or_else(|| {
                    format!(
                        "replay policy requires scalar MySQL params[{index}], but actual value is raw"
                    )
                })?;
                self.preview_dynamic_value(
                    case_id,
                    rule_id,
                    field,
                    recorded_value
                        .value
                        .as_ref()
                        .expect("validated scalar value"),
                    value,
                    &mut decision,
                    context.request_times,
                )?;
            } else if recorded_value != actual_value {
                return Err(format!(
                    "stable MySQL params[{index}] did not match the recording"
                ));
            }
        }
        Ok(decision)
    }

    pub(in crate::replay) fn allows_mysql_sql_difference(
        &self,
        context: &MysqlPolicyContext<'_>,
    ) -> bool {
        let Some(case_id) = context.case_id else {
            return false;
        };
        let Some(case) = self.cases.get(case_id) else {
            return false;
        };
        self.loaded.document.dependency_rules.iter().any(|rule| {
            rule.protocol == DependencyProtocol::Mysql
                && rule
                    .mysql
                    .as_ref()
                    .is_some_and(|mysql| mysql.response_time_shift.is_empty())
                && rule_matches_case(rule, case)
                && self.mysql_selectors.matches(
                    rule,
                    context.identity,
                    context.command,
                    context.sql,
                )
                && self.mysql_selectors.matches_sql(rule, context.recorded_sql)
        })
    }

    pub(in crate::replay) fn preview_http(
        &self,
        context: &HttpPolicyContext<'_>,
        _now: DateTime<Utc>,
    ) -> Result<DependencyRuleDecision, String> {
        let Some(case_id) = context.case_id else {
            return Ok(DependencyRuleDecision::default());
        };
        let Some(case) = self.cases.get(case_id) else {
            return Err(format!(
                "replay policy has no request metadata for case {case_id}"
            ));
        };
        let matching_rules = self
            .loaded
            .document
            .dependency_rules
            .iter()
            .filter(|rule| {
                rule.protocol == DependencyProtocol::Http
                    && rule.replay_scope != super::config::ReplayScope::RecordingRun
                    && rule.http.as_ref().is_some_and(|h| h.json.is_empty())
                    && rule_matches_case(rule, case)
                    && rule_matches_http(rule, context.target, context.method, context.actual_uri)
            })
            .collect::<Vec<_>>();
        if matching_rules.is_empty() {
            return Ok(DependencyRuleDecision::default());
        }
        let recorded_query = query_values(context.recorded_uri);
        let actual_query = query_values(context.actual_uri);
        let mut fields = BTreeMap::new();
        for rule in &matching_rules {
            let http = rule.http.as_ref().expect("validated HTTP policy");
            for (name, field) in &http.query {
                if fields
                    .insert(name.as_str(), (rule.id.as_str(), field))
                    .is_some()
                {
                    return Err(format!(
                        "multiple replay policy rules select HTTP query parameter {name:?}"
                    ));
                }
            }
        }
        let mut decision = DependencyRuleDecision::default();
        let native_times = self.compare_native_query_times(
            context.request_times,
            &matching_rules,
            &recorded_query,
            &actual_query,
            &mut decision,
        )?;
        for (name, (rule_id, field)) in fields {
            let recorded_values = recorded_query.get(name).cloned().unwrap_or_default();
            let actual_values = actual_query.get(name).cloned().unwrap_or_default();
            if recorded_values.len() != 1 || actual_values.len() != 1 {
                return Err(format!(
                    "dynamic HTTP query parameter {name:?} must occur exactly once (recorded {}, actual {})",
                    recorded_values.len(),
                    actual_values.len()
                ));
            }
            if !native_times.contains(&(rule_id.into(), name.into())) {
                self.preview_dynamic_value(
                    case_id,
                    rule_id,
                    field,
                    &Value::String(recorded_values[0].clone()),
                    &Value::String(actual_values[0].clone()),
                    &mut decision,
                    context.request_times,
                )?;
            }
            decision.dynamic_query_params.push(name.to_string());
        }
        Ok(decision)
    }

    #[allow(clippy::too_many_arguments)]
    fn preview_dynamic_value(
        &self,
        case_id: &str,
        rule_id: &str,
        field: &DynamicValueRule,
        recorded: &Value,
        actual: &Value,
        decision: &mut DependencyRuleDecision,
        request_times: crate::replay::assertion::RequestTimes,
    ) -> Result<(), String> {
        let usage = decision.usage.entry(rule_id.to_string()).or_default();
        if let Some(reference) = &field.reference {
            let Some(bound) = self
                .bindings
                .get(case_id)
                .and_then(|bindings| bindings.get(reference))
            else {
                return Err(format!(
                    "replay policy ref {reference:?} is not bound in this case"
                ));
            };
            if bound != actual {
                return Err(format!(
                    "replay policy ref {reference:?} did not match its bound value"
                ));
            }
            usage.references += 1;
            return Ok(());
        }
        if let Some(validator) = field.validate {
            validate_value(actual, validator)?;
            usage.validations += 1;
        }
        if let Some(time) = &field.time {
            validate_relative_time(recorded, actual, time, request_times)?;
            usage.time_validations += 1;
        }
        if let Some(binding) = &field.bind {
            if let Some(bound) = self
                .bindings
                .get(case_id)
                .and_then(|bindings| bindings.get(binding))
                .or_else(|| {
                    decision
                        .bindings
                        .iter()
                        .find_map(|(name, value)| (name == binding).then_some(value))
                })
                && bound != actual
            {
                return Err(format!(
                    "replay policy bind {binding:?} changed within the same case"
                ));
            }
            decision.bindings.push((binding.clone(), actual.clone()));
            usage.binds += 1;
        }
        Ok(())
    }

    pub(in crate::replay) fn commit(
        &mut self,
        case_id: Option<&str>,
        decision: DependencyRuleDecision,
    ) {
        for value_contract in decision.value_contracts {
            self.request_contracts.commit(value_contract);
        }
        if let Some(case_id) = case_id {
            let bindings = self.bindings.entry(case_id.to_string()).or_default();
            for (name, value) in decision.bindings {
                bindings.entry(name).or_insert(value);
            }
        }
        for (rule_id, decision_usage) in decision.usage {
            self.applicable_dependency_rule_ids.insert(rule_id.clone());
            let usage = self
                .usage
                .get_mut(&rule_id)
                .expect("policy usage initialized for every rule");
            usage.matches += 1;
            usage.binds += decision_usage.binds;
            usage.references += decision_usage.references;
            usage.validations += decision_usage.validations;
            usage.time_validations += decision_usage.time_validations;
        }
    }

    pub(in crate::replay) fn report(&self) -> ReplayPolicyReport {
        let dependency_rules = self
            .loaded
            .document
            .dependency_rules
            .iter()
            .filter(|rule| !super::request_contract::is_request_rule(rule))
            .map(|rule| {
                let usage = self.usage.get(&rule.id).cloned().unwrap_or_default();
                DependencyRuleReport {
                    id: rule.id.clone(),
                    protocol: rule.protocol,
                    kind: None,
                    applicable: self.applicable_dependency_rule_ids.contains(&rule.id),
                    matches: usage.matches,
                    binds: usage.binds,
                    references: usage.references,
                    validations: usage.validations,
                    time_validations: usage.time_validations,
                }
            })
            .chain(self.dynamic_values.rule_reports())
            .chain(self.request_contracts.reports())
            .collect::<Vec<_>>();
        let unused_applicable_dependency_rule_ids = dependency_rules
            .iter()
            .filter(|rule| rule.applicable && rule.matches == 0)
            .map(|rule| rule.id.clone())
            .collect();
        ReplayPolicyReport {
            version: self.loaded.document.version,
            path: self.loaded.path.display().to_string(),
            fingerprint: self.loaded.fingerprint.clone(),
            expected_response: self.loaded.document.expected_response,
            dependency_rules,
            dynamic_bindings: self.dynamic_values.report(),
            key_bindings: self.request_contracts.key_binding_report(),
            dynamic_capture_candidates: self.dynamic_values.capture_candidates(),
            request_contract_candidates: self.request_contracts.candidates(),
            unused_applicable_dependency_rule_ids,
            recorded_mysql_rule_applicability: self.recorded_mysql_rule_applicability.clone(),
            recorded_redis_rule_applicability: self
                .request_contracts
                .recorded_redis_rule_applicability(),
            unavailable_value_slots: self.request_contracts.unavailable_value_slots(),
        }
    }
}

fn exact_mysql_params(
    recorded: Option<&[RecordedMysqlValue]>,
    actual: Option<&[RecordedMysqlValue]>,
) -> Result<DependencyRuleDecision, String> {
    if recorded == actual {
        Ok(DependencyRuleDecision::default())
    } else {
        Err("MySQL params did not match the recording".to_string())
    }
}

fn exact_memcached_value(
    recorded: Option<&[u8]>,
    actual: Option<&[u8]>,
) -> Result<DependencyRuleDecision, String> {
    if recorded == actual {
        Ok(DependencyRuleDecision::default())
    } else {
        Err("Memcached value did not match the recording".to_string())
    }
}

fn rule_matches_case(rule: &ReplayDependencyRule, case: &CaseIdentity) -> bool {
    if rule.when.is_some() && !case.conditions.contains(&rule.id) {
        return false;
    }
    let Some(selector) = rule.case_selector.as_ref() else {
        return true;
    };
    let (Some(method), Some(path)) = (case.method.as_deref(), case.path.as_deref()) else {
        return false;
    };
    selector.method.eq_ignore_ascii_case(method) && path_pattern_matches(&selector.path, path)
}

fn load_case_identity(case_dir: &Path, request_path: &Path) -> Result<CaseIdentity> {
    let descriptor_path = case_dir.join("case.json");
    if descriptor_path.is_file() {
        let descriptor: RecordedCaseDescriptor =
            serde_json::from_slice(&fs::read(&descriptor_path).with_context(|| {
                format!(
                    "failed to read primary case descriptor {}",
                    descriptor_path.display()
                )
            })?)
            .with_context(|| {
                format!(
                    "failed to parse primary case descriptor {}",
                    descriptor_path.display()
                )
            })?;
        if matches!(descriptor.kind, RecordedCaseKind::MotanRpc) {
            return Ok(CaseIdentity::default());
        }
    }

    let request: RecordedCaseRequest =
        serde_json::from_slice(&fs::read(request_path).with_context(|| {
            format!(
                "failed to read request metadata for replay policy {}",
                request_path.display()
            )
        })?)
        .with_context(|| {
            format!(
                "failed to parse request metadata for replay policy {}",
                request_path.display()
            )
        })?;
    let path = uri_path(&request.uri);
    ensure!(
        path.starts_with('/'),
        "recorded request URI must contain an absolute path: {:?}",
        request.uri
    );
    Ok(CaseIdentity {
        method: Some(request.method),
        path: Some(path),
        conditions: BTreeSet::new(),
    })
}

fn rule_matches_http(
    rule: &ReplayDependencyRule,
    target: &TargetKey,
    method: &str,
    uri: &str,
) -> bool {
    rule_matches_target(rule, Some(target))
        && rule.http.as_ref().is_some_and(|http| {
            http.method.eq_ignore_ascii_case(method)
                && path_pattern_matches(&http.path, &uri_path(uri))
        })
}

fn rule_matches_memcached(
    rule: &ReplayDependencyRule,
    target: &TargetKey,
    command: &str,
    key: Option<&[u8]>,
) -> bool {
    rule.memcached.as_ref().is_some_and(|memcached| {
        memcached.resource.port() == target.port
            && memcached.command.eq_ignore_ascii_case(command)
            && key.is_some_and(|key| {
                let prefix = memcached.key.prefix.as_bytes();
                let suffix = memcached.key.suffix.as_bytes();
                key.strip_prefix(prefix)
                    .and_then(|middle| middle.strip_suffix(suffix))
                    .is_some_and(is_u64_ascii)
            })
    })
}

fn is_u64_ascii(value: &[u8]) -> bool {
    !value.is_empty()
        && value.len() <= 20
        && value.iter().all(u8::is_ascii_digit)
        && std::str::from_utf8(value)
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .is_some()
}

fn rule_matches_target(rule: &ReplayDependencyRule, actual: Option<&TargetKey>) -> bool {
    let Some(host) = rule.target.host.as_deref() else {
        return true;
    };
    let Some(actual) = actual else {
        return false;
    };
    normalize_host(host) == actual.host && rule.target.port.is_none_or(|port| port == actual.port)
}

mod http_headers;
mod http_json;

mod redis_value;
