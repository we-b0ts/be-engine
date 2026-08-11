use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::Value;

use super::config::{
    DynamicValueRule, LoadedReplayPolicy, PolicyProtocol, ReplayPolicyRule, load_replay_policy,
};
use super::pattern::{path_pattern_matches, query_values, text_pattern_matches, uri_path};
use super::report::{PolicyRuleReport, ReplayPolicyReport};
use super::value::{validate_time, validate_value};
use crate::replay::{
    RecordedMysqlValue, ReplayCase, ReplaySessionIdentity, TargetKey, normalize_host, normalize_sql,
};

#[derive(Debug, Clone, Default)]
struct CaseIdentity {
    method: Option<String>,
    path: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct PolicyRuleUsage {
    matches: usize,
    binds: usize,
    references: usize,
    validations: usize,
    time_validations: usize,
}

#[derive(Debug, Clone, Default)]
pub(in crate::replay) struct PolicyDecision {
    usage: BTreeMap<String, PolicyRuleUsage>,
    bindings: Vec<(String, Value)>,
    pub(in crate::replay) dynamic_query_params: Vec<String>,
}

#[derive(Debug)]
pub(in crate::replay) struct ReplayPolicyRuntime {
    loaded: LoadedReplayPolicy,
    cases: BTreeMap<String, CaseIdentity>,
    applicable_rule_ids: BTreeSet<String>,
    usage: BTreeMap<String, PolicyRuleUsage>,
    bindings: BTreeMap<String, BTreeMap<String, Value>>,
}

#[derive(Debug)]
pub(in crate::replay) struct HttpPolicyContext<'a> {
    pub(in crate::replay) case_id: Option<&'a str>,
    pub(in crate::replay) target: &'a TargetKey,
    pub(in crate::replay) method: &'a str,
    pub(in crate::replay) recorded_uri: &'a str,
    pub(in crate::replay) actual_uri: &'a str,
}

#[derive(Debug)]
pub(in crate::replay) struct MysqlPolicyContext<'a> {
    pub(in crate::replay) case_id: Option<&'a str>,
    pub(in crate::replay) identity: &'a ReplaySessionIdentity,
    pub(in crate::replay) command: &'a str,
    pub(in crate::replay) recorded_sql: Option<&'a str>,
    pub(in crate::replay) sql: Option<&'a str>,
    pub(in crate::replay) recorded: Option<&'a [RecordedMysqlValue]>,
    pub(in crate::replay) actual: Option<&'a [RecordedMysqlValue]>,
}

#[derive(Debug, Deserialize)]
// Replay policy only needs the route identity from the evolving request artifact.
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
    pub(in crate::replay) fn load(
        path: &Path,
        cases: &BTreeMap<String, ReplayCase>,
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
        let usage = loaded
            .document
            .rules
            .iter()
            .map(|rule| (rule.id.clone(), PolicyRuleUsage::default()))
            .collect();
        Ok(Self {
            loaded,
            cases: case_identities,
            applicable_rule_ids: BTreeSet::new(),
            usage,
            bindings: BTreeMap::new(),
        })
    }

    pub(in crate::replay) fn observe_recorded_mysql_exchange(
        &mut self,
        case_id: Option<&str>,
        identity: &ReplaySessionIdentity,
        command: &str,
        sql: Option<&str>,
    ) {
        let Some(case) = case_id.and_then(|case_id| self.cases.get(case_id)) else {
            return;
        };
        self.applicable_rule_ids.extend(
            self.loaded
                .document
                .rules
                .iter()
                .filter(|rule| {
                    rule.protocol == PolicyProtocol::Mysql
                        && rule_matches_case(rule, case)
                        && rule_matches_mysql(rule, identity, command, sql)
                })
                .map(|rule| rule.id.clone()),
        );
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
        self.applicable_rule_ids.extend(
            self.loaded
                .document
                .rules
                .iter()
                .filter(|rule| {
                    rule.protocol == PolicyProtocol::Http
                        && rule_matches_case(rule, case)
                        && rule_matches_http(rule, target, method, uri)
                })
                .map(|rule| rule.id.clone()),
        );
    }

    pub(in crate::replay) fn reject_http_ignore_overlap(&self, ignored: &[String]) -> Result<()> {
        let overlaps = self
            .loaded
            .document
            .rules
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
        self.bindings.remove(case_id);
    }

    pub(in crate::replay) fn preview_mysql(
        &self,
        context: &MysqlPolicyContext<'_>,
        now: DateTime<Utc>,
    ) -> Result<PolicyDecision, String> {
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
            .rules
            .iter()
            .filter(|rule| {
                rule.protocol == PolicyProtocol::Mysql
                    && rule_matches_case(rule, case)
                    && rule_matches_mysql(rule, context.identity, context.command, context.sql)
                    && rule_matches_mysql_sql_pattern(rule, context.recorded_sql)
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
        let mut decision = PolicyDecision::default();
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
                self.preview_dynamic_value(case_id, rule_id, field, value, now, &mut decision)?;
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
        self.loaded.document.rules.iter().any(|rule| {
            rule.protocol == PolicyProtocol::Mysql
                && rule_matches_case(rule, case)
                && rule_matches_mysql(rule, context.identity, context.command, context.sql)
                && rule_matches_mysql_sql_pattern(rule, context.recorded_sql)
        })
    }

    pub(in crate::replay) fn preview_http(
        &self,
        context: &HttpPolicyContext<'_>,
        now: DateTime<Utc>,
    ) -> Result<PolicyDecision, String> {
        let Some(case_id) = context.case_id else {
            return Ok(PolicyDecision::default());
        };
        let Some(case) = self.cases.get(case_id) else {
            return Err(format!(
                "replay policy has no request metadata for case {case_id}"
            ));
        };
        let matching_rules = self
            .loaded
            .document
            .rules
            .iter()
            .filter(|rule| {
                rule.protocol == PolicyProtocol::Http
                    && rule_matches_case(rule, case)
                    && rule_matches_http(rule, context.target, context.method, context.actual_uri)
            })
            .collect::<Vec<_>>();
        if matching_rules.is_empty() {
            return Ok(PolicyDecision::default());
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
        let mut decision = PolicyDecision::default();
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
            self.preview_dynamic_value(
                case_id,
                rule_id,
                field,
                &Value::String(actual_values[0].clone()),
                now,
                &mut decision,
            )?;
            decision.dynamic_query_params.push(name.to_string());
        }
        Ok(decision)
    }

    fn preview_dynamic_value(
        &self,
        case_id: &str,
        rule_id: &str,
        field: &DynamicValueRule,
        actual: &Value,
        now: DateTime<Utc>,
        decision: &mut PolicyDecision,
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
            validate_time(actual, time, now)?;
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

    pub(in crate::replay) fn commit(&mut self, case_id: Option<&str>, decision: PolicyDecision) {
        let Some(case_id) = case_id else {
            return;
        };
        let bindings = self.bindings.entry(case_id.to_string()).or_default();
        for (name, value) in decision.bindings {
            bindings.entry(name).or_insert(value);
        }
        for (rule_id, decision_usage) in decision.usage {
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
        let rules = self
            .loaded
            .document
            .rules
            .iter()
            .map(|rule| {
                let usage = self.usage.get(&rule.id).cloned().unwrap_or_default();
                PolicyRuleReport {
                    id: rule.id.clone(),
                    protocol: rule.protocol,
                    applicable: self.applicable_rule_ids.contains(&rule.id),
                    matches: usage.matches,
                    binds: usage.binds,
                    references: usage.references,
                    validations: usage.validations,
                    time_validations: usage.time_validations,
                }
            })
            .collect::<Vec<_>>();
        let unused_applicable_rule_ids = rules
            .iter()
            .filter(|rule| rule.applicable && rule.matches == 0)
            .map(|rule| rule.id.clone())
            .collect();
        ReplayPolicyReport {
            version: self.loaded.document.version,
            path: self.loaded.path.display().to_string(),
            fingerprint: self.loaded.fingerprint.clone(),
            expected_response: self.loaded.document.expected_response,
            rules,
            unused_applicable_rule_ids,
        }
    }
}

fn exact_mysql_params(
    recorded: Option<&[RecordedMysqlValue]>,
    actual: Option<&[RecordedMysqlValue]>,
) -> Result<PolicyDecision, String> {
    if recorded == actual {
        Ok(PolicyDecision::default())
    } else {
        Err("MySQL params did not match the recording".to_string())
    }
}

fn rule_matches_case(rule: &ReplayPolicyRule, case: &CaseIdentity) -> bool {
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
    })
}

fn rule_matches_mysql(
    rule: &ReplayPolicyRule,
    identity: &ReplaySessionIdentity,
    command: &str,
    sql: Option<&str>,
) -> bool {
    let Some(mysql) = &rule.mysql else {
        return false;
    };
    if !mysql.command.eq_ignore_ascii_case(command)
        || !rule_matches_target(rule, identity.target.as_ref())
        || mysql
            .database
            .as_deref()
            .is_some_and(|database| identity.database.as_deref() != Some(database))
        || mysql
            .username
            .as_deref()
            .is_some_and(|username| identity.username.as_deref() != Some(username))
    {
        return false;
    }
    let Some(sql) = sql else {
        return false;
    };
    text_pattern_matches(&normalize_sql(&mysql.sql), &normalize_sql(sql))
}

fn rule_matches_mysql_sql_pattern(rule: &ReplayPolicyRule, sql: Option<&str>) -> bool {
    let (Some(mysql), Some(sql)) = (&rule.mysql, sql) else {
        return false;
    };
    text_pattern_matches(&normalize_sql(&mysql.sql), &normalize_sql(sql))
}

fn rule_matches_http(rule: &ReplayPolicyRule, target: &TargetKey, method: &str, uri: &str) -> bool {
    rule_matches_target(rule, Some(target))
        && rule.http.as_ref().is_some_and(|http| {
            http.method.eq_ignore_ascii_case(method)
                && path_pattern_matches(&http.path, &uri_path(uri))
        })
}

fn rule_matches_target(rule: &ReplayPolicyRule, actual: Option<&TargetKey>) -> bool {
    let Some(host) = rule.target.host.as_deref() else {
        return true;
    };
    let Some(actual) = actual else {
        return false;
    };
    normalize_host(host) == actual.host && rule.target.port.is_none_or(|port| port == actual.port)
}
