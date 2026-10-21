//! Retain only identity fingerprints in Replay reports; restore proven bindings for planners.
use super::*;
use crate::replay::{
    RecordedMysqlValue,
    policy::{
        config::fingerprint,
        matcher::mysql_values::{template_pair_values, template_values},
    },
};
use anyhow::Context;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Serialize)]
pub(in crate::replay) struct DynamicBindingReport {
    case_id: String,
    rule_id: String,
    source_fingerprint: String,
    target_fingerprint: String,
}

impl DynamicValues {
    pub(in crate::replay) fn observe_source(&self, case: &str, bytes: &[u8]) -> Result<()> {
        for line in bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            let event: Value = serde_json::from_slice(line)?;
            if event["global_dependency_reason"].is_string() {
                continue;
            }
            for rule in self.rules.iter().filter(|rule| {
                self.matches_case(rule, case) && self.native_source_allowed(rule, &event)
            }) {
                let applicable = match &rule.capture {
                    DynamicValueCapture::Mysql {
                        target,
                        database,
                        value_index,
                        json_pointer,
                        ..
                    } => {
                        let template = rule.capture.mysql_template()?;
                        event["event_type"] == "mysql_exchange"
                            && event["target_host"]
                                .as_str()
                                .is_some_and(|host| host.eq_ignore_ascii_case(&target.host))
                            && event["target_port"] == target.port
                            && event["database"] == *database
                            && serde_json::from_value::<Option<Vec<RecordedMysqlValue>>>(
                                event.get("params").cloned().unwrap_or(Value::Null),
                            )
                            .ok()
                            .is_some_and(|params| {
                                template_values(&template, event["sql"].as_str(), params.as_deref())
                                    .ok()
                                    .is_some_and(|values| {
                                        mysql::capture(
                                            &values[*value_index],
                                            json_pointer.as_deref(),
                                        )
                                        .is_ok()
                                    })
                            })
                    }
                    _ => source::from_event(&rule.capture, rule.value_type, &event)
                        .ok()
                        .flatten()
                        .is_some(),
                };
                if applicable {
                    self.applicable
                        .lock()
                        .expect("dynamic applicability")
                        .insert(rule.id.clone());
                }
            }
        }
        Ok(())
    }
    pub(in crate::replay) fn rule_reports(
        &self,
    ) -> Vec<super::super::report::DependencyRuleReport> {
        let bindings = self.bindings.lock().expect("dynamic bindings");
        let applicable = self.applicable.lock().expect("dynamic applicability");
        self.rules
            .iter()
            .map(|rule| {
                let binds = bindings
                    .values()
                    .filter_map(|rules| rules.get(&rule.id))
                    .map(Vec::len)
                    .sum();
                super::super::report::DependencyRuleReport {
                    id: rule.id.clone(),
                    kind: Some("dynamic_value"),
                    protocol: match rule.capture {
                        DynamicValueCapture::Mysql { .. } => {
                            super::super::config::DependencyProtocol::Mysql
                        }
                        DynamicValueCapture::Redis { .. } => {
                            super::super::config::DependencyProtocol::Redis
                        }
                        DynamicValueCapture::Http { .. } => {
                            super::super::config::DependencyProtocol::Http
                        }
                    },
                    applicable: applicable.contains(&rule.id),
                    matches: binds,
                    binds,
                    references: 0,
                    validations: binds,
                    time_validations: match &rule.capture {
                        DynamicValueCapture::Http {
                            path_segment: Some(segment),
                            ..
                        } => {
                            binds
                                * segment
                                    .fields
                                    .values()
                                    .filter(|field| {
                                        matches!(field, PathSegmentField::Timestamp { .. })
                                    })
                                    .count()
                        }
                        _ => 0,
                    },
                }
            })
            .collect()
    }
    pub(in crate::replay) fn report(&self) -> Vec<DynamicBindingReport> {
        self.bindings
            .lock()
            .expect("dynamic bindings")
            .iter()
            .flat_map(|(case, rules)| {
                rules.iter().flat_map(move |(rule, pairs)| {
                    pairs.iter().map(move |pair| DynamicBindingReport {
                        case_id: case.clone(),
                        rule_id: rule.clone(),
                        source_fingerprint: fingerprint(pair.source.as_bytes()),
                        target_fingerprint: fingerprint(pair.target.as_bytes()),
                    })
                })
            })
            .collect()
    }
}

pub(in crate::replay) fn from_report(
    rules: &[DynamicValueRule],
    report: &Value,
    case_id: &str,
    request: &Value,
    dependencies: &[u8],
    source_values: &[crate::mysql::sql::Token],
    actual_values: &[crate::mysql::sql::Token],
) -> Result<DynamicValues> {
    let path = super::super::pattern::uri_path(request["uri"].as_str().unwrap_or_default());
    let mut runtime = DynamicValues::new(rules.to_vec(), BTreeMap::from([(case_id.into(), path)]));
    runtime.set_request(case_id, request);
    if rules.is_empty() {
        return Ok(runtime);
    }
    restore_bindings(
        &runtime,
        report,
        case_id,
        dependencies,
        (source_values, actual_values),
        None,
        None,
    )?;
    Ok(runtime)
}

/// Native SQL preflight reuses accepted binding fingerprints while preserving
/// method, Source conditions, database and authentication reference scope.
pub(in crate::replay) fn from_native_report(
    compiled: &crate::policy::CompiledPolicy,
    report: &Value,
    context: &super::super::matcher::MysqlPolicyContext<'_>,
    request: &Value,
    dependencies: &[u8],
) -> Result<(DynamicValues, BTreeSet<String>)> {
    let source_values =
        super::super::matcher::mysql_values::materialized(context.recorded_sql, context.recorded)
            .map_err(anyhow::Error::msg)?;
    let actual_values =
        super::super::matcher::mysql_values::materialized(context.sql, context.actual)
            .map_err(anyhow::Error::msg)?;
    let case = context
        .case_id
        .context("SQL identity preflight requires a Case")?;
    let projection = super::super::native_projection::project_native(&compiled.native)?;
    let path = super::super::pattern::uri_path(request["uri"].as_str().unwrap_or_default());
    let mut runtime = DynamicValues::new(
        projection.document.dynamic_values,
        BTreeMap::from([(case.into(), path)]),
    );
    runtime.configure_native(&compiled.native);
    runtime.set_request(case, request);
    let database = context
        .identity
        .database
        .as_ref()
        .map(|name| crate::policy::Database::Name(name.clone()));
    let scope = super::scopes::ResourceContext {
        protocol: crate::policy::Protocol::Mysql,
        target: context
            .identity
            .target
            .as_ref()
            .context("SQL identity endpoint missing")?,
        database: database.as_ref(),
        username: context.identity.username.as_deref(),
        operation: context.command,
    };
    let allowed = runtime
        .selected_scoped(case, scope, false)
        .into_iter()
        .filter(|r| r.value_type == DynamicValueType::String)
        .map(|r| r.id.as_str())
        .collect::<BTreeSet<_>>();
    if allowed.is_empty() {
        return Ok((runtime, BTreeSet::new()));
    }
    restore_bindings(
        &runtime,
        report,
        case,
        dependencies,
        (&source_values, &actual_values),
        Some(&allowed),
        context.request_times.source,
    )?;
    let ids = runtime
        .report()
        .into_iter()
        .map(|row| row.rule_id)
        .collect();
    Ok((runtime, ids))
}

fn restore_bindings(
    runtime: &DynamicValues,
    report: &Value,
    case_id: &str,
    dependencies: &[u8],
    values: (&[crate::mysql::sql::Token], &[crate::mysql::sql::Token]),
    allowed: Option<&BTreeSet<&str>>,
    before: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<()> {
    let (source_values, actual_values) = values;
    let events = dependencies
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(serde_json::from_slice::<Value>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let eligible_events = events
        .iter()
        .filter(|event| {
            before.is_none_or(|before| {
                event["global_dependency_reason"].is_null()
                    && event["timestamp"]
                        .as_str()
                        .and_then(|time| time.parse::<chrono::DateTime<chrono::Utc>>().ok())
                        .is_some_and(|time| time <= before)
            })
        })
        .collect::<Vec<_>>();
    for proof in report["replay_policy"]["dynamic_bindings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|proof| proof["case_id"] == case_id)
        .filter(|proof| {
            allowed.is_none_or(|ids| proof["rule_id"].as_str().is_some_and(|id| ids.contains(id)))
        })
    {
        let rule = runtime
            .rules
            .iter()
            .find(|rule| proof["rule_id"] == rule.id)
            .ok_or_else(|| anyhow::anyhow!("Replay references an unknown dynamic rule"))?;
        ensure!(
            runtime.matches_case(rule, case_id),
            "dynamic proof is outside the API scope"
        );
        // A resource reference is permission to normalize this identity where
        // it occurs, not a prerequisite for unrelated earlier statements.
        // Later immutable captures may establish relevance only; restoration
        // still uses the causally eligible inventory below.
        if allowed.is_some()
            && !binding_occurs_in_request(runtime, rule, proof, &events, source_values)?
        {
            continue;
        }
        let DynamicValueCapture::Mysql {
            target,
            database,
            value_index,
            json_pointer,
            ..
        } = &rule.capture
        else {
            restore_request_binding(
                runtime,
                rule,
                proof,
                &eligible_events,
                case_id,
                source_values,
                actual_values,
            )?;
            continue;
        };
        let template = rule.capture.mysql_template()?;
        let mut restored = false;
        for actual in report["matched_queries"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|query| {
                query["case_id"] == case_id
                    && query["target"]["host"]
                        .as_str()
                        .is_some_and(|host| host.eq_ignore_ascii_case(&target.host))
                    && query["target"]["port"] == target.port
                    && query["database"] == *database
            })
        {
            let actual_params: Option<Vec<RecordedMysqlValue>> =
                serde_json::from_value(actual.get("params").cloned().unwrap_or(Value::Null))?;
            for source in eligible_events.iter().filter(|source| {
                source["event_type"] == "mysql_exchange"
                    && runtime.native_source_allowed(rule, source)
                    && source["target_host"]
                        .as_str()
                        .is_some_and(|host| host.eq_ignore_ascii_case(&target.host))
                    && source["target_port"] == target.port
                    && source["database"] == *database
                    && source["username"] == actual["username"]
            }) {
                let params: Option<Vec<RecordedMysqlValue>> =
                    serde_json::from_value(source.get("params").cloned().unwrap_or(Value::Null))?;
                let Ok((source_values, actual_values)) = template_pair_values(
                    &template,
                    source["sql"].as_str(),
                    params.as_deref(),
                    actual["sql"].as_str(),
                    actual_params.as_deref(),
                ) else {
                    continue;
                };
                let target_value =
                    mysql::capture(&actual_values[*value_index], json_pointer.as_deref())?;
                if fingerprint(target_value.as_bytes()) != proof["target_fingerprint"] {
                    continue;
                }
                let source_value =
                    mysql::capture(&source_values[*value_index], json_pointer.as_deref())?;
                if fingerprint(source_value.as_bytes()) != proof["source_fingerprint"] {
                    continue;
                }
                let pair = IdentityPair {
                    source: source_value,
                    target: target_value.clone(),
                };
                runtime.check_pair(case_id, rule, &pair, &DynamicDecision::default())?;
                runtime.commit(
                    case_id,
                    DynamicDecision {
                        pairs: vec![(rule.id.clone(), pair)],
                    },
                );
                restored = true;
                break;
            }
        }
        ensure!(
            restored,
            "dynamic binding cannot be restored from the same-case matched capture"
        );
    }
    Ok(())
}

fn binding_occurs_in_request(
    runtime: &DynamicValues,
    rule: &DynamicValueRule,
    proof: &Value,
    events: &[Value],
    values: &[crate::mysql::sql::Token],
) -> Result<bool> {
    let strings = strings(values);
    let mut witnessed = false;
    for event in events.iter().filter(|event| {
        event["global_dependency_reason"].is_null() && runtime.native_source_allowed(rule, event)
    }) {
        let value = if let DynamicValueCapture::Mysql {
            target,
            database,
            value_index,
            json_pointer,
            ..
        } = &rule.capture
        {
            if event["event_type"] != "mysql_exchange"
                || event["target_host"]
                    .as_str()
                    .is_none_or(|host| !host.eq_ignore_ascii_case(&target.host))
                || event["target_port"] != target.port
                || event["database"] != *database
            {
                continue;
            }
            let params: Option<Vec<RecordedMysqlValue>> =
                serde_json::from_value(event.get("params").cloned().unwrap_or(Value::Null))?;
            let Ok(values) = template_values(
                &rule.capture.mysql_template()?,
                event["sql"].as_str(),
                params.as_deref(),
            ) else {
                continue;
            };
            mysql::capture(
                values
                    .get(*value_index)
                    .context("SQL source capture slot is absent")?,
                json_pointer.as_deref(),
            )?
        } else {
            let Some(capture) = source::from_event(&rule.capture, rule.value_type, event)? else {
                continue;
            };
            capture.value
        };
        if fingerprint(value.as_bytes()) == proof["source_fingerprint"] {
            witnessed = true;
            if strings.iter().any(|text| text.contains(&value)) {
                return Ok(true);
            }
        }
    }
    ensure!(
        witnessed,
        "dynamic request proof has no matching source capture"
    );
    Ok(false)
}

fn strings(values: &[crate::mysql::sql::Token]) -> Vec<String> {
    let mut out = Vec::new();
    fn visit(value: &Value, out: &mut Vec<String>, depth: usize) {
        if depth > 64 {
            return;
        }
        match value {
            Value::String(text) => out.push(text.clone()),
            Value::Object(fields) => {
                for (key, value) in fields {
                    out.push(key.clone());
                    visit(value, out, depth + 1);
                }
            }
            Value::Array(items) => {
                for value in items {
                    visit(value, out, depth + 1);
                }
            }
            _ => (),
        }
    }
    for value in values {
        if let crate::mysql::sql::Token::Bytes(bytes) = value
            && bytes.len() <= crate::mysql::sql::bounds::MAX_STATEMENT_BYTES
            && let Ok(text) = std::str::from_utf8(bytes)
        {
            out.push(text.into());
            if let Some(value) = crate::json_value::parse_with_limit(
                bytes,
                crate::mysql::sql::bounds::MAX_STATEMENT_BYTES,
            ) {
                visit(&value, &mut out, 0);
            }
        }
    }
    out
}

fn restore_request_binding(
    runtime: &DynamicValues,
    rule: &DynamicValueRule,
    proof: &Value,
    events: &[&Value],
    case: &str,
    source_values: &[crate::mysql::sql::Token],
    actual_values: &[crate::mysql::sql::Token],
) -> Result<()> {
    let mut captured = None;
    for event in events {
        if runtime.native_source_allowed(rule, event)
            && let Some(source) = source::from_event(&rule.capture, rule.value_type, event)?
            && fingerprint(source.value.as_bytes()) == proof["source_fingerprint"]
        {
            captured = Some(source.value);
            break;
        }
    }
    let source = captured
        .ok_or_else(|| anyhow::anyhow!("dynamic request proof has no matching source capture"))?;
    let source_strings = strings(source_values);
    if !source_strings.iter().any(|value| value.contains(&source)) {
        return Ok(());
    }
    let target_strings = strings(actual_values);
    let mut candidates = target_strings.clone();
    for left in &source_strings {
        if let Some((prefix, suffix)) = left.split_once(&source)
            && !suffix.contains(&source)
        {
            for right in &target_strings {
                if let Some(value) = right
                    .strip_prefix(prefix)
                    .and_then(|value| value.strip_suffix(suffix))
                    && value.len() <= 1024
                {
                    candidates.push(value.into());
                }
            }
        }
    }
    let target = candidates
        .into_iter()
        .find(|value| fingerprint(value.as_bytes()) == proof["target_fingerprint"])
        .ok_or_else(|| {
            anyhow::anyhow!("dynamic request binding cannot be restored from SQL references")
        })?;
    let pair = IdentityPair { source, target };
    runtime.check_pair(case, rule, &pair, &DynamicDecision::default())?;
    runtime.commit(
        case,
        DynamicDecision {
            pairs: vec![(rule.id.clone(), pair)],
        },
    );
    Ok(())
}
