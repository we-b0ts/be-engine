//! Retain only identity fingerprints in Replay reports; restore proven bindings for planners.
use super::*;
use crate::replay::{
    RecordedMysqlValue,
    policy::{
        config::fingerprint,
        matcher::mysql_values::{template_pair_values, template_values},
    },
};
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
            for rule in self
                .rules
                .iter()
                .filter(|rule| self.matches_case(rule, case))
            {
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
    let events = dependencies
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(serde_json::from_slice::<Value>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for proof in report["replay_policy"]["dynamic_bindings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|proof| proof["case_id"] == case_id)
    {
        let rule = rules
            .iter()
            .find(|rule| proof["rule_id"] == rule.id)
            .ok_or_else(|| anyhow::anyhow!("Replay references an unknown dynamic rule"))?;
        ensure!(
            runtime.matches_case(rule, case_id),
            "dynamic proof is outside the API scope"
        );
        let DynamicValueCapture::Mysql {
            target,
            database,
            value_index,
            json_pointer,
            ..
        } = &rule.capture
        else {
            restore_request_binding(
                &runtime,
                rule,
                proof,
                &events,
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
            for source in events.iter().filter(|source| {
                source["event_type"] == "mysql_exchange"
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
    Ok(runtime)
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
            && bytes.len() <= 1024 * 1024
            && let Ok(text) = std::str::from_utf8(bytes)
        {
            out.push(text.into());
            if let Some(value) = crate::replay::json_order::parse(bytes) {
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
    events: &[Value],
    case: &str,
    source_values: &[crate::mysql::sql::Token],
    actual_values: &[crate::mysql::sql::Token],
) -> Result<()> {
    let mut captured = None;
    for event in events {
        if let Some(source) = source::from_event(&rule.capture, rule.value_type, event)?
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
