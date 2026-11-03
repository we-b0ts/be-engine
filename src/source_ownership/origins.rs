//! Unique committed tuple origins; no identity is learned from Target output.
use super::{
    Assignment, CaseFacts, Outcome, Prepared, Rule, epoch, event_id, mysql, problem, started,
    transactions,
};
use crate::policy::{AsyncApiRules, AsyncOwnershipRequest};
use anyhow::{Result, ensure};
use chrono::{DateTime, Utc};
use serde_json::Value;
use std::collections::BTreeMap;
use uuid::Uuid;

pub(super) struct Origin {
    pub assignment: Assignment,
    pub epoch: Uuid,
    pub started_at: DateTime<Utc>,
    pub input_started_at: DateTime<Utc>,
    pub bindings: BTreeMap<String, u64>,
    pub certain: bool,
}

pub(super) fn collect(
    prepared: &Prepared<'_>,
    all: &BTreeMap<String, AsyncApiRules>,
    inputs: &[CaseFacts],
    events: &[Value],
    wires: &transactions::Wires,
    outcome: &mut Outcome,
) -> Result<Vec<Origin>> {
    let mut result = Vec::new();
    for rule in prepared.rules {
        for input in inputs {
            let first_api = all
                .iter()
                .find(|(api, scenarios)| {
                    scenarios.iter().any(|scenario| {
                        crate::policy::async_api_matches(
                            api,
                            scenario,
                            &input.method,
                            &input.uri,
                            input.request.as_ref(),
                        )
                    })
                })
                .map(|(api, _)| api.as_str());
            if first_api != Some(rule.api) {
                continue;
            }
            let Some(scenarios) = all.get(rule.api) else {
                continue;
            };
            if scenarios.iter().position(|scenario| {
                crate::policy::async_api_matches(
                    rule.api,
                    scenario,
                    &input.method,
                    &input.uri,
                    input.request.as_ref(),
                ) && crate::policy::async_response_matches(scenario, input.response.as_ref())
            }) != Some(rule.scenario_index)
            {
                continue;
            }
            let origin = &rule.ownership.origin;
            let matcher = crate::config::mysql_tables::TableMatcher::new(
                &origin.tables,
                &origin.table_patterns,
                None,
            )?;
            let mut captured = Vec::new();
            for (index, event) in events.iter().enumerate() {
                if !super::projection::resource_matches(&origin.resource, event)
                    || !mysql::successful(event)
                    || event["response"]["affected_rows"].as_u64() != Some(1)
                    || !super::candidate_scope(event)
                    || !super::projection::native_identity(event)
                    || started(event).is_none_or(|time| time < input.started_at)
                {
                    continue;
                }
                let owner = event["capture"]["admitted_case"]
                    .as_str()
                    .or_else(|| event["capture"]["attribution"]["origin_case_id"].as_str())
                    .and_then(|id| Uuid::parse_str(id).ok());
                if owner != Some(input.case_id) {
                    continue;
                }
                let Some((table, row)) = prepared.sql.row(event) else {
                    continue;
                };
                if !matcher.matches(table)
                    || !origin.row_match.iter().all(|(column, value)| {
                        row.get(column).is_some_and(|token| literal(token, value))
                    })
                {
                    continue;
                }
                let bindings = origin
                    .bindings
                    .iter()
                    .map(|(name, column)| Some((name.clone(), mysql::positive(row.get(column)?)?)))
                    .collect::<Option<BTreeMap<_, _>>>();
                let Some(bindings) = bindings else {
                    continue;
                };
                let committed = wires.committed(events, index, input.case_id, &prepared.sql);
                let (Some(epoch), Some(at), Some(id)) =
                    (epoch(event), started(event), event_id(event))
                else {
                    continue;
                };
                captured.push(Origin {
                    assignment: Assignment {
                        case_id: input.case_id,
                        rule_id: format!("{}:{}", crate::policy::ASYNC_API_ID, rule.api),
                        rule_fingerprint: rule.fingerprint.clone(),
                        scenario_index: rule.scenario_index,
                        origin_exchange_id: id,
                    },
                    epoch,
                    started_at: at,
                    input_started_at: input.started_at,
                    bindings,
                    certain: committed,
                });
            }
            if captured.len() == 1 {
                if !captured[0].certain {
                    problem(
                        outcome,
                        &Value::Null,
                        Some(&captured[0]),
                        "unproven_origin_commit",
                    );
                }
                result.push(captured.pop().expect("one origin"));
            } else if !captured.is_empty() {
                for origin in &mut captured {
                    origin.certain = false;
                    problem(
                        outcome,
                        &Value::Null,
                        Some(origin),
                        "non_unique_origin_capture",
                    );
                }
                result.extend(captured);
            }
            ensure!(
                result.len() <= 100_000,
                "async origin inventory exceeds bounds"
            );
        }
    }
    Ok(result)
}

fn literal(token: &crate::mysql::sql::Token, value: &Value) -> bool {
    match token {
        crate::mysql::sql::Token::Number(number) => {
            crate::mysql::sql::number(&value.to_string()).as_ref() == Some(number)
        }
        crate::mysql::sql::Token::Bytes(bytes) => {
            value.as_str().is_some_and(|text| text.as_bytes() == bytes)
        }
        _ => false,
    }
}

pub(super) fn requests<'a>(
    rules: &'a [Rule<'a>],
    origin: &Origin,
) -> impl Iterator<Item = &'a AsyncOwnershipRequest> {
    let scenario_index = origin.assignment.scenario_index;
    let rule_id = origin.assignment.rule_id.clone();
    rules
        .iter()
        .filter(move |rule| {
            rule.scenario_index == scenario_index
                && format!("{}:{}", crate::policy::ASYNC_API_ID, rule.api) == rule_id
        })
        .flat_map(|rule| rule.ownership.requests.iter())
}

pub(super) fn references(input: &CaseFacts, identity: u64) -> bool {
    fn text(value: &str, identity: u64) -> bool {
        value
            .split(|ch: char| !ch.is_ascii_digit())
            .filter_map(|part| part.parse::<u64>().ok())
            .any(|value| value == identity)
    }
    fn json(value: &Value, identity: u64) -> bool {
        match value {
            Value::Number(value) => value.as_u64() == Some(identity),
            Value::String(value) => text(value, identity),
            Value::Array(values) => values.iter().any(|value| json(value, identity)),
            Value::Object(values) => values.values().any(|value| json(value, identity)),
            _ => false,
        }
    }
    input.request_unavailable
        || text(&input.uri, identity)
        || url::form_urlencoded::parse(input.uri.as_bytes())
            .any(|(key, value)| text(&key, identity) || text(&value, identity))
        || input
            .request
            .as_ref()
            .is_some_and(|value| json(value, identity))
}
