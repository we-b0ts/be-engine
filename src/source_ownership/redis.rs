//! Strict Redis argument and JSON identity selection.
use super::{
    CaseFacts, Outcome, Rule, admissible, epoch, mysql, origins, problem, projection, started,
};
use crate::policy::{
    AsyncOwnershipArgument as Argument, AsyncOwnershipIdentity, AsyncOwnershipJsonValue,
    AsyncOwnershipRequest,
};
use serde_json::Value;
use std::collections::BTreeMap;

pub(super) fn successful(event: &Value) -> bool {
    projection::complete(event)
        && event["outcome"] == "response"
        && event["session_setup"] != true
        && event["replay_safe"] != false
        && !matches!(
            event["response_kind"].as_str(),
            Some("error" | "blob_error")
        )
        && event["parse_warnings"].as_array().is_none_or(Vec::is_empty)
}

fn identity(expected: &AsyncOwnershipIdentity, bytes: &[u8]) -> Option<u64> {
    let body = bytes
        .strip_prefix(expected.prefix.as_bytes())?
        .strip_suffix(expected.suffix.as_bytes())?;
    let text = std::str::from_utf8(body).ok()?;
    let value = text.parse::<u64>().ok().filter(|value| *value > 0)?;
    (value.to_string() == text).then_some(value)
}

fn insert(bindings: &mut BTreeMap<String, u64>, name: &str, value: u64) -> Option<()> {
    match bindings.insert(name.into(), value) {
        Some(previous) if previous != value => None,
        _ => Some(()),
    }
}

pub(super) fn selector(
    request: &AsyncOwnershipRequest,
    event: &Value,
) -> Option<BTreeMap<String, u64>> {
    let AsyncOwnershipRequest::Redis {
        resource,
        operation,
        arguments,
        ..
    } = request
    else {
        return None;
    };
    if !projection::resource_matches(resource, event)
        || event["command"] != *operation
        || !successful(event)
    {
        return None;
    }
    let actual = event["args"].as_array()?;
    if arguments.len() != actual.len() {
        return None;
    }
    let mut bindings = BTreeMap::new();
    for (expected, actual) in arguments.iter().zip(actual) {
        match expected {
            Argument::Any(any) if any.any => {}
            Argument::Any(_) => return None,
            Argument::Literal(expected) => {
                if mysql::decode(actual)?.as_slice() != expected.as_bytes() {
                    return None;
                }
            }
            Argument::Identity(expected) => insert(
                &mut bindings,
                &expected.identity,
                identity(expected, &mysql::decode(actual)?)?,
            )?,
            Argument::Json(expected) => {
                let bytes = mysql::decode(actual)?;
                let actual = crate::json_value::parse_with_limit(
                    &bytes,
                    crate::value_limits::MAX_VALUE_BYTES,
                )?;
                for (pointer, expected) in &expected.json {
                    let value = actual.pointer(pointer)?;
                    match expected {
                        AsyncOwnershipJsonValue::Literal(expected) => {
                            if value != &expected.literal {
                                return None;
                            }
                        }
                        AsyncOwnershipJsonValue::Identity(expected) => {
                            let identity =
                                if expected.prefix.is_empty() && expected.suffix.is_empty() {
                                    value.as_u64().filter(|value| *value > 0).or_else(|| {
                                        value
                                            .as_str()
                                            .and_then(|value| identity(expected, value.as_bytes()))
                                    })
                                } else {
                                    value
                                        .as_str()
                                        .and_then(|value| identity(expected, value.as_bytes()))
                                }?;
                            insert(&mut bindings, &expected.identity, identity)?;
                        }
                    }
                }
            }
        }
    }
    Some(bindings)
}

pub(super) fn candidates<'a>(
    rules: &'a [Rule<'a>],
    origins: &'a [origins::Origin],
    inputs: &[CaseFacts],
    event: &Value,
    outcome: &mut Outcome,
) -> Vec<(&'a origins::Origin, &'a AsyncOwnershipRequest)> {
    let mut found = Vec::new();
    if !super::candidate_scope(event) {
        return found;
    }
    for rule in rules {
        for request in &rule.ownership.requests {
            let Some(bindings) = selector(request, event) else {
                continue;
            };
            for origin in origins {
                if origin.assignment.scenario_index != rule.scenario_index
                    || origin.assignment.rule_id
                        != format!("{}:{}", crate::policy::ASYNC_API_ID, rule.api)
                    || bindings.is_empty()
                    || !bindings
                        .iter()
                        .all(|(name, value)| origin.bindings.get(name) == Some(value))
                    || epoch(event) != Some(origin.epoch)
                    || started(event).is_none_or(|time| time < origin.started_at)
                {
                    continue;
                }
                if !origin.certain {
                    problem(outcome, event, Some(origin), "non_unique_origin_capture");
                } else if admissible(origin, inputs, event, &bindings) {
                    found.push((origin, request));
                } else {
                    problem(outcome, event, Some(origin), "competing_ingress");
                }
            }
        }
    }
    found
}

pub(super) fn prelude<'a>(
    request: &AsyncOwnershipRequest,
    event: &Value,
    events: &'a [Value],
) -> Option<&'a Value> {
    let AsyncOwnershipRequest::Redis {
        resource,
        script_exists_prelude: true,
        arguments,
        ..
    } = request
    else {
        return None;
    };
    let Some(Argument::Literal(sha)) = arguments.first() else {
        return None;
    };
    let sequence = event["sequence"].as_u64()?.checked_sub(1)?;
    let mut candidates = events.iter().filter(|prior| {
        prior["event_type"] == "redis_exchange"
            && prior["connection_id"] == event["connection_id"]
            && prior["sequence"].as_u64() == Some(sequence)
            && epoch(prior) == epoch(event)
    });
    let previous = candidates.next()?;
    if candidates.next().is_some()
        || !projection::native_identity(previous)
        || !successful(previous)
        || !projection::resource_matches(resource, previous)
        || previous["command"] != "SCRIPT"
    {
        return None;
    }
    let actual = previous["args"].as_array()?;
    (actual.len() == 2
        && mysql::decode(&actual[0])?.as_slice() == b"EXISTS"
        && mysql::decode(&actual[1])?.as_slice() == sha.as_bytes())
    .then_some(previous)
}
