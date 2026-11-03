//! Bounded request-side projection; database rows and response bytes never persist.
use crate::policy::{AsyncApiRules, AsyncOwnershipRequest, Protocol, Resource};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub(crate) fn request_unavailable(envelope: &Value) -> bool {
    if crate::replay::native_source_request_body(envelope).is_some() {
        return false;
    }
    let body = &envelope["body"];
    body.is_null()
        || body["truncated"] == true
        || super::mysql::decode(body).is_none_or(|bytes| !bytes.is_empty())
}

pub(super) fn native_identity(event: &Value) -> bool {
    let (protocol, sequence) = match event["event_type"].as_str() {
        Some("mysql_exchange") => ("mysql", event["query_sequence"].as_u64()),
        Some("redis_exchange") => ("redis", event["sequence"].as_u64()),
        _ => return false,
    };
    let reference = &event["capture"]["protocol_ref"];
    event["connection_id"]
        .as_str()
        .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok())
        && reference["protocol"] == protocol
        && reference["connection_id"] == event["connection_id"]
        && sequence.is_some()
        && reference["sequence"].as_u64() == sequence
        && super::event_id(event).is_some()
        && super::epoch(event).is_some()
}

pub(crate) fn resource_matches(resource: &Resource, event: &Value) -> bool {
    event["target_host"]
        .as_str()
        .is_some_and(|host| host.eq_ignore_ascii_case(&resource.endpoint.host))
        && event["target_port"].as_u64() == Some(u64::from(resource.endpoint.port))
        && match resource.protocol {
            Protocol::Mysql => {
                event["event_type"] == "mysql_exchange"
                    && event["database"].as_str()
                        == resource.database.as_ref().and_then(|value| value.name())
            }
            Protocol::Redis => {
                event["event_type"] == "redis_exchange"
                    && event["database"].as_i64()
                        == resource.database.as_ref().and_then(|value| value.index())
            }
            _ => false,
        }
        && event["username"].as_str() == resource.username.as_deref()
}

pub(crate) fn request_view(
    event: &Value,
    rules: &BTreeMap<String, AsyncApiRules>,
) -> Option<Value> {
    let selected = rules
        .values()
        .flat_map(|rules| rules.iter())
        .filter_map(|rule| rule.ownership.as_ref())
        .any(|ownership| {
            resource_matches(&ownership.origin.resource, event)
                || ownership.requests.iter().any(|request| match request {
                    AsyncOwnershipRequest::Mysql { resource, .. } => {
                        resource_matches(resource, event)
                    }
                    AsyncOwnershipRequest::Redis {
                        resource,
                        operation,
                        script_exists_prelude,
                        ..
                    } => {
                        resource_matches(resource, event)
                            && (event["command"] == *operation
                                || *script_exists_prelude && event["command"] == "SCRIPT")
                    }
                })
        });
    selected.then(|| project_event(event)).flatten()
}

pub(crate) fn project_event(event: &Value) -> Option<Value> {
    if !matches!(
        event["event_type"].as_str(),
        Some("mysql_exchange" | "redis_exchange")
    ) {
        return None;
    }
    let mut out = Map::new();
    for field in [
        "event_type",
        "capture",
        "id",
        "target_host",
        "target_port",
        "database",
        "username",
        "command",
        "connection_id",
        "query_sequence",
        "sequence",
        "sql",
        "params",
        "args",
        "request_started_at",
        "timestamp",
        "outcome",
        "parse_warnings",
        "replay_safe",
        "session_setup",
        "response_kind",
        "server_status_before",
    ] {
        if let Some(value) = event.get(field) {
            out.insert(field.into(), value.clone());
        }
    }
    let mut response = Map::new();
    for field in [
        "status",
        "error_code",
        "affected_rows",
        "last_insert_id",
        "server_status",
        "rows_truncated",
        "column_count",
        "row_count",
    ] {
        if let Some(value) = event["response"].get(field) {
            response.insert(field.into(), value.clone());
        }
    }
    response.insert(
        "_error_absent".into(),
        Value::Bool(
            event["response"]["_error_absent"]
                .as_bool()
                .unwrap_or(event["response"]["error_message"].is_null()),
        ),
    );
    response.insert(
        "_rows_empty".into(),
        Value::Bool(
            event["response"]["_rows_empty"]
                .as_bool()
                .unwrap_or_else(|| {
                    event["response"]["rows"]
                        .as_array()
                        .is_some_and(Vec::is_empty)
                }),
        ),
    );
    response.insert(
        "_columns_empty".into(),
        Value::Bool(
            event["response"]["_columns_empty"]
                .as_bool()
                .unwrap_or_else(|| {
                    event["response"]["columns"]
                        .as_array()
                        .is_some_and(Vec::is_empty)
                }),
        ),
    );
    out.insert("response".into(), Value::Object(response));
    out.insert("_capture_complete".into(), Value::Bool(complete(event)));
    Some(Value::Object(out))
}

pub(super) fn complete(event: &Value) -> bool {
    if let Some(complete) = event["_capture_complete"].as_bool() {
        return complete;
    }
    if !crate::dependency_index::proof::capture_complete(event) {
        return false;
    }
    let raw_complete = |value: &Value| value["raw"]["truncated"] != true;
    match event["event_type"].as_str() {
        Some("mysql_exchange") => {
            event["response"]["status"] != "incomplete"
                && event["response"]["rows_truncated"] != true
                && event["params"]
                    .as_array()
                    .is_none_or(|values| values.iter().all(raw_complete))
                && event["response"]["rows"].as_array().is_none_or(|rows| {
                    rows.iter().all(|row| {
                        row.as_array()
                            .is_some_and(|values| values.iter().all(raw_complete))
                    })
                })
                && event["response"]["wire_prefix"]
                    .as_array()
                    .is_none_or(|packets| {
                        packets
                            .iter()
                            .all(|packet| packet["packet"]["truncated"] != true)
                    })
        }
        Some("redis_exchange") => {
            event["response"]["truncated"] != true
                && event["args"].as_array().is_some_and(|arguments| {
                    arguments
                        .iter()
                        .all(|argument| argument["truncated"] != true)
                })
                && event["parse_warnings"].as_array().is_none_or(|warnings| {
                    warnings.iter().all(|warning| {
                        warning.as_str().is_none_or(|warning| {
                            !warning.contains("incomplete") && !warning.contains("interrupted")
                        })
                    })
                })
        }
        _ => false,
    }
}
