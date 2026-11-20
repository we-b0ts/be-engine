//! Source operation shapes. Request bodies and SQL literal values stay out of the report.
use super::GroupShape;
use crate::dependency::observation::CaptureMetadata;
use serde_json::Value;
use traffic_protocol::observation::{format_endpoint, optional_endpoint};
use traffic_protocol_mysql::{access, sql::Token, sql_family};
use traffic_protocol_redis::{is_pubsub_command, key_slots, recorded::RecordedCapture};

pub(super) fn shape(event: &Value, capture: &CaptureMetadata) -> GroupShape {
    let protocol = capture.protocol_ref.protocol().to_owned();
    let endpoint = optional_endpoint(
        event["target_host"].as_str(),
        event["target_port"]
            .as_u64()
            .and_then(|port| u16::try_from(port).ok()),
        event["target_addr"].as_str(),
    );
    let mut group = GroupShape {
        protocol,
        endpoint,
        database: None,
        operation: event["event_type"].as_str().unwrap_or("unknown").into(),
        selectors: Vec::new(),
        selector_count: None,
    };
    match group.operation.as_str() {
        "mysql_exchange" => {
            group.database = event["database"].as_str().map(str::to_owned);
            group.operation = event["command"].as_str().unwrap_or("unknown").into();
            if let Some(sql) = event["sql"].as_str() {
                group.selectors = mysql_selectors(sql, group.database.as_deref());
            }
        }
        "redis_exchange" => {
            group.database = event["database"].as_i64().map(|db| db.to_string());
            group.operation = event["command"]
                .as_str()
                .unwrap_or("unknown")
                .to_ascii_uppercase();
            group.selectors = redis_selectors(event, &group.operation).unwrap_or_default();
        }
        "redis_pub_sub_push" => {
            group.database = event["database"].as_i64().map(|db| db.to_string());
            if let Some(frame) = decode(&event["response"]).and_then(|wire| {
                traffic_protocol_redis::parse_pubsub_push(&wire)
                    .ok()
                    .flatten()
            }) {
                group
                    .selectors
                    .push(format!("channel={}", bounded_label(&frame.channel)));
            }
        }
        "http_exchange" => {
            if let Ok(endpoint) = traffic_protocol_http::index::endpoint(event) {
                group.endpoint = Some(format!(
                    "{}://{}",
                    endpoint.protocol,
                    format_endpoint(&endpoint.host, endpoint.port)
                ));
            }
            group.operation = event["method"]
                .as_str()
                .unwrap_or("unknown")
                .to_ascii_uppercase();
            if let Some(path) = event["uri"]
                .as_str()
                .and_then(|uri| uri.parse::<hyper::Uri>().ok())
                .map(|uri| bounded_label(uri.path().as_bytes()))
            {
                group.selectors.push(path);
            }
        }
        _ => {}
    }
    group
}

pub(super) fn mysql_selectors(sql: &str, database: Option<&str>) -> Vec<String> {
    let Some(tokens) = sql_family::bounded_tokens(sql) else {
        return vec![crate::policy_evidence::digest(sql.as_bytes())];
    };
    let mut tables = if let Some(table) = sql_family::select_table(&tokens) {
        vec![table.to_owned()]
    } else {
        access::analyze_sql(sql).resource_names(database)
    };
    tables.sort();
    tables.dedup();
    let mut labels: Vec<_> = tables
        .into_iter()
        .map(|table| format!("table={table}"))
        .collect();
    let template = tokens
        .iter()
        .map(|token| match token {
            Token::Word(word) | Token::Symbol(word) => word.clone(),
            Token::Identifier(name) => format!("`{}`", name.replace('`', "``")),
            Token::Bytes(_) | Token::Number(_) | Token::Null | Token::Placeholder => "?".into(),
        })
        .collect::<Vec<_>>()
        .join(" ");
    labels.push(format!("sql={}", bounded_label(template.as_bytes())));
    labels
}

fn redis_selectors(event: &Value, command: &str) -> Option<Vec<String>> {
    let args = event["args"].as_array()?;
    let script = matches!(command, "EVAL" | "EVALSHA" | "EVAL_RO" | "EVALSHA_RO");
    let publishes = matches!(command, "PUBLISH" | "SPUBLISH");
    let subscription = is_pubsub_command(command);
    let mut selectors = Vec::new();
    let (kind, indices) = if publishes {
        ("channel", vec![0])
    } else if subscription {
        ("channel", (0..args.len()).collect())
    } else {
        // The protocol's key-slot parser only inspects the script key count.
        // Decode only that argument plus the selected keys and script.
        let mut slots = vec![Vec::new(); args.len()];
        if script {
            selectors.push(format!(
                "script={}",
                crate::policy_evidence::digest(&decode(args.first()?)?)
            ));
            *slots.get_mut(1)? = decode(args.get(1)?)?;
        }
        let key_command = command
            .strip_suffix("_RO")
            .filter(|_| script)
            .unwrap_or(command);
        ("key", key_slots::key_indices(key_command, &slots).ok()?)
    };
    for index in indices {
        selectors.push(format!(
            "{kind}={}",
            bounded_label(&decode(args.get(index)?)?)
        ));
    }
    Some(selectors)
}

fn decode(value: &Value) -> Option<Vec<u8>> {
    serde_json::from_value::<RecordedCapture>(value.clone())
        .ok()?
        .decode()
        .ok()
}

fn bounded_label(value: &[u8]) -> String {
    const MAX_LABEL_BYTES: usize = 2048;
    match std::str::from_utf8(value) {
        Ok(label) if label.len() <= MAX_LABEL_BYTES && !label.chars().any(char::is_control) => {
            label.into()
        }
        _ => crate::policy_evidence::digest(value),
    }
}
