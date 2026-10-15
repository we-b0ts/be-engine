//! Compact request-side facts; no expected responses or retained body payloads.
use crate::config::ApiTriggerSource;
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

pub(super) struct RequestFacts {
    pub method: String,
    pub uri: String,
    pub started_at: Option<DateTime<Utc>>,
    conditions: BTreeMap<String, Value>,
    references: BTreeSet<String>,
    ambiguous_body: bool,
}

pub(super) fn read(path: &Path, pointers: &BTreeSet<String>) -> Result<Option<RequestFacts>> {
    ensure!(
        std::fs::metadata(path)?.len() <= 128 * 1024 * 1024,
        "API trigger request evidence exceeds limit"
    );
    let value: Value =
        serde_json::from_slice(&std::fs::read(path)?).context("invalid request artifact")?;
    let (Some(uri), Some(method)) = (value["uri"].as_str(), value["method"].as_str()) else {
        // Non-HTTP primary cases cannot prove an HTTP API origin or independent victim.
        return Ok(None);
    };
    let (uri, method) = (uri.to_owned(), method.to_owned());
    let started_at = value["timestamp"]
        .as_str()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|t| t.with_timezone(&Utc));
    let body = body(&value);
    let mut conditions = BTreeMap::new();
    if let Some(body) = &body {
        for pointer in pointers {
            if let Some(v) = body
                .pointer(pointer)
                .filter(|v| !v.is_array() && !v.is_object())
            {
                conditions.insert(pointer.clone(), v.clone());
            }
        }
    }
    let mut references = BTreeSet::new();
    // Decode percent-encoded URI values before rejecting same-resource victims.
    for (key, value) in url::form_urlencoded::parse(uri.as_bytes()) {
        add_digits(&key, &mut references);
        add_digits(&value, &mut references);
    }
    if let Some(body) = &body {
        collect(body, &mut references);
    }
    let nonempty = value["body"]["original_len"].as_u64().unwrap_or(0) > 0
        || value["body"]["data"]
            .as_str()
            .is_some_and(|s| !s.is_empty());
    let ambiguous_body = (nonempty && body.is_none()) || references.len() > 4096;
    references.retain(|s| s.len() <= 20);
    Ok(Some(RequestFacts {
        method,
        uri,
        started_at,
        conditions,
        references,
        ambiguous_body,
    }))
}

fn collect(value: &Value, refs: &mut BTreeSet<String>) {
    if refs.len() > 4096 {
        return;
    }
    match value {
        Value::Number(n) => {
            if let Some(n) = n.as_u64() {
                refs.insert(n.to_string());
            }
        }
        Value::String(s) => add_digits(s, refs),
        Value::Array(a) => {
            for v in a {
                collect(v, refs);
            }
        }
        Value::Object(o) => {
            for v in o.values() {
                collect(v, refs);
            }
        }
        _ => {}
    }
}

fn add_digits(text: &str, refs: &mut BTreeSet<String>) {
    for part in text.split(|c: char| !c.is_ascii_digit()) {
        if refs.len() > 4096 {
            return;
        }
        if let Ok(n) = part.parse::<u64>() {
            refs.insert(n.to_string());
        }
    }
}

fn body(request: &Value) -> Option<Value> {
    let capture = &request["body"];
    if capture["truncated"] == true || capture["decode_error"].as_str().is_some() {
        return None;
    }
    let text = capture["data"].as_str()?;
    if text.len() > 2 * 1024 * 1024 {
        return None;
    }
    let bytes = match capture["encoding"].as_str()? {
        "utf8" => text.as_bytes().to_vec(),
        "base64" => STANDARD.decode(text).ok()?,
        _ => return None,
    };
    crate::json_value::parse(&bytes)
}

pub(super) fn matches(source: &ApiTriggerSource, request: &RequestFacts) -> bool {
    request.method == source.method
        && request
            .uri
            .parse::<hyper::Uri>()
            .is_ok_and(|uri| uri.path() == source.path)
        && source
            .request_body_json
            .iter()
            .all(|(pointer, expected)| request.conditions.get(pointer) == Some(expected))
}

pub(super) fn references(request: &RequestFacts, identity: &str) -> bool {
    request.ambiguous_body || request.references.contains(identity)
}

pub(super) fn same_resource_reference(request: &RequestFacts, identity: &str) -> bool {
    !request.ambiguous_body && request.references.contains(identity)
}
