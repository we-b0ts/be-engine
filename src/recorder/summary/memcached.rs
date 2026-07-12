use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Default, Serialize)]
pub(super) struct MemcachedDependencySummary {
    connections: usize,
    exchanges: usize,
    unsafe_exchanges: usize,
    errors: usize,
    no_response: usize,
    quiet: usize,
    noreply: usize,
    hits: usize,
    misses: usize,
    commands: BTreeMap<String, usize>,
    response_statuses: BTreeMap<String, usize>,
    wire_protocols: BTreeMap<String, usize>,
    targets: BTreeMap<String, usize>,
    request_bytes: usize,
    response_bytes: usize,
}

#[derive(Default)]
pub(super) struct MemcachedSummaryBuilder {
    connection_ids: BTreeSet<String>,
    summary: MemcachedDependencySummary,
}

impl MemcachedSummaryBuilder {
    pub(super) fn record_connection(&mut self, value: &Value) {
        if let Some(id) = json_str(value, "id") {
            self.connection_ids.insert(id.to_string());
        }
        increment_string(
            &mut self.summary.wire_protocols,
            json_str(value, "wire_protocol"),
        );
        record_target(&mut self.summary.targets, value);
    }

    pub(super) fn record_exchange(&mut self, value: &Value) {
        self.summary.exchanges += 1;
        if !json_bool(value, "replay_safe").unwrap_or(false) {
            self.summary.unsafe_exchanges += 1;
        }
        if json_bool(value, "no_response").unwrap_or(false) {
            self.summary.no_response += 1;
        }
        if json_bool(value, "quiet").unwrap_or(false) {
            self.summary.quiet += 1;
        }
        if json_bool(value, "noreply").unwrap_or(false) {
            self.summary.noreply += 1;
        }
        let command = json_str(value, "command");
        let status = json_str(value, "response_status").map(normalize_response_status);
        increment_string(&mut self.summary.commands, command);
        increment_string(&mut self.summary.response_statuses, status.as_deref());
        increment_string(
            &mut self.summary.wire_protocols,
            json_str(value, "wire_protocol"),
        );
        record_target(&mut self.summary.targets, value);
        if matches!(status.as_deref(), Some(value) if matches!(value, "CLIENT_ERROR" | "SERVER_ERROR" | "ERROR") || (!matches!(value, "0" | "1" | "no_response") && value.parse::<u16>().is_ok_and(|code| code != 0)))
        {
            self.summary.errors += 1;
        }
        if matches!(command, Some("get" | "gets" | "gat" | "gats")) {
            match status.as_deref() {
                Some("0") => self.summary.hits += 1,
                Some("VALUE") => self.summary.hits += 1,
                Some("1") | Some("END") => self.summary.misses += 1,
                _ => {}
            }
            if json_bool(value, "quiet").unwrap_or(false)
                && json_bool(value, "no_response").unwrap_or(false)
                && json_str(value, "wire_protocol") == Some("binary")
            {
                self.summary.misses += 1;
            }
        }
        self.summary.request_bytes += capture_len(value.get("key"))
            + capture_len(value.get("value"))
            + capture_len(value.get("extras"));
        self.summary.response_bytes += value
            .get("response_frames")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|capture| capture_len(Some(capture)))
            .sum::<usize>();
    }

    pub(super) fn finish(mut self) -> MemcachedDependencySummary {
        self.summary.connections = self.connection_ids.len();
        self.summary
    }

    pub(super) fn has_activity(&self) -> bool {
        !self.connection_ids.is_empty() || self.summary.exchanges > 0
    }
}

fn normalize_response_status(value: &str) -> String {
    if value.starts_with("VALUE ") {
        "VALUE".to_string()
    } else if value.starts_with("CLIENT_ERROR") {
        "CLIENT_ERROR".to_string()
    } else if value.starts_with("SERVER_ERROR") {
        "SERVER_ERROR".to_string()
    } else {
        value.to_string()
    }
}

fn record_target(targets: &mut BTreeMap<String, usize>, value: &Value) {
    let Some(host) = json_str(value, "target_host") else {
        return;
    };
    let port = json_u64(value, "target_port")
        .map(|value| value.to_string())
        .unwrap_or_else(|| "?".to_string());
    *targets.entry(format!("{host}:{port}")).or_default() += 1;
}

fn increment_string(counts: &mut BTreeMap<String, usize>, value: Option<&str>) {
    if let Some(value) = value {
        *counts.entry(value.to_string()).or_default() += 1;
    }
}

fn capture_len(value: Option<&Value>) -> usize {
    value
        .and_then(|capture| json_u64(capture, "original_len"))
        .unwrap_or_default() as usize
}

fn json_str<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn json_u64(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(Value::as_u64)
}

fn json_bool(value: &Value, key: &str) -> Option<bool> {
    value.get(key).and_then(Value::as_bool)
}
