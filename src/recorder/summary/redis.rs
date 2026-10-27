use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::Serialize;
use serde_json::Value;

#[cfg(test)]
mod tests;

pub(crate) fn is_client_library_info_exchange(
    exchange: &crate::recorder::RedisExchangeEvent,
) -> bool {
    if !exchange.command.eq_ignore_ascii_case("CLIENT")
        || !exchange.replay_safe
        || exchange.outcome != crate::DependencyExchangeOutcome::Response
        || exchange.response.truncated
        || !exchange.parse_warnings.is_empty()
    {
        return false;
    }
    let args = exchange
        .args
        .iter()
        .map(|capture| {
            if capture.truncated {
                return None;
            }
            match capture.encoding {
                "base64" => STANDARD.decode(&capture.data).ok(),
                "utf8" => Some(capture.data.as_bytes().to_vec()),
                _ => None,
            }
        })
        .collect::<Option<Vec<_>>>();
    args.is_some_and(|args| crate::redis::is_client_library_info(&exchange.command, &args))
}

#[derive(Debug, Default, Serialize)]
pub(super) struct RedisDependencySummary {
    connections: usize,
    exchanges: usize,
    #[serde(skip_serializing_if = "is_zero")]
    pubsub_pushes: usize,
    #[serde(skip_serializing_if = "is_zero")]
    rpc_callbacks: usize,
    unsafe_exchanges: usize,
    errors: usize,
    client_terminated: usize,
    server_terminated: usize,
    commands: BTreeMap<String, usize>,
    outcomes: BTreeMap<String, usize>,
    response_kinds: BTreeMap<String, usize>,
    targets: BTreeMap<String, usize>,
    resp_versions: BTreeMap<String, usize>,
    request_bytes: usize,
    response_bytes: usize,
}

#[derive(Default)]
pub(super) struct RedisSummaryBuilder {
    connection_ids: BTreeSet<String>,
    summary: RedisDependencySummary,
}

impl RedisSummaryBuilder {
    pub(super) fn record_connection(&mut self, value: &Value) {
        if let Some(id) = json_str(value, "id") {
            self.connection_ids.insert(id.to_string());
        }
        record_target(&mut self.summary.targets, value);
    }

    pub(super) fn record_push(&mut self, value: &Value) {
        self.summary.pubsub_pushes += 1;
        if value.get("rpc_request").is_some_and(|v| !v.is_null()) {
            self.summary.rpc_callbacks += 1;
        }
        if value["replay_safe"] != true {
            self.summary.unsafe_exchanges += 1;
        }
        record_target(&mut self.summary.targets, value);
        self.summary.response_bytes +=
            value["response"]["original_len"].as_u64().unwrap_or(0) as usize;
    }

    pub(super) fn record_exchange(&mut self, value: &Value) {
        self.summary.exchanges += 1;
        if !json_bool(value, "replay_safe").unwrap_or(false) {
            self.summary.unsafe_exchanges += 1;
        }
        if json_str(value, "response_kind") == Some("error") {
            self.summary.errors += 1;
        }
        if super::termination::client_terminated(value) {
            self.summary.client_terminated += 1;
        }
        if super::termination::server_terminated(value) {
            self.summary.server_terminated += 1;
        }
        increment_string(&mut self.summary.commands, json_str(value, "command"));
        increment_string(&mut self.summary.outcomes, super::termination::label(value));
        increment_string(
            &mut self.summary.response_kinds,
            json_str(value, "response_kind"),
        );
        if let Some(version) = json_u64(value, "resp_version") {
            *self
                .summary
                .resp_versions
                .entry(format!("resp{version}"))
                .or_default() += 1;
        }
        record_target(&mut self.summary.targets, value);
        self.summary.request_bytes += value
            .get("args")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|capture| json_u64(capture, "original_len"))
            .map(|value| value as usize)
            .sum::<usize>();
        self.summary.response_bytes += value
            .get("response")
            .and_then(|capture| json_u64(capture, "original_len"))
            .unwrap_or_default() as usize;
    }

    pub(super) fn finish(mut self) -> RedisDependencySummary {
        self.summary.connections = self.connection_ids.len();
        self.summary
    }

    pub(super) fn has_activity(&self) -> bool {
        !self.connection_ids.is_empty()
            || self.summary.exchanges > 0
            || self.summary.pubsub_pushes > 0
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

fn json_str<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn json_u64(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(Value::as_u64)
}

fn json_bool(value: &Value, key: &str) -> Option<bool> {
    value.get(key).and_then(Value::as_bool)
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}
