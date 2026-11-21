use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::Value;

#[cfg(test)]
mod tests;

#[derive(Debug, Default, Serialize)]
pub(crate) struct RedisDependencySummary {
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
pub(crate) struct RedisSummaryBuilder {
    connection_ids: BTreeSet<String>,
    summary: RedisDependencySummary,
}

impl RedisSummaryBuilder {
    pub(crate) fn record_connection(&mut self, value: &Value) {
        if let Some(id) = json_str(value, "id") {
            self.connection_ids.insert(id.to_string());
        }
        record_target(&mut self.summary.targets, value);
    }

    pub(crate) fn record_push(&mut self, value: &Value) {
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

    pub(crate) fn record_exchange(&mut self, value: &Value) {
        self.summary.exchanges += 1;
        if !json_bool(value, "replay_safe").unwrap_or(false) {
            self.summary.unsafe_exchanges += 1;
        }
        if json_str(value, "response_kind") == Some("error") {
            self.summary.errors += 1;
        }
        if traffic_protocol::observation::termination::client_terminated(value) {
            self.summary.client_terminated += 1;
        }
        if traffic_protocol::observation::termination::server_terminated(value) {
            self.summary.server_terminated += 1;
        }
        increment_string(&mut self.summary.commands, json_str(value, "command"));
        increment_string(
            &mut self.summary.outcomes,
            traffic_protocol::observation::termination::label(value),
        );
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

    fn into_summary(mut self) -> RedisDependencySummary {
        self.summary.connections = self.connection_ids.len();
        self.summary
    }

    pub(crate) fn has_activity(&self) -> bool {
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

impl traffic_protocol::observation::RecordingSummary for RedisSummaryBuilder {
    fn observe(&mut self, value: &Value) {
        match value["event_type"].as_str() {
            Some("redis_connection") => self.record_connection(value),
            Some("redis_exchange") => self.record_exchange(value),
            Some("redis_pub_sub_push") => self.record_push(value),
            _ => {}
        }
    }
    fn finish(self: Box<Self>) -> anyhow::Result<BTreeMap<String, Value>> {
        let mut fields = BTreeMap::new();
        if self.has_activity() {
            fields.insert("redis".into(), serde_json::to_value(self.into_summary())?);
        }
        Ok(fields)
    }
}
