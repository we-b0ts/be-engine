use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Default, Serialize)]
pub(super) struct MotanDependencySummary {
    connections: usize,
    connection_errors: usize,
    exchanges: usize,
    unsafe_events: usize,
    client_terminated: usize,
    exceptions: usize,
    targets: BTreeMap<String, usize>,
    methods: BTreeMap<String, usize>,
    codec_versions: BTreeMap<String, usize>,
}

#[derive(Debug, Default)]
pub(super) struct MotanSummaryBuilder {
    connection_ids: BTreeSet<String>,
    summary: MotanDependencySummary,
}

impl MotanSummaryBuilder {
    pub(super) fn has_activity(&self) -> bool {
        !self.connection_ids.is_empty() || self.summary.exchanges > 0
    }

    pub(super) fn finish(mut self) -> MotanDependencySummary {
        self.summary.connections = self.connection_ids.len();
        self.summary
    }

    pub(super) fn record_connection(&mut self, value: &Value) {
        if let Some(id) = value.get("id").and_then(Value::as_str) {
            self.connection_ids.insert(id.to_string());
        }
        if value.get("error").is_some_and(|error| !error.is_null()) {
            self.summary.connection_errors += 1;
        }
        if value.get("replay_safe").and_then(Value::as_bool) != Some(true) {
            self.summary.unsafe_events += 1;
        }
        record_target(&mut self.summary, value);
    }

    pub(super) fn record_exchange(&mut self, value: &Value) {
        self.summary.exchanges += 1;
        if value.get("replay_safe").and_then(Value::as_bool) != Some(true) {
            self.summary.unsafe_events += 1;
        }
        record_target(&mut self.summary, value);
        if let Some(command) = value.get("command").and_then(Value::as_str) {
            *self.summary.methods.entry(command.to_string()).or_default() += 1;
        }
        if let Some(version) = value.get("codec_version").and_then(Value::as_u64) {
            *self
                .summary
                .codec_versions
                .entry(version.to_string())
                .or_default() += 1;
        }
        match value.get("outcome").and_then(Value::as_str) {
            Some("client_terminated") => self.summary.client_terminated += 1,
            _ if value.get("response_status").and_then(Value::as_str) == Some("exception") => {
                self.summary.exceptions += 1;
            }
            _ => {}
        }
    }
}

fn record_target(summary: &mut MotanDependencySummary, value: &Value) {
    if let (Some(host), Some(port)) = (
        value.get("target_host").and_then(Value::as_str),
        value.get("target_port").and_then(Value::as_u64),
    ) {
        *summary.targets.entry(format!("{host}:{port}")).or_default() += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_connection_id_once_and_tracks_unsafe_exchange() {
        let mut builder = MotanSummaryBuilder::default();
        for phase in ["opened", "closed"] {
            builder.record_connection(&serde_json::json!({
                "id": "018f8923-a678-7df3-beed-5887785ba276",
                "phase": phase,
                "target_host": "vintage-node.trp.test",
                "target_port": 8881,
                "replay_safe": true
            }));
        }
        builder.record_exchange(&serde_json::json!({
            "target_host": "vintage-node.trp.test",
            "target_port": 8881,
            "command": "example.UserService#getUser",
            "codec_version": 1,
            "response_status": "value",
            "outcome": "response",
            "replay_safe": false
        }));

        let summary = builder.finish();
        assert_eq!(summary.connections, 1);
        assert_eq!(summary.exchanges, 1);
        assert_eq!(summary.unsafe_events, 1);
    }
}
