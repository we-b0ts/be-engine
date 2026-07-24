use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

use super::json_str;

#[derive(Debug, Default, Serialize)]
pub(super) struct KafkaDependencySummary {
    connections: usize,
    produced_records: usize,
    fetch_requests: usize,
    delivered_records: usize,
    outcomes: BTreeMap<String, usize>,
    topics: BTreeMap<String, usize>,
    targets: BTreeMap<String, usize>,
    key_bytes: usize,
    value_bytes: usize,
    header_bytes: usize,
    unsafe_events: usize,
}

impl KafkaDependencySummary {
    pub(super) fn has_activity(&self) -> bool {
        self.connections > 0
            || self.produced_records > 0
            || self.fetch_requests > 0
            || self.delivered_records > 0
    }
}

pub(super) fn record_kafka_connection_summary(summary: &mut KafkaDependencySummary, value: &Value) {
    summary.connections += 1;
    if let Some(target) = json_str(value, "target_addr") {
        *summary.targets.entry(target.to_string()).or_default() += 1;
    }
    if value.get("replay_safe").and_then(Value::as_bool) != Some(true) {
        summary.unsafe_events += 1;
    }
}

pub(super) fn record_kafka_record_summary(
    summary: &mut KafkaDependencySummary,
    value: &Value,
    produced: bool,
) {
    if produced {
        summary.produced_records += 1;
        record_outcome(summary, value);
    } else {
        summary.delivered_records += 1;
    }
    if let Some(topic) = json_str(value, "topic") {
        *summary.topics.entry(topic.to_string()).or_default() += 1;
    }
    if let Some(target) = json_str(value, "target_addr") {
        *summary.targets.entry(target.to_string()).or_default() += 1;
    }
    summary.key_bytes += capture_stored_len(value.get("key"));
    summary.value_bytes += capture_stored_len(value.get("value"));
    summary.header_bytes += value
        .get("headers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|header| capture_stored_len(header.get("value")))
        .sum::<usize>();
    if value.get("replay_safe").and_then(Value::as_bool) != Some(true) {
        summary.unsafe_events += 1;
    }
}

pub(super) fn record_kafka_fetch_summary(summary: &mut KafkaDependencySummary, value: &Value) {
    summary.fetch_requests += 1;
    record_outcome(summary, value);
    if let Some(target) = json_str(value, "target_addr") {
        *summary.targets.entry(target.to_string()).or_default() += 1;
    }
    if value.get("replay_safe").and_then(Value::as_bool) != Some(true) {
        summary.unsafe_events += 1;
    }
}

fn record_outcome(summary: &mut KafkaDependencySummary, value: &Value) {
    let outcome = json_str(value, "outcome").unwrap_or("response");
    *summary.outcomes.entry(outcome.to_string()).or_default() += 1;
}

fn capture_stored_len(value: Option<&Value>) -> usize {
    value
        .and_then(|value| value.get("stored_len"))
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_semantic_bytes_without_exposing_payloads() {
        let mut summary = KafkaDependencySummary::default();
        record_kafka_record_summary(
            &mut summary,
            &serde_json::json!({
                "topic": "orders",
                "target_addr": "kafka.internal:9092",
                "key": {"stored_len": 3},
                "headers": [{"name": "trace", "value": {"stored_len": 4}}],
                "value": {"stored_len": 5},
                "replay_safe": true
            }),
            true,
        );
        assert_eq!(summary.produced_records, 1);
        assert_eq!(summary.key_bytes, 3);
        assert_eq!(summary.header_bytes, 4);
        assert_eq!(summary.value_bytes, 5);
    }
}
