use anyhow::Result;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use traffic_protocol::observation::RecordingSummary;
use traffic_protocol::observation::termination;
#[derive(Debug, Default, Serialize)]
pub(crate) struct HttpDependencySummary {
    calls: usize,
    methods: BTreeMap<String, usize>,
    authorities: BTreeMap<String, usize>,
    status_codes: BTreeMap<String, usize>,
    errors: usize,
    client_terminated: usize,
    server_terminated: usize,
}

fn record_http_summary(summary: &mut HttpDependencySummary, value: &Value) {
    summary.calls += 1;
    if termination::client_terminated(value) {
        summary.client_terminated += 1;
    }
    if termination::server_terminated(value) {
        summary.server_terminated += 1;
    }
    if let Some(method) = json_str(value, "method") {
        *summary
            .methods
            .entry(method.to_ascii_uppercase())
            .or_default() += 1;
    }
    if let Some(authority) = json_str(value, "authority") {
        *summary
            .authorities
            .entry(authority.to_string())
            .or_default() += 1;
    }
    if let Some(status) = json_u64(value, "response_status") {
        *summary.status_codes.entry(status.to_string()).or_default() += 1;
    }
    if value.get("error").is_some_and(|error| !error.is_null()) {
        summary.errors += 1;
    }
}

fn json_str<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn json_u64(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(Value::as_u64)
}

impl RecordingSummary for HttpDependencySummary {
    fn observe(&mut self, value: &Value) {
        record_http_summary(self, value);
    }
    fn finish(self: Box<Self>) -> Result<BTreeMap<String, Value>> {
        let mut fields = BTreeMap::new();
        if self.calls > 0 {
            fields.insert("http".into(), serde_json::to_value(self)?);
        }
        Ok(fields)
    }
}
