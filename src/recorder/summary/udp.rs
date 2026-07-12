use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

use super::{json_str, json_usize};

#[derive(Debug, Default, Serialize)]
pub(super) struct UdpDependencySummary {
    pub(super) datagrams: usize,
    protocols: BTreeMap<String, usize>,
    target_hosts: BTreeMap<String, usize>,
    target_addrs: BTreeMap<String, usize>,
    upstreams: BTreeMap<String, usize>,
    payload_bytes: usize,
    forwarded: usize,
    errors: usize,
}

pub(super) fn record_udp_summary(summary: &mut UdpDependencySummary, value: &Value) {
    summary.datagrams += 1;
    if let Some(protocol) = json_str(value, "protocol") {
        *summary.protocols.entry(protocol.to_string()).or_default() += 1;
    }
    if let Some(target_host) = json_str(value, "target_host") {
        *summary
            .target_hosts
            .entry(target_host.to_string())
            .or_default() += 1;
    }
    if let Some(target_addr) = json_str(value, "target_addr") {
        *summary
            .target_addrs
            .entry(target_addr.to_string())
            .or_default() += 1;
    }
    if let Some(upstream) = json_str(value, "upstream_addr") {
        *summary.upstreams.entry(upstream.to_string()).or_default() += 1;
    }
    if let Some(stored_len) = value
        .get("payload")
        .and_then(|payload| json_usize(payload, "stored_len"))
    {
        summary.payload_bytes += stored_len;
    }
    if value
        .get("forwarded")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        summary.forwarded += 1;
    }
    if value.get("error").is_some_and(|error| !error.is_null()) {
        summary.errors += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::super::build_dependency_summary;

    #[test]
    fn dependency_summary_includes_udp_datagrams() {
        let raw = r#"{"event_type":"udp_datagram","protocol":"udp","target_host":"metrics.internal","target_addr":"metrics.internal:8125","upstream_addr":"10.0.0.2:8125","forwarded":false,"payload":{"stored_len":18},"error":null}
{"event_type":"udp_datagram","protocol":"udp","target_host":"metrics.internal","target_addr":"metrics.internal:8125","forwarded":true,"payload":{"stored_len":9},"error":"send failed"}"#;
        let summary = serde_json::to_value(build_dependency_summary(raw)).unwrap();

        assert_eq!(summary["total_events"], 2);
        assert_eq!(summary["event_types"]["udp_datagram"], 2);
        assert_eq!(summary["udp"]["datagrams"], 2);
        assert_eq!(summary["udp"]["protocols"]["udp"], 2);
        assert_eq!(summary["udp"]["target_hosts"]["metrics.internal"], 2);
        assert_eq!(summary["udp"]["target_addrs"]["metrics.internal:8125"], 2);
        assert_eq!(summary["udp"]["upstreams"]["10.0.0.2:8125"], 1);
        assert_eq!(summary["udp"]["payload_bytes"], 27);
        assert_eq!(summary["udp"]["forwarded"], 1);
        assert_eq!(summary["udp"]["errors"], 1);
    }
}
