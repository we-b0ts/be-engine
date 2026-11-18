//! Native compatibility and transport recording summaries.
use anyhow::Result;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use traffic_protocol::observation::RecordingSummary;
mod udp;
use udp::*;

#[derive(Default)]
pub struct TransportSummary {
    tcp_gateway: TcpGatewayDependencySummary,
    udp: UdpDependencySummary,
    proxy_errors: ProxyErrorSummary,
}
impl RecordingSummary for TransportSummary {
    fn observe(&mut self, value: &Value) {
        match value["event_type"].as_str() {
            Some("tcp_gateway_connection") => {
                record_tcp_gateway_summary(&mut self.tcp_gateway, value)
            }
            Some("udp_datagram") => record_udp_summary(&mut self.udp, value),
            Some("proxy_error") => record_proxy_error_summary(&mut self.proxy_errors, value),
            _ => {}
        }
    }
    fn finish(self: Box<Self>) -> Result<BTreeMap<String, Value>> {
        let mut fields = BTreeMap::new();
        if self.tcp_gateway.connections > 0 {
            fields.insert(
                "tcp_gateway".into(),
                serde_json::to_value(self.tcp_gateway)?,
            );
        }
        if self.udp.datagrams > 0 {
            fields.insert("udp".into(), serde_json::to_value(self.udp)?);
        }
        if self.proxy_errors.total > 0 {
            fields.insert(
                "proxy_errors".into(),
                serde_json::to_value(self.proxy_errors)?,
            );
        }
        Ok(fields)
    }
}
#[derive(Debug, Default, Serialize)]
struct TcpGatewayDependencySummary {
    connections: usize,
    domains: BTreeMap<String, usize>,
    upstreams: BTreeMap<String, usize>,
    errors: usize,
}

#[derive(Debug, Default, Serialize)]
struct ProxyErrorSummary {
    total: usize,
    protocols: BTreeMap<String, usize>,
    targets: BTreeMap<String, usize>,
}

fn record_tcp_gateway_summary(summary: &mut TcpGatewayDependencySummary, value: &Value) {
    summary.connections += 1;
    if let Some(domain) = json_str(value, "domain") {
        *summary.domains.entry(domain.to_string()).or_default() += 1;
    }
    if let Some(upstream) = json_str(value, "upstream_addr") {
        *summary.upstreams.entry(upstream.to_string()).or_default() += 1;
    }
    if value.get("error").is_some_and(|error| !error.is_null()) {
        summary.errors += 1;
    }
}

fn record_proxy_error_summary(summary: &mut ProxyErrorSummary, value: &Value) {
    summary.total += 1;
    if let Some(protocol) = json_str(value, "protocol") {
        *summary.protocols.entry(protocol.to_string()).or_default() += 1;
    }
    if let Some(target) = json_str(value, "target") {
        *summary.targets.entry(target.to_string()).or_default() += 1;
    }
}

fn json_str<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn json_usize(value: &Value, key: &str) -> Option<usize> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
}

#[cfg(test)]
fn build_dependency_summary(raw: &str) -> serde_json::Value {
    crate::recorder::summary::build_dependency_summary(raw)
}
#[cfg(test)]
mod tests;
