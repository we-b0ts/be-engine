use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result};
use hyper::http::uri::Authority;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub(crate) const SUMMARY_FILENAME: &str = "pre-readiness-traffic-summary.json";
const GLOBAL_DEPENDENCIES_FILENAME: &str = "global-dependencies.jsonl";
const MAX_ENDPOINT_CANDIDATES: usize = 128;
const MAX_REPORTED_ENDPOINTS: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PreReadinessTrafficSummary {
    pub(crate) version: u8,
    pub(crate) phase: String,
    pub(crate) source: String,
    pub(crate) bootstrap_events: usize,
    pub(crate) data_interactions: usize,
    pub(crate) excluded_events: usize,
    pub(crate) unresolved_interactions: usize,
    pub(crate) endpoints: Vec<PreReadinessEndpointActivity>,
    pub(crate) omitted_interactions: usize,
    pub(crate) truncated: bool,
    pub(crate) parse_errors: usize,
    pub(crate) interpretation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PreReadinessEndpointActivity {
    pub(crate) endpoint: String,
    pub(crate) interaction_count: usize,
    pub(crate) protocols: BTreeMap<String, usize>,
}

#[derive(Debug, Default)]
struct EndpointCounts {
    interactions: usize,
    protocols: BTreeMap<String, usize>,
}

#[derive(Debug, Default)]
struct CandidateTracker {
    estimates: BTreeMap<String, usize>,
    overflowed: bool,
}

impl CandidateTracker {
    fn observe(&mut self, endpoint: String) {
        if let Some(count) = self.estimates.get_mut(&endpoint) {
            *count += 1;
            return;
        }
        if self.estimates.len() < MAX_ENDPOINT_CANDIDATES {
            self.estimates.insert(endpoint, 1);
            return;
        }

        self.overflowed = true;
        let Some((candidate, count)) = self
            .estimates
            .iter()
            .min_by_key(|(candidate, count)| (**count, *candidate))
            .map(|(candidate, count)| (candidate.clone(), *count))
        else {
            return;
        };
        self.estimates.remove(&candidate);
        self.estimates.insert(endpoint, count.saturating_add(1));
    }
}

pub(super) async fn write(dir: &Path) -> Result<()> {
    let dependencies_path = dir.join(GLOBAL_DEPENDENCIES_FILENAME);
    let raw = match super::super::storage::read_to_string(&dependencies_path).await {
        Ok(raw) => raw,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(());
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to read global dependencies {}",
                    dependencies_path.display()
                )
            });
        }
    };
    let summary = build(&raw);
    let mut payload = serde_json::to_vec_pretty(&summary)
        .context("failed to serialize pre-readiness traffic summary")?;
    payload.push(b'\n');
    let summary_path = dir.join(SUMMARY_FILENAME);
    super::super::storage::write(&summary_path, &payload)
        .await
        .with_context(|| {
            format!(
                "failed to write pre-readiness traffic summary {}",
                summary_path.display()
            )
        })
}

pub(crate) fn load_or_build(dir: &Path) -> Result<Option<PreReadinessTrafficSummary>> {
    let summary_path = dir.join(SUMMARY_FILENAME);
    match std::fs::read(&summary_path) {
        Ok(payload) => {
            let summary = serde_json::from_slice(&payload).with_context(|| {
                format!(
                    "invalid pre-readiness traffic summary {}",
                    summary_path.display()
                )
            })?;
            return Ok(Some(summary));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to read pre-readiness traffic summary {}",
                    summary_path.display()
                )
            });
        }
    }

    let dependencies_path = dir.join(GLOBAL_DEPENDENCIES_FILENAME);
    match std::fs::read_to_string(&dependencies_path) {
        Ok(raw) => Ok(Some(build(&raw))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to read global dependencies {}",
                dependencies_path.display()
            )
        }),
    }
}

fn build(raw_jsonl: &str) -> PreReadinessTrafficSummary {
    let (candidates, discovery_parse_errors) = discover_candidates(raw_jsonl);
    let candidate_endpoints = candidates
        .estimates
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut exact = BTreeMap::<String, EndpointCounts>::new();
    let mut bootstrap_events = 0_usize;
    let mut data_interactions = 0_usize;
    let mut excluded_events = 0_usize;
    let mut unresolved_interactions = 0_usize;
    let mut parse_errors = 0_usize;

    for line in raw_jsonl
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let value: Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(_) => {
                parse_errors += 1;
                continue;
            }
        };
        if value.get("global_dependency_phase").and_then(Value::as_str) != Some("bootstrap") {
            continue;
        }
        bootstrap_events += 1;
        let event_type = value
            .get("event_type")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        if !is_data_interaction(event_type, &value) {
            excluded_events += 1;
            continue;
        }
        data_interactions += 1;
        let Some(endpoint) = endpoint(&value, event_type) else {
            unresolved_interactions += 1;
            continue;
        };
        if !candidate_endpoints.contains(&endpoint) {
            continue;
        }
        let counts = exact.entry(endpoint).or_default();
        counts.interactions += 1;
        *counts
            .protocols
            .entry(protocol(event_type).to_string())
            .or_default() += 1;
    }

    let resolved_interactions = data_interactions.saturating_sub(unresolved_interactions);
    let mut endpoints = exact.into_iter().collect::<Vec<_>>();
    endpoints.sort_by_key(|(endpoint, counts)| (Reverse(counts.interactions), endpoint.clone()));
    let endpoint_overflow = endpoints.len() > MAX_REPORTED_ENDPOINTS;
    endpoints.truncate(MAX_REPORTED_ENDPOINTS);
    let included_interactions = endpoints
        .iter()
        .map(|(_, counts)| counts.interactions)
        .sum::<usize>();
    let endpoints = endpoints
        .into_iter()
        .map(|(endpoint, counts)| PreReadinessEndpointActivity {
            endpoint,
            interaction_count: counts.interactions,
            protocols: counts.protocols,
        })
        .collect();

    debug_assert_eq!(discovery_parse_errors, parse_errors);
    PreReadinessTrafficSummary {
        version: 1,
        phase: "bootstrap".to_string(),
        source: GLOBAL_DEPENDENCIES_FILENAME.to_string(),
        bootstrap_events,
        data_interactions,
        excluded_events,
        unresolved_interactions,
        endpoints,
        omitted_interactions: resolved_interactions.saturating_sub(included_interactions),
        truncated: candidates.overflowed || endpoint_overflow,
        parse_errors,
        interpretation: "pre-readiness data-interaction frequency is temporal evidence; connection lifecycle and known ping or setup traffic are excluded, and the result does not prove asynchronous ownership, local-cache behavior, or response causality".to_string(),
    }
}

fn discover_candidates(raw_jsonl: &str) -> (CandidateTracker, usize) {
    let mut candidates = CandidateTracker::default();
    let mut parse_errors = 0;
    for line in raw_jsonl
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let value: Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(_) => {
                parse_errors += 1;
                continue;
            }
        };
        if value.get("global_dependency_phase").and_then(Value::as_str) != Some("bootstrap") {
            continue;
        }
        let event_type = value
            .get("event_type")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        if is_data_interaction(event_type, &value)
            && let Some(endpoint) = endpoint(&value, event_type)
        {
            candidates.observe(endpoint);
        }
    }
    (candidates, parse_errors)
}

fn is_data_interaction(event_type: &str, value: &Value) -> bool {
    match event_type {
        "http_exchange" | "udp_datagram" | "kafka_produce" | "kafka_fetch" => true,
        "redis_exchange" => {
            value.get("session_setup").and_then(Value::as_bool) != Some(true)
                && !value
                    .get("command")
                    .and_then(Value::as_str)
                    .is_some_and(|command| command.eq_ignore_ascii_case("PING"))
        }
        "memcached_exchange" => {
            !value
                .get("command")
                .and_then(Value::as_str)
                .is_some_and(|command| {
                    matches!(command.to_ascii_lowercase().as_str(), "version" | "noop")
                })
        }
        "motan_exchange" => value.get("heartbeat").and_then(Value::as_bool) != Some(true),
        "mysql_exchange" => !super::is_debug_only_mysql_exchange_value(value),
        _ => false,
    }
}

fn protocol(event_type: &str) -> &'static str {
    if event_type.starts_with("http_") {
        "http"
    } else if event_type.starts_with("tcp_gateway_") {
        "tcp_gateway"
    } else if event_type.starts_with("udp_") {
        "udp"
    } else if event_type.starts_with("redis_") {
        "redis"
    } else if event_type.starts_with("memcached_") {
        "memcached"
    } else if event_type.starts_with("kafka_") {
        "kafka"
    } else if event_type.starts_with("motan_") {
        "motan"
    } else if event_type.starts_with("mysql_") {
        "mysql"
    } else {
        "unknown"
    }
}

fn endpoint(value: &Value, event_type: &str) -> Option<String> {
    if let (Some(host), Some(port)) = (
        value.get("target_host").and_then(Value::as_str),
        value.get("target_port").and_then(Value::as_u64),
    ) && let Ok(port) = u16::try_from(port)
    {
        return Some(format_endpoint(host, port));
    }
    if event_type == "http_exchange"
        && let Some(authority) = value.get("authority").and_then(Value::as_str)
    {
        return http_endpoint(authority, value.get("scheme").and_then(Value::as_str));
    }
    if event_type == "tcp_gateway_connection"
        && let Some(domain) = value.get("domain").and_then(Value::as_str)
        && let Some(port) = value
            .get("upstream_addr")
            .and_then(Value::as_str)
            .and_then(endpoint_port)
    {
        return Some(format_endpoint(domain, port));
    }
    for key in ["target_addr", "upstream_addr", "target"] {
        if let Some(endpoint) = value
            .get(key)
            .and_then(Value::as_str)
            .and_then(normalize_endpoint)
        {
            return Some(endpoint);
        }
    }
    None
}

fn http_endpoint(authority: &str, scheme: Option<&str>) -> Option<String> {
    let authority = authority.parse::<Authority>().ok()?;
    let port = authority.port_u16().or(match scheme {
        Some("http") => Some(80),
        Some("https") => Some(443),
        _ => None,
    })?;
    Some(format_endpoint(authority.host(), port))
}

fn normalize_endpoint(value: &str) -> Option<String> {
    let authority = value.parse::<Authority>().ok()?;
    Some(format_endpoint(authority.host(), authority.port_u16()?))
}

fn endpoint_port(value: &str) -> Option<u16> {
    value
        .parse::<Authority>()
        .ok()
        .and_then(|authority| authority.port_u16())
}

fn format_endpoint(host: &str, port: u16) -> String {
    let host = host.trim_matches(['[', ']']).to_ascii_lowercase();
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarizes_only_bootstrap_semantic_activity_by_endpoint() {
        let raw = r#"{"event_type":"http_exchange","global_dependency_phase":"bootstrap","scheme":"https","authority":"config.internal"}
{"event_type":"redis_connection","global_dependency_phase":"bootstrap","target_host":"cache.internal","target_port":6379}
{"event_type":"redis_exchange","global_dependency_phase":"bootstrap","target_host":"cache.internal","target_port":6379}
{"event_type":"redis_exchange","global_dependency_phase":"bootstrap","target_host":"cache.internal","target_port":6379}
{"event_type":"tcp_gateway_connection","global_dependency_phase":"bootstrap","domain":"rpc.internal","upstream_addr":"10.0.0.7:8888"}
{"event_type":"proxy_error","global_dependency_phase":"bootstrap","target":"broken.internal:9000"}
{"event_type":"redis_exchange","global_dependency_phase":"bootstrap","target_host":"cache.internal","target_port":6379,"command":"PING"}
{"event_type":"memcached_exchange","global_dependency_phase":"bootstrap","target_host":"cache.internal","target_port":11211,"command":"version"}
{"event_type":"motan_exchange","global_dependency_phase":"bootstrap","target_host":"rpc.internal","target_port":8888,"heartbeat":true}
{"event_type":"mysql_exchange","global_dependency_phase":"bootstrap","target_host":"db.internal","target_port":3306,"command":"COM_PING","response":{"status":"ok"}}
{"event_type":"redis_exchange","global_dependency_phase":"runtime","target_host":"cache.internal","target_port":6379}"#;

        let summary = build(raw);

        assert_eq!(summary.bootstrap_events, 10);
        assert_eq!(summary.data_interactions, 3);
        assert_eq!(summary.excluded_events, 7);
        assert_eq!(summary.unresolved_interactions, 0);
        assert_eq!(summary.endpoints.len(), 2);
        assert_eq!(summary.endpoints[0].endpoint, "cache.internal:6379");
        assert_eq!(summary.endpoints[0].interaction_count, 2);
        assert_eq!(summary.endpoints[1].endpoint, "config.internal:443");
        assert!(!summary.truncated);
    }

    #[test]
    fn bounds_endpoint_output_while_retaining_a_late_hot_endpoint() {
        let mut lines = (0..(MAX_ENDPOINT_CANDIDATES + 32))
            .map(|index| {
                format!(
                    r#"{{"event_type":"redis_exchange","global_dependency_phase":"bootstrap","target_host":"cache-{index}.internal","target_port":6379}}"#
                )
            })
            .collect::<Vec<_>>();
        lines.extend(std::iter::repeat_n(
            r#"{"event_type":"redis_exchange","global_dependency_phase":"bootstrap","target_host":"hot.internal","target_port":6379}"#.to_string(),
            200,
        ));

        let summary = build(&lines.join("\n"));

        assert_eq!(summary.endpoints.len(), MAX_REPORTED_ENDPOINTS);
        assert!(summary.truncated);
        assert_eq!(summary.endpoints[0].endpoint, "hot.internal:6379");
        assert_eq!(summary.endpoints[0].interaction_count, 200);
        assert!(summary.omitted_interactions > 0);
    }
}
