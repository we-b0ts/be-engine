use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use traffic_protocol::evidence::EvidenceRegistry;

pub const SUMMARY_FILENAME: &str = "pre-readiness-traffic-summary.json";
const GLOBAL_DEPENDENCIES_FILENAME: &str = "global-dependencies.jsonl";
const MAX_ENDPOINT_CANDIDATES: usize = 128;
const MAX_REPORTED_ENDPOINTS: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreReadinessTrafficSummary {
    pub version: u8,
    pub phase: String,
    pub source: String,
    pub bootstrap_events: usize,
    pub data_interactions: usize,
    pub excluded_events: usize,
    pub unresolved_interactions: usize,
    pub endpoints: Vec<PreReadinessEndpointActivity>,
    pub omitted_interactions: usize,
    pub truncated: bool,
    pub parse_errors: usize,
    pub interpretation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreReadinessEndpointActivity {
    pub endpoint: String,
    pub interaction_count: usize,
    pub protocols: BTreeMap<String, usize>,
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

pub(super) async fn write(dir: &Path, evidence: Arc<EvidenceRegistry>) -> Result<()> {
    let dependencies_path = dir.join(GLOBAL_DEPENDENCIES_FILENAME);
    let summary = tokio::task::spawn_blocking(move || build_file(&dependencies_path, &evidence))
        .await
        .context("pre-readiness summary builder failed")??;
    let Some(summary) = summary else {
        return Ok(());
    };
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

pub fn load_or_build(
    dir: &Path,
    evidence: &EvidenceRegistry,
) -> Result<Option<PreReadinessTrafficSummary>> {
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

    build_file(&dir.join(GLOBAL_DEPENDENCIES_FILENAME), evidence)
}

fn build_file(
    path: &Path,
    evidence: &EvidenceRegistry,
) -> Result<Option<PreReadinessTrafficSummary>> {
    let stamp = match crate::dependency_index::FileStamp::read(path) {
        Ok(stamp) => stamp,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let summary = build_with(evidence, |visit| {
        let mut input = crate::dependency_index::RecordStream::open(path)?;
        while let Some((_, raw)) = input.next()? {
            let line = std::str::from_utf8(raw)?;
            if !line.trim().is_empty() {
                visit(line.trim());
            }
        }
        crate::dependency_index::scoped::validate_stamp(path, &stamp)?;
        Ok(())
    })?;
    Ok(Some(summary))
}

#[cfg(test)]
fn build(raw_jsonl: &str) -> PreReadinessTrafficSummary {
    build_with(crate::protocols::default_providers().evidence(), |visit| {
        for line in raw_jsonl
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
        {
            visit(line);
        }
        Ok(())
    })
    .unwrap()
}

fn build_with(
    evidence: &EvidenceRegistry,
    mut lines: impl FnMut(&mut dyn FnMut(&str)) -> Result<()>,
) -> Result<PreReadinessTrafficSummary> {
    let (candidates, discovery_parse_errors) = discover_candidates(evidence, &mut lines)?;
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

    lines(&mut |line| {
        let value: Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(_) => {
                parse_errors += 1;
                return;
            }
        };
        if value["capture"]["phase"].as_str() != Some("startup") {
            return;
        }
        bootstrap_events += 1;
        let Some(interaction) = evidence.interaction(&value) else {
            excluded_events += 1;
            return;
        };
        data_interactions += 1;
        let Some(endpoint) = interaction.endpoint else {
            unresolved_interactions += 1;
            return;
        };
        if !candidate_endpoints.contains(&endpoint) {
            return;
        }
        let counts = exact.entry(endpoint).or_default();
        counts.interactions += 1;
        *counts.protocols.entry(interaction.protocol).or_default() += 1;
    })?;

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
    Ok(PreReadinessTrafficSummary {
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
    })
}

fn discover_candidates(
    evidence: &EvidenceRegistry,
    lines: &mut impl FnMut(&mut dyn FnMut(&str)) -> Result<()>,
) -> Result<(CandidateTracker, usize)> {
    let mut candidates = CandidateTracker::default();
    let mut parse_errors = 0;
    lines(&mut |line| {
        let value: Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(_) => {
                parse_errors += 1;
                return;
            }
        };
        if value["capture"]["phase"].as_str() != Some("startup") {
            return;
        }
        if let Some(endpoint) = evidence
            .interaction(&value)
            .and_then(|interaction| interaction.endpoint)
        {
            candidates.observe(endpoint);
        }
    })?;
    Ok((candidates, parse_errors))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarizes_only_bootstrap_semantic_activity_by_endpoint() {
        let raw = r#"{"event_type":"http_exchange","capture":{"phase":"startup"},"scheme":"https","authority":"config.internal"}
{"event_type":"redis_connection","capture":{"phase":"startup"},"target_host":"cache.internal","target_port":6379}
{"event_type":"redis_exchange","capture":{"phase":"startup"},"target_host":"cache.internal","target_port":6379}
{"event_type":"redis_exchange","capture":{"phase":"startup"},"target_host":"cache.internal","target_port":6379}
{"event_type":"tcp_gateway_connection","capture":{"phase":"startup"},"domain":"rpc.internal","upstream_addr":"10.0.0.7:8888"}
{"event_type":"proxy_error","capture":{"phase":"startup"},"target":"broken.internal:9000"}
{"event_type":"redis_exchange","capture":{"phase":"startup"},"target_host":"cache.internal","target_port":6379,"command":"PING"}
{"event_type":"memcached_exchange","capture":{"phase":"startup"},"target_host":"cache.internal","target_port":11211,"command":"version"}
{"event_type":"motan_exchange","capture":{"phase":"startup"},"target_host":"rpc.internal","target_port":8888,"heartbeat":true}
{"event_type":"mysql_exchange","capture":{"phase":"startup"},"target_host":"db.internal","target_port":3306,"command":"COM_PING","response":{"status":"ok"}}
{"event_type":"redis_exchange","capture":{"phase":"runtime"},"target_host":"cache.internal","target_port":6379}"#;

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
                    r#"{{"event_type":"redis_exchange","capture":{{"phase":"startup"}},"target_host":"cache-{index}.internal","target_port":6379}}"#
                )
            })
            .collect::<Vec<_>>();
        lines.extend(std::iter::repeat_n(
            r#"{"event_type":"redis_exchange","capture":{"phase":"startup"},"target_host":"hot.internal","target_port":6379}"#.to_string(),
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
