use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use hyper::http::uri::Authority;
use serde::{Deserialize, Serialize};

use crate::dependency::DependencyExchangeOutcome;
use crate::mysql::maintenance::is_mysql_maintenance_exchange;
use crate::recorder::RecorderEvent;

pub(crate) const SUMMARY_FILENAME: &str = "source-process-traffic-summary.json";

const MAX_OBSERVATIONS: usize = 512;
const MAX_BACKGROUND_RULES: usize = 256;
const MAX_RULE_OBSERVATIONS: usize = 128;
const MAX_SNAPSHOT_ENDPOINTS: usize = 128;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SourceProcessTrafficSummary {
    pub(crate) version: u8,
    pub(crate) source: String,
    pub(crate) bootstrap: SourceProcessTrafficScopeSummary,
    pub(crate) background: SourceProcessBackgroundSummary,
    pub(crate) interpretation: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct SourceProcessTrafficScopeSummary {
    pub(crate) events: u64,
    pub(crate) data_interactions: u64,
    pub(crate) excluded_events: u64,
    pub(crate) unresolved_interactions: u64,
    pub(crate) observations: Vec<SourceProcessTrafficObservation>,
    pub(crate) omitted_interactions: u64,
    pub(crate) truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SourceProcessTrafficObservation {
    pub(crate) protocol: String,
    pub(crate) endpoint: String,
    pub(crate) operation: String,
    pub(crate) interactions: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct SourceProcessBackgroundSummary {
    pub(crate) events: u64,
    pub(crate) data_interactions: u64,
    pub(crate) excluded_events: u64,
    pub(crate) unresolved_interactions: u64,
    pub(crate) rules: Vec<SourceProcessBackgroundRuleSummary>,
    pub(crate) omitted_interactions: u64,
    pub(crate) truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SourceProcessBackgroundRuleSummary {
    pub(crate) name: String,
    pub(crate) interactions: u64,
    pub(crate) bootstrap_interactions: u64,
    pub(crate) runtime_interactions: u64,
    pub(crate) other_phase_interactions: u64,
    pub(crate) unresolved_interactions: u64,
    pub(crate) observations: Vec<SourceProcessTrafficObservation>,
    pub(crate) omitted_interactions: u64,
    pub(crate) truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) redis_snapshot: Option<SourceProcessRedisSnapshotSummary>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct SourceProcessRedisSnapshotSummary {
    pub(crate) seeds: u64,
    pub(crate) reuses: u64,
    pub(crate) fill_failures: u64,
    pub(crate) endpoints: Vec<SourceProcessRedisSnapshotEndpointSummary>,
    pub(crate) omitted_interactions: u64,
    pub(crate) truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SourceProcessRedisSnapshotEndpointSummary {
    pub(crate) endpoint: String,
    pub(crate) seeds: u64,
    pub(crate) reuses: u64,
    pub(crate) fill_failures: u64,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct SourceProcessTrafficSummaryBuilder {
    bootstrap: TrafficScopeBuilder,
    background: BackgroundBuilder,
}

#[derive(Debug, Clone, Default)]
struct TrafficScopeBuilder {
    events: u64,
    data_interactions: u64,
    excluded_events: u64,
    unresolved_interactions: u64,
    observations: ObservationCounts,
}

#[derive(Debug, Clone, Default)]
struct BackgroundBuilder {
    events: u64,
    data_interactions: u64,
    excluded_events: u64,
    unresolved_interactions: u64,
    rules: BTreeMap<String, BackgroundRuleBuilder>,
    omitted_interactions: u64,
    truncated: bool,
}

#[derive(Debug, Clone, Default)]
struct BackgroundRuleBuilder {
    interactions: u64,
    bootstrap_interactions: u64,
    runtime_interactions: u64,
    other_phase_interactions: u64,
    unresolved_interactions: u64,
    observations: ObservationCounts,
    redis_snapshot: Option<RedisSnapshotBuilder>,
}

#[derive(Debug, Clone, Default)]
struct RedisSnapshotBuilder {
    seeds: u64,
    reuses: u64,
    fill_failures: u64,
    endpoints: BTreeMap<String, RedisSnapshotEndpointBuilder>,
    omitted_interactions: u64,
    truncated: bool,
}

#[derive(Debug, Clone, Default)]
struct RedisSnapshotEndpointBuilder {
    seeds: u64,
    reuses: u64,
    fill_failures: u64,
}

#[derive(Debug, Clone, Default)]
struct ObservationCounts {
    values: BTreeMap<ObservationKey, u64>,
    omitted_interactions: u64,
    truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ObservationKey {
    protocol: String,
    endpoint: String,
    operation: String,
}

struct Interaction {
    protocol: &'static str,
    endpoint: Option<String>,
    operation: String,
}

enum SnapshotObservation {
    Seed,
    Reuse,
    FillFailure,
}

impl SourceProcessTrafficSummaryBuilder {
    pub(crate) fn observe(
        &mut self,
        event: &RecorderEvent,
        reason: &str,
        phase: &str,
        matched_by: &str,
    ) {
        let interaction = data_interaction(event);
        if phase == "bootstrap" {
            self.bootstrap
                .observe(interaction.as_ref(), MAX_OBSERVATIONS);
        }
        if reason == "background_rule" {
            self.background
                .observe(event, interaction.as_ref(), phase, matched_by);
        }
    }

    pub(crate) async fn write(&self, dir: &Path) -> Result<()> {
        let mut payload = serde_json::to_vec_pretty(&self.summary())
            .context("failed to serialize source process traffic summary")?;
        payload.push(b'\n');
        super::super::storage::write(&dir.join(SUMMARY_FILENAME), &payload)
            .await
            .context("failed to write source process traffic summary")
    }

    fn summary(&self) -> SourceProcessTrafficSummary {
        SourceProcessTrafficSummary {
            version: 1,
            source: "recorder_events".to_string(),
            bootstrap: self.bootstrap.summary(),
            background: self.background.summary(),
            interpretation: "bootstrap timing and configured background-rule matches are process-traffic evidence; Redis snapshot counts describe recorder reuse, and none of these observations alone prove business ownership or response causality".to_string(),
        }
    }
}

pub(crate) fn load(dir: &Path) -> Result<Option<SourceProcessTrafficSummary>> {
    let path = dir.join(SUMMARY_FILENAME);
    match std::fs::read(&path) {
        Ok(payload) => serde_json::from_slice(&payload)
            .with_context(|| format!("invalid source process traffic summary {}", path.display()))
            .map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to read source process traffic summary {}",
                path.display()
            )
        }),
    }
}

impl TrafficScopeBuilder {
    fn observe(&mut self, interaction: Option<&Interaction>, limit: usize) {
        self.events = self.events.saturating_add(1);
        let Some(interaction) = interaction else {
            self.excluded_events = self.excluded_events.saturating_add(1);
            return;
        };
        self.data_interactions = self.data_interactions.saturating_add(1);
        let Some(key) = observation_key(interaction) else {
            self.unresolved_interactions = self.unresolved_interactions.saturating_add(1);
            return;
        };
        self.observations.observe(key, limit);
    }

    fn summary(&self) -> SourceProcessTrafficScopeSummary {
        SourceProcessTrafficScopeSummary {
            events: self.events,
            data_interactions: self.data_interactions,
            excluded_events: self.excluded_events,
            unresolved_interactions: self.unresolved_interactions,
            observations: self.observations.finish(),
            omitted_interactions: self.observations.omitted_interactions,
            truncated: self.observations.truncated,
        }
    }
}

impl BackgroundBuilder {
    fn observe(
        &mut self,
        event: &RecorderEvent,
        interaction: Option<&Interaction>,
        phase: &str,
        matched_by: &str,
    ) {
        self.events = self.events.saturating_add(1);
        let Some(interaction) = interaction else {
            self.excluded_events = self.excluded_events.saturating_add(1);
            return;
        };
        self.data_interactions = self.data_interactions.saturating_add(1);
        if interaction.endpoint.is_none() {
            self.unresolved_interactions = self.unresolved_interactions.saturating_add(1);
        }
        if !self.rules.contains_key(matched_by) && self.rules.len() >= MAX_BACKGROUND_RULES {
            self.omitted_interactions = self.omitted_interactions.saturating_add(1);
            self.truncated = true;
            return;
        }
        self.rules
            .entry(matched_by.to_string())
            .or_default()
            .observe(event, interaction, phase);
    }

    fn summary(&self) -> SourceProcessBackgroundSummary {
        let mut rules = self
            .rules
            .iter()
            .map(|(name, rule)| rule.summary(name))
            .collect::<Vec<_>>();
        rules.sort_by(|left, right| {
            right
                .interactions
                .cmp(&left.interactions)
                .then_with(|| left.name.cmp(&right.name))
        });
        SourceProcessBackgroundSummary {
            events: self.events,
            data_interactions: self.data_interactions,
            excluded_events: self.excluded_events,
            unresolved_interactions: self.unresolved_interactions,
            rules,
            omitted_interactions: self.omitted_interactions,
            truncated: self.truncated,
        }
    }
}

impl BackgroundRuleBuilder {
    fn observe(&mut self, event: &RecorderEvent, interaction: &Interaction, phase: &str) {
        self.interactions = self.interactions.saturating_add(1);
        match phase {
            "bootstrap" => {
                self.bootstrap_interactions = self.bootstrap_interactions.saturating_add(1)
            }
            "runtime" => self.runtime_interactions = self.runtime_interactions.saturating_add(1),
            _ => self.other_phase_interactions = self.other_phase_interactions.saturating_add(1),
        }
        if let Some(key) = observation_key(interaction) {
            self.observations.observe(key, MAX_RULE_OBSERVATIONS);
        } else {
            self.unresolved_interactions = self.unresolved_interactions.saturating_add(1);
        }
        if let Some(snapshot) = snapshot_observation(event) {
            self.redis_snapshot
                .get_or_insert_default()
                .observe(interaction.endpoint.as_deref(), snapshot);
        }
    }

    fn summary(&self, name: &str) -> SourceProcessBackgroundRuleSummary {
        SourceProcessBackgroundRuleSummary {
            name: name.to_string(),
            interactions: self.interactions,
            bootstrap_interactions: self.bootstrap_interactions,
            runtime_interactions: self.runtime_interactions,
            other_phase_interactions: self.other_phase_interactions,
            unresolved_interactions: self.unresolved_interactions,
            observations: self.observations.finish(),
            omitted_interactions: self.observations.omitted_interactions,
            truncated: self.observations.truncated,
            redis_snapshot: self
                .redis_snapshot
                .as_ref()
                .map(RedisSnapshotBuilder::summary),
        }
    }
}

impl RedisSnapshotBuilder {
    fn observe(&mut self, endpoint: Option<&str>, observation: SnapshotObservation) {
        increment_snapshot_counts(
            &mut self.seeds,
            &mut self.reuses,
            &mut self.fill_failures,
            &observation,
        );
        let Some(endpoint) = endpoint else {
            self.omitted_interactions = self.omitted_interactions.saturating_add(1);
            return;
        };
        if !self.endpoints.contains_key(endpoint) && self.endpoints.len() >= MAX_SNAPSHOT_ENDPOINTS
        {
            self.omitted_interactions = self.omitted_interactions.saturating_add(1);
            self.truncated = true;
            return;
        }
        let counts = self.endpoints.entry(endpoint.to_string()).or_default();
        increment_snapshot_counts(
            &mut counts.seeds,
            &mut counts.reuses,
            &mut counts.fill_failures,
            &observation,
        );
    }

    fn summary(&self) -> SourceProcessRedisSnapshotSummary {
        let mut endpoints = self
            .endpoints
            .iter()
            .map(
                |(endpoint, counts)| SourceProcessRedisSnapshotEndpointSummary {
                    endpoint: endpoint.clone(),
                    seeds: counts.seeds,
                    reuses: counts.reuses,
                    fill_failures: counts.fill_failures,
                },
            )
            .collect::<Vec<_>>();
        endpoints.sort_by(|left, right| {
            let left_total = left
                .seeds
                .saturating_add(left.reuses)
                .saturating_add(left.fill_failures);
            let right_total = right
                .seeds
                .saturating_add(right.reuses)
                .saturating_add(right.fill_failures);
            right_total
                .cmp(&left_total)
                .then_with(|| left.endpoint.cmp(&right.endpoint))
        });
        SourceProcessRedisSnapshotSummary {
            seeds: self.seeds,
            reuses: self.reuses,
            fill_failures: self.fill_failures,
            endpoints,
            omitted_interactions: self.omitted_interactions,
            truncated: self.truncated,
        }
    }
}

fn increment_snapshot_counts(
    seeds: &mut u64,
    reuses: &mut u64,
    fill_failures: &mut u64,
    observation: &SnapshotObservation,
) {
    match observation {
        SnapshotObservation::Seed => *seeds = seeds.saturating_add(1),
        SnapshotObservation::Reuse => *reuses = reuses.saturating_add(1),
        SnapshotObservation::FillFailure => *fill_failures = fill_failures.saturating_add(1),
    }
}

impl ObservationCounts {
    fn observe(&mut self, key: ObservationKey, limit: usize) {
        if let Some(count) = self.values.get_mut(&key) {
            *count = count.saturating_add(1);
        } else if self.values.len() < limit {
            self.values.insert(key, 1);
        } else {
            self.omitted_interactions = self.omitted_interactions.saturating_add(1);
            self.truncated = true;
        }
    }

    fn finish(&self) -> Vec<SourceProcessTrafficObservation> {
        let mut observations = self
            .values
            .iter()
            .map(|(key, interactions)| SourceProcessTrafficObservation {
                protocol: key.protocol.clone(),
                endpoint: key.endpoint.clone(),
                operation: key.operation.clone(),
                interactions: *interactions,
            })
            .collect::<Vec<_>>();
        observations.sort_by(|left, right| {
            right
                .interactions
                .cmp(&left.interactions)
                .then_with(|| left.protocol.cmp(&right.protocol))
                .then_with(|| left.endpoint.cmp(&right.endpoint))
                .then_with(|| left.operation.cmp(&right.operation))
        });
        observations
    }
}

fn observation_key(interaction: &Interaction) -> Option<ObservationKey> {
    Some(ObservationKey {
        protocol: interaction.protocol.to_string(),
        endpoint: interaction.endpoint.clone()?,
        operation: interaction.operation.clone(),
    })
}

fn data_interaction(event: &RecorderEvent) -> Option<Interaction> {
    match event {
        RecorderEvent::HttpExchange(event) => Some(Interaction {
            protocol: "http",
            endpoint: event
                .authority
                .as_deref()
                .and_then(|authority| http_endpoint(authority, &event.scheme)),
            operation: event.method.to_ascii_uppercase(),
        }),
        RecorderEvent::UdpDatagram(event) => Some(Interaction {
            protocol: "udp",
            endpoint: optional_endpoint(
                event.target_host.as_deref(),
                event.target_port,
                event
                    .target_addr
                    .as_deref()
                    .or(event.upstream_addr.as_deref()),
            ),
            operation: event.protocol.clone(),
        }),
        RecorderEvent::RedisExchange(event)
            if !event.session_setup && !event.command.eq_ignore_ascii_case("PING") =>
        {
            Some(Interaction {
                protocol: "redis",
                endpoint: Some(format_endpoint(&event.target_host, event.target_port)),
                operation: event.command.to_ascii_uppercase(),
            })
        }
        RecorderEvent::MemcachedExchange(event)
            if !matches!(
                event.command.to_ascii_lowercase().as_str(),
                "version" | "noop"
            ) =>
        {
            Some(Interaction {
                protocol: "memcached",
                endpoint: Some(format_endpoint(&event.target_host, event.target_port)),
                operation: event.command.to_ascii_lowercase(),
            })
        }
        RecorderEvent::KafkaProduce(event) => Some(Interaction {
            protocol: "kafka",
            endpoint: Some(format_endpoint(&event.target_host, event.target_port)),
            operation: "produce".to_string(),
        }),
        RecorderEvent::KafkaFetch(event) => Some(Interaction {
            protocol: "kafka",
            endpoint: Some(format_endpoint(&event.target_host, event.target_port)),
            operation: "fetch".to_string(),
        }),
        RecorderEvent::MotanExchange(event) if !event.heartbeat => Some(Interaction {
            protocol: "motan",
            endpoint: Some(format_endpoint(&event.target_host, event.target_port)),
            operation: event
                .method_name
                .as_deref()
                .unwrap_or(&event.command)
                .to_string(),
        }),
        RecorderEvent::MysqlExchange(event)
            if !is_mysql_maintenance_exchange(&event.command, event.sql.as_deref()) =>
        {
            Some(Interaction {
                protocol: "mysql",
                endpoint: optional_endpoint(
                    event.target_host.as_deref(),
                    event.target_port,
                    event
                        .target_addr
                        .as_deref()
                        .or(event.upstream_addr.as_deref()),
                ),
                operation: event.command.to_ascii_uppercase(),
            })
        }
        _ => None,
    }
}

fn snapshot_observation(event: &RecorderEvent) -> Option<SnapshotObservation> {
    let RecorderEvent::RedisExchange(event) = event else {
        return None;
    };
    event.cache_snapshot_rule.as_ref()?;
    if event.cache_snapshot_hit {
        return Some(SnapshotObservation::Reuse);
    }
    if event.outcome == DependencyExchangeOutcome::Response && event.response_kind != "error" {
        Some(SnapshotObservation::Seed)
    } else {
        Some(SnapshotObservation::FillFailure)
    }
}

fn optional_endpoint(
    host: Option<&str>,
    port: Option<u16>,
    fallback: Option<&str>,
) -> Option<String> {
    host.zip(port)
        .map(|(host, port)| format_endpoint(host, port))
        .or_else(|| fallback.and_then(normalize_endpoint))
}

fn http_endpoint(authority: &str, scheme: &str) -> Option<String> {
    let authority = authority.parse::<Authority>().ok()?;
    let port = authority.port_u16().or(match scheme {
        "http" => Some(80),
        "https" => Some(443),
        _ => None,
    })?;
    Some(format_endpoint(authority.host(), port))
}

fn normalize_endpoint(value: &str) -> Option<String> {
    let authority = value.parse::<Authority>().ok()?;
    Some(format_endpoint(authority.host(), authority.port_u16()?))
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
#[path = "source_process/tests.rs"]
mod tests;
