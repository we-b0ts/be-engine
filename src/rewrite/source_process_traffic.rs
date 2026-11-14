use std::collections::BTreeSet;
use std::path::Path;

use serde::Serialize;

use super::model::RewriteState;
use crate::recorder::load_source_process_traffic_summary;

const MAX_BOOTSTRAP_OBSERVATIONS: usize = 16;
const MAX_PROCESS_OWNED_RULES: usize = 16;
const MAX_RULE_OBSERVATIONS: usize = 8;
const MAX_SNAPSHOT_ENDPOINTS: usize = 16;

#[derive(Debug, Clone, Serialize)]
pub struct RewriteSourceProcessTrafficView {
    pub available: bool,
    pub scope: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bootstrap: Option<RewriteSourceProcessTrafficScopeView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_owned: Option<RewriteSourceProcessOwnedView>,
    pub interpretation: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteSourceProcessTrafficScopeView {
    pub events: u64,
    pub data_interactions: u64,
    pub excluded_events: u64,
    pub unresolved_interactions: u64,
    pub protocols: Vec<String>,
    pub observations: Vec<RewriteSourceProcessObservationView>,
    pub omitted_observations: usize,
    pub omitted_interactions: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteSourceProcessObservationView {
    pub protocol: String,
    pub endpoint: String,
    pub operation: String,
    pub interactions: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteSourceProcessOwnedView {
    pub events: u64,
    pub data_interactions: u64,
    pub excluded_events: u64,
    pub unresolved_interactions: u64,
    pub rules_total: usize,
    pub rules: Vec<RewriteSourceProcessOwnedRuleView>,
    pub omitted_rules: usize,
    pub omitted_interactions: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteSourceProcessOwnedRuleView {
    pub name: String,
    pub interactions: u64,
    pub bootstrap_interactions: u64,
    pub runtime_interactions: u64,
    pub other_phase_interactions: u64,
    pub unresolved_interactions: u64,
    pub observations: Vec<RewriteSourceProcessObservationView>,
    pub omitted_observations: usize,
    pub omitted_interactions: u64,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redis_snapshot: Option<RewriteSourceProcessRedisSnapshotView>,
    #[serde(flatten)]
    pub native: std::collections::BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteSourceProcessRedisSnapshotView {
    pub seeds: u64,
    pub reuses: u64,
    pub fill_failures: u64,
    pub endpoints: Vec<RewriteSourceProcessRedisSnapshotEndpointView>,
    pub omitted_endpoints: usize,
    pub omitted_interactions: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteSourceProcessRedisSnapshotEndpointView {
    pub endpoint: String,
    pub seeds: u64,
    pub reuses: u64,
    pub fill_failures: u64,
}

pub(super) fn evidence_view(
    target_root: &Path,
    state: &RewriteState,
) -> RewriteSourceProcessTrafficView {
    let Some(case_source) = state.case_source.as_deref() else {
        return unavailable("the rewrite workflow has no finalized standard recording");
    };
    let case_source = if case_source.is_absolute() {
        case_source.to_path_buf()
    } else {
        target_root.join(case_source)
    };
    match load_source_process_traffic_summary(&case_source) {
        Ok(Some(summary)) => {
            let snapshots = summary
                .background
                .rules
                .iter()
                .map(|rule| {
                    rule.native
                        .get("redis_snapshot")
                        .map(|snapshot| {
                            serde_json::from_value::<
                                traffic_protocol_redis::process_summary::SnapshotSummary,
                            >(snapshot.clone())
                        })
                        .transpose()
                })
                .collect::<Result<Vec<_>, _>>();
            let snapshots = match snapshots {
                Ok(snapshots) => snapshots,
                Err(error) => {
                    return unavailable(&format!("invalid native process summary: {error}"));
                }
            };
            let bootstrap_observations_total = summary.bootstrap.observations.len();
            let bootstrap_protocols = summary
                .bootstrap
                .observations
                .iter()
                .map(|observation| observation.protocol.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            let bootstrap = RewriteSourceProcessTrafficScopeView {
                events: summary.bootstrap.events,
                data_interactions: summary.bootstrap.data_interactions,
                excluded_events: summary.bootstrap.excluded_events,
                unresolved_interactions: summary.bootstrap.unresolved_interactions,
                protocols: bootstrap_protocols,
                observations: summary
                    .bootstrap
                    .observations
                    .iter()
                    .take(MAX_BOOTSTRAP_OBSERVATIONS)
                    .map(observation_view)
                    .collect(),
                omitted_observations: bootstrap_observations_total
                    .saturating_sub(MAX_BOOTSTRAP_OBSERVATIONS),
                omitted_interactions: summary.bootstrap.omitted_interactions,
                truncated: summary.bootstrap.truncated
                    || bootstrap_observations_total > MAX_BOOTSTRAP_OBSERVATIONS,
            };
            let rules_total = summary.background.rules.len();
            let rules = summary
                .background
                .rules
                .iter()
                .take(MAX_PROCESS_OWNED_RULES)
                .enumerate()
                .map(|(index, rule)| {
                    let observations_total = rule.observations.len();
                    RewriteSourceProcessOwnedRuleView {
                        name: rule.name.clone(),
                        interactions: rule.interactions,
                        bootstrap_interactions: rule.bootstrap_interactions,
                        runtime_interactions: rule.runtime_interactions,
                        other_phase_interactions: rule.other_phase_interactions,
                        unresolved_interactions: rule.unresolved_interactions,
                        observations: rule
                            .observations
                            .iter()
                            .take(MAX_RULE_OBSERVATIONS)
                            .map(observation_view)
                            .collect(),
                        omitted_observations: observations_total
                            .saturating_sub(MAX_RULE_OBSERVATIONS),
                        omitted_interactions: rule.omitted_interactions,
                        truncated: rule.truncated || observations_total > MAX_RULE_OBSERVATIONS,
                        native: rule
                            .native
                            .iter()
                            .filter(|(name, _)| name.as_str() != "redis_snapshot")
                            .map(|(name, value)| (name.clone(), value.clone()))
                            .collect(),
                        redis_snapshot: snapshots[index].as_ref().map(|snapshot| {
                            let endpoints_total = snapshot.endpoints.len();
                            RewriteSourceProcessRedisSnapshotView {
                                seeds: snapshot.seeds,
                                reuses: snapshot.reuses,
                                fill_failures: snapshot.fill_failures,
                                endpoints: snapshot
                                    .endpoints
                                    .iter()
                                    .take(MAX_SNAPSHOT_ENDPOINTS)
                                    .map(|endpoint| RewriteSourceProcessRedisSnapshotEndpointView {
                                        endpoint: endpoint.endpoint.clone(),
                                        seeds: endpoint.seeds,
                                        reuses: endpoint.reuses,
                                        fill_failures: endpoint.fill_failures,
                                    })
                                    .collect(),
                                omitted_endpoints: endpoints_total
                                    .saturating_sub(MAX_SNAPSHOT_ENDPOINTS),
                                omitted_interactions: snapshot.omitted_interactions,
                                truncated: snapshot.truncated
                                    || endpoints_total > MAX_SNAPSHOT_ENDPOINTS,
                            }
                        }),
                    }
                })
                .collect();
            RewriteSourceProcessTrafficView {
                available: true,
                scope: "recording_global",
                reason: None,
                bootstrap: Some(bootstrap),
                process_owned: Some(RewriteSourceProcessOwnedView {
                    events: summary.background.events,
                    data_interactions: summary.background.data_interactions,
                    excluded_events: summary.background.excluded_events,
                    unresolved_interactions: summary.background.unresolved_interactions,
                    rules_total,
                    rules,
                    omitted_rules: rules_total.saturating_sub(MAX_PROCESS_OWNED_RULES),
                    omitted_interactions: summary.background.omitted_interactions,
                    truncated: summary.background.truncated
                        || rules_total > MAX_PROCESS_OWNED_RULES,
                }),
                interpretation: "bootstrap observations do not prove ownership; configured process-owned rule matches identify only declared process scope, and neither replaces request-owned target behavior or proves response causality".to_string(),
            }
        }
        Ok(None) => {
            unavailable("the selected standard recording predates source process traffic summaries")
        }
        Err(_) => unavailable(
            "the selected standard recording has an unreadable source process traffic summary",
        ),
    }
}

fn observation_view(
    observation: &crate::recorder::SourceProcessTrafficObservation,
) -> RewriteSourceProcessObservationView {
    RewriteSourceProcessObservationView {
        protocol: observation.protocol.clone(),
        endpoint: observation.endpoint.clone(),
        operation: observation.operation.clone(),
        interactions: observation.interactions,
    }
}

fn unavailable(reason: &str) -> RewriteSourceProcessTrafficView {
    RewriteSourceProcessTrafficView {
        available: false,
        scope: "recording_global",
        reason: Some(reason.to_string()),
        bootstrap: None,
        process_owned: None,
        interpretation: "source process traffic is a triage hint, not proof of business ownership or response causality".to_string(),
    }
}

#[cfg(test)]
#[path = "source_process_traffic/tests.rs"]
mod tests;
