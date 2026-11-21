//! Native recorder snapshot observations and bounded endpoint counters.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use traffic_protocol::observation::NativeSummary;

const MAX_SNAPSHOT_ENDPOINTS: usize = 128;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SnapshotSummary {
    pub seeds: u64,
    pub reuses: u64,
    pub fill_failures: u64,
    pub endpoints: Vec<SnapshotEndpointSummary>,
    pub omitted_interactions: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotEndpointSummary {
    pub endpoint: String,
    pub seeds: u64,
    pub reuses: u64,
    pub fill_failures: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotView {
    pub seeds: u64,
    pub reuses: u64,
    pub fill_failures: u64,
    pub endpoints: Vec<SnapshotEndpointSummary>,
    pub omitted_endpoints: usize,
    pub omitted_interactions: u64,
    pub truncated: bool,
}

impl SnapshotSummary {
    pub fn view(&self, detail_limit: usize) -> SnapshotView {
        SnapshotView {
            seeds: self.seeds,
            reuses: self.reuses,
            fill_failures: self.fill_failures,
            endpoints: self.endpoints.iter().take(detail_limit).cloned().collect(),
            omitted_endpoints: self.endpoints.len().saturating_sub(detail_limit),
            omitted_interactions: self.omitted_interactions,
            truncated: self.truncated || self.endpoints.len() > detail_limit,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SnapshotAccumulator {
    seeds: u64,
    reuses: u64,
    fill_failures: u64,
    endpoints: BTreeMap<String, EndpointCounts>,
    omitted_interactions: u64,
    truncated: bool,
}

#[derive(Debug, Clone, Default)]
struct EndpointCounts {
    seeds: u64,
    reuses: u64,
    fill_failures: u64,
}

enum SnapshotObservation {
    Seed,
    Reuse,
    FillFailure,
}

impl SnapshotAccumulator {
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

    fn summary(&self) -> SnapshotSummary {
        let mut endpoints = self
            .endpoints
            .iter()
            .map(|(endpoint, counts)| SnapshotEndpointSummary {
                endpoint: endpoint.clone(),
                seeds: counts.seeds,
                reuses: counts.reuses,
                fill_failures: counts.fill_failures,
            })
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
        SnapshotSummary {
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

impl NativeSummary for SnapshotAccumulator {
    fn observe(&mut self, event: &Value, endpoint: Option<&str>) {
        let observation = if event["cache_snapshot_hit"] == true {
            SnapshotObservation::Reuse
        } else if serde_json::from_value::<traffic_model::DependencyExchangeOutcome>(
            event["outcome"].clone(),
        )
        .ok()
            == Some(traffic_model::DependencyExchangeOutcome::Response)
            && event["response_kind"] != "error"
        {
            SnapshotObservation::Seed
        } else {
            SnapshotObservation::FillFailure
        };
        self.observe(endpoint, observation);
    }
    fn value(&self) -> Value {
        serde_json::to_value(self.summary()).expect("native snapshot summary is serializable")
    }
}

#[cfg(test)]
mod view_tests {
    use super::*;
    use traffic_protocol::evidence::EvidenceRegistry;

    #[test]
    fn installed_summary_projection_preserves_native_counts_and_reports_omitted_endpoints() {
        let mut registry = EvidenceRegistry::default();
        registry
            .register(
                "redis",
                std::sync::Arc::new(crate::evidence::NativeEvidence),
            )
            .unwrap();
        let summary = SnapshotSummary {
            seeds: 8,
            reuses: 5,
            fill_failures: 3,
            endpoints: (0..3)
                .map(|index| SnapshotEndpointSummary {
                    endpoint: format!("cache-{index}:6379"),
                    seeds: 1,
                    reuses: 2,
                    fill_failures: 3,
                })
                .collect(),
            omitted_interactions: 7,
            truncated: false,
        };
        let values = BTreeMap::from([(
            "redis_snapshot".into(),
            serde_json::to_value(&summary).unwrap(),
        )]);
        let projected = registry.process_summary_views(&values, 1).unwrap();
        let view = &projected["redis_snapshot"];
        assert_eq!(view["seeds"], 8);
        assert_eq!(view["reuses"], 5);
        assert_eq!(view["fill_failures"], 3);
        assert_eq!(view["endpoints"].as_array().unwrap().len(), 1);
        assert_eq!(view["omitted_endpoints"], 2);
        assert_eq!(view["omitted_interactions"], 7);
        assert_eq!(view["truncated"], true);
        assert_eq!(summary.endpoints.len(), 3);
        let complete = registry.process_summary_views(&values, 3).unwrap();
        assert_eq!(complete["redis_snapshot"]["truncated"], false);
        assert_eq!(complete["redis_snapshot"]["omitted_endpoints"], 0);
        assert!(
            registry
                .process_summary_views(
                    &BTreeMap::from([("redis_snapshot".into(), serde_json::json!({}))]),
                    1
                )
                .is_err()
        );
    }
}
