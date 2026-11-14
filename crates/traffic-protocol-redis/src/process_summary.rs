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
