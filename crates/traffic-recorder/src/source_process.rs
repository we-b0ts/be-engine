use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::CapturedEvent;
use std::sync::Arc;
use traffic_protocol::{
    evidence::EvidenceRegistry,
    observation::{NativeSummaries, TrafficInteraction as Interaction},
};

pub const SUMMARY_FILENAME: &str = "source-process-traffic-summary.json";

const MAX_OBSERVATIONS: usize = 512;
const MAX_BACKGROUND_RULES: usize = 256;
const MAX_RULE_OBSERVATIONS: usize = 128;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceProcessTrafficSummary {
    pub version: u8,
    pub source: String,
    pub bootstrap: SourceProcessTrafficScopeSummary,
    pub background: SourceProcessBackgroundSummary,
    pub interpretation: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SourceProcessTrafficScopeSummary {
    pub events: u64,
    pub data_interactions: u64,
    pub excluded_events: u64,
    pub unresolved_interactions: u64,
    pub observations: Vec<SourceProcessTrafficObservation>,
    pub omitted_interactions: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceProcessTrafficObservation {
    pub protocol: String,
    pub endpoint: String,
    pub operation: String,
    pub interactions: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SourceProcessBackgroundSummary {
    pub events: u64,
    pub data_interactions: u64,
    pub excluded_events: u64,
    pub unresolved_interactions: u64,
    pub rules: Vec<SourceProcessBackgroundRuleSummary>,
    pub omitted_interactions: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceProcessBackgroundRuleSummary {
    pub name: String,
    pub interactions: u64,
    pub bootstrap_interactions: u64,
    pub runtime_interactions: u64,
    pub other_phase_interactions: u64,
    pub unresolved_interactions: u64,
    pub observations: Vec<SourceProcessTrafficObservation>,
    pub omitted_interactions: u64,
    pub truncated: bool,
    #[serde(flatten)]
    pub native: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug)]
pub struct SourceProcessTrafficSummaryBuilder {
    evidence: Arc<EvidenceRegistry>,
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

#[derive(Debug, Default)]
struct BackgroundBuilder {
    events: u64,
    data_interactions: u64,
    excluded_events: u64,
    unresolved_interactions: u64,
    rules: BTreeMap<String, BackgroundRuleBuilder>,
    omitted_interactions: u64,
    truncated: bool,
}

#[derive(Debug, Default)]
struct BackgroundRuleBuilder {
    interactions: u64,
    bootstrap_interactions: u64,
    runtime_interactions: u64,
    other_phase_interactions: u64,
    unresolved_interactions: u64,
    observations: ObservationCounts,
    native: NativeSummaries,
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

impl SourceProcessTrafficSummaryBuilder {
    pub fn new(evidence: Arc<EvidenceRegistry>) -> Self {
        Self {
            evidence,
            bootstrap: Default::default(),
            background: Default::default(),
        }
    }

    pub fn observe(
        &mut self,
        event: &CapturedEvent,
        reason: &str,
        phase: &str,
        matched_by: &str,
    ) -> Result<()> {
        let interaction = self.evidence.interaction(event.payload());
        if phase == "bootstrap" {
            self.bootstrap
                .observe(interaction.as_ref(), MAX_OBSERVATIONS);
        }
        if reason == "background_rule" {
            self.background.observe(
                event,
                interaction.as_ref(),
                phase,
                matched_by,
                &self.evidence,
            )?;
        }
        Ok(())
    }

    pub async fn write(&self, dir: &Path) -> Result<()> {
        let mut payload = serde_json::to_vec_pretty(&self.summary())
            .context("failed to serialize source process traffic summary")?;
        payload.push(b'\n');
        crate::storage::write(&dir.join(SUMMARY_FILENAME), &payload)
            .await
            .context("failed to write source process traffic summary")
    }

    pub fn summary(&self) -> SourceProcessTrafficSummary {
        SourceProcessTrafficSummary {
            version: 1,
            source: "recorder_events".to_string(),
            bootstrap: self.bootstrap.summary(),
            background: self.background.summary(),
            interpretation: "bootstrap timing and configured background-rule matches are process-traffic evidence; Redis snapshot counts describe recorder reuse, and none of these observations alone prove business ownership or response causality".to_string(),
        }
    }
}

pub fn load(dir: &Path) -> Result<Option<SourceProcessTrafficSummary>> {
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
        event: &CapturedEvent,
        interaction: Option<&Interaction>,
        phase: &str,
        matched_by: &str,
        evidence: &EvidenceRegistry,
    ) -> Result<()> {
        self.events = self.events.saturating_add(1);
        let Some(interaction) = interaction else {
            self.excluded_events = self.excluded_events.saturating_add(1);
            return Ok(());
        };
        self.data_interactions = self.data_interactions.saturating_add(1);
        if interaction.endpoint.is_none() {
            self.unresolved_interactions = self.unresolved_interactions.saturating_add(1);
        }
        if !self.rules.contains_key(matched_by) && self.rules.len() >= MAX_BACKGROUND_RULES {
            self.omitted_interactions = self.omitted_interactions.saturating_add(1);
            self.truncated = true;
            return Ok(());
        }
        self.rules
            .entry(matched_by.to_string())
            .or_default()
            .observe(event, interaction, phase, evidence)?;
        Ok(())
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
    fn observe(
        &mut self,
        event: &CapturedEvent,
        interaction: &Interaction,
        phase: &str,
        evidence: &EvidenceRegistry,
    ) -> Result<()> {
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
        evidence.observe_process(
            &mut self.native,
            event.payload(),
            interaction.endpoint.as_deref(),
        )?;
        Ok(())
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
            native: self.native.snapshot(),
        }
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
