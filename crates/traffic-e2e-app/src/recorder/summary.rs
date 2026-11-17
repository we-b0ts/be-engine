//! Shared recording event counters, authenticated summary persistence and process aggregation.
use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;
use std::{collections::BTreeMap, path::Path, sync::Arc};
use traffic_protocol::{
    capture::CaptureEvidence,
    evidence::{EvidenceRegistry, RecordingSummaries},
};
mod persistence;
pub(crate) use persistence::refresh_owned_dependency_indexes;
use persistence::write_dependency_summary;
mod pre_readiness;
mod source_process;
pub(crate) use source_process::SourceProcessTrafficObservation;
pub(crate) fn should_append_case_dependency(event: &impl CaptureEvidence) -> bool {
    event.capture_facts().case_dependency
}

pub(crate) async fn write_case_dependency_summary(
    dir: &Path,
    evidence: Arc<EvidenceRegistry>,
) -> Result<()> {
    write_dependency_summary(
        dir,
        "dependencies.jsonl",
        "dependencies-summary.json",
        evidence,
    )
    .await
}

pub(crate) async fn write_global_dependency_summary(
    dir: &Path,
    evidence: Arc<EvidenceRegistry>,
) -> Result<()> {
    write_dependency_summary(
        dir,
        "global-dependencies.jsonl",
        "global-dependencies-summary.json",
        evidence.clone(),
    )
    .await?;
    pre_readiness::write(dir, evidence).await
}

pub(crate) fn load_pre_readiness_traffic_summary(
    dir: &Path,
    evidence: &EvidenceRegistry,
) -> Result<Option<pre_readiness::PreReadinessTrafficSummary>> {
    pre_readiness::load_or_build(dir, evidence)
}

pub(crate) fn load_source_process_traffic_summary(
    dir: &Path,
) -> Result<Option<source_process::SourceProcessTrafficSummary>> {
    source_process::load(dir)
}

#[derive(Debug, Serialize)]
struct DependencySummary {
    version: u8,
    source: &'static str,
    total_events: usize,
    event_types: BTreeMap<String, usize>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    parse_errors: Vec<String>,
    #[serde(flatten)]
    native: BTreeMap<String, Value>,
}
struct DependencySummaryBuilder {
    total_events: usize,
    event_types: BTreeMap<String, usize>,
    parse_errors: Vec<String>,
    native: RecordingSummaries,
}
impl DependencySummaryBuilder {
    fn new(evidence: EvidenceRegistry) -> Self {
        Self {
            total_events: 0,
            event_types: BTreeMap::new(),
            parse_errors: vec![],
            native: RecordingSummaries::new(evidence),
        }
    }
    fn observe(&mut self, value: &Value) {
        if !self.native.observe(value) {
            return;
        }
        self.total_events += 1;
        let event_type = value["event_type"].as_str().unwrap_or("unknown");
        *self.event_types.entry(event_type.into()).or_default() += 1;
    }
    fn finish(self) -> Result<DependencySummary> {
        Ok(DependencySummary {
            version: 1,
            source: "dependencies.jsonl",
            total_events: self.total_events,
            event_types: self.event_types,
            parse_errors: self.parse_errors,
            native: self.native.finish()?,
        })
    }
}
#[cfg(test)]
pub(crate) fn build_dependency_summary(raw: &str) -> Value {
    let mut builder =
        DependencySummaryBuilder::new(crate::protocols::default_providers().evidence().clone());
    for (index, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str(line) {
            Ok(event) => builder.observe(&event),
            Err(error) => builder
                .parse_errors
                .push(format!("line {}: {error}", index + 1)),
        }
    }
    serde_json::to_value(builder.finish().unwrap()).unwrap()
}
