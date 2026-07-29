use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;

use crate::breeze::snapshot::{Snapshot, SnapshotResource};

use super::edit::write_atomic;
use super::rule_document::{
    array_table_ranges, assignment_count, find_managed_block, managed_block_diff, newline,
    parse_and_validate,
};
use super::{AppConfig, DnsBypassStrategyConfig};

const TABLE_HEADER: &str = "[[dns_mock.bypass_strategies]]";
const FIELD: &str = "capture_resources";
const BEGIN_MARKER: &str = "# BEGIN AI-MANAGED BREEZE CAPTURE RESOURCES";
const END_MARKER: &str = "# END AI-MANAGED BREEZE CAPTURE RESOURCES";

#[derive(Debug, Clone)]
pub struct BreezeResourceCaptureFeedback {
    pub config_path: PathBuf,
    pub resource: String,
    pub source_revision: String,
    pub source_evidence: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BreezeResourceCaptureReport {
    pub config: PathBuf,
    pub snapshot_dir: PathBuf,
    pub requested_resource: String,
    pub resource: String,
    pub resource_identity: String,
    pub descriptor: PathBuf,
    pub domains: Vec<String>,
    pub shared_domain_resources: Vec<String>,
    pub source_revision: String,
    pub source_evidence: String,
    pub capture_resources_before: Vec<String>,
    pub capture_resources_after: Vec<String>,
    pub changed: bool,
    pub applied: bool,
    pub diff: String,
}

#[derive(Debug)]
pub struct BreezeResourceCapturePlan {
    config_path: PathBuf,
    original_config: String,
    updated_config: String,
    snapshot_dir: PathBuf,
    expected_resource: SnapshotResource,
    report: BreezeResourceCaptureReport,
}

impl BreezeResourceCapturePlan {
    pub fn report(&self) -> &BreezeResourceCaptureReport {
        &self.report
    }

    pub fn apply(self) -> Result<BreezeResourceCaptureReport> {
        let current = read_config(&self.config_path)?;
        ensure!(
            current == self.original_config,
            "recorder config changed after planning; rerun plan before applying"
        );
        let snapshot = Snapshot::load(&self.snapshot_dir)?;
        let resource = snapshot.resolve(&self.expected_resource.identity)?;
        ensure!(
            resource == &self.expected_resource,
            "Breeze snapshot resource changed after planning; rerun plan before applying"
        );
        if self.report.changed {
            write_atomic(&self.config_path, self.updated_config.as_bytes())?;
        }
        let mut report = self.report;
        report.applied = true;
        Ok(report)
    }
}

pub fn plan_breeze_resource_capture(
    feedback: BreezeResourceCaptureFeedback,
) -> Result<BreezeResourceCapturePlan> {
    validate_feedback(&feedback)?;
    ensure_regular_config(&feedback.config_path)?;
    let original = read_config(&feedback.config_path)?;
    let config = parse_and_validate(&original, &feedback.config_path)?;
    let candidate = resolve_candidate(&config, &feedback.resource)?;
    ensure!(
        !candidate.resource.domains.is_empty(),
        "Breeze resource {:?} has no hostname backend; IP literals are not part of DNS bypass and cannot be enabled by this strategy",
        candidate.resource.identity
    );

    let ranges = array_table_ranges(&original, TABLE_HEADER);
    ensure!(
        ranges.len() == config.dns_mock.bypass_strategies.len(),
        "could not associate parsed DNS bypass strategies with their source ranges"
    );
    let strategy_range = ranges[candidate.strategy_index].clone();
    let strategy_source = &original[strategy_range.clone()];
    let managed = find_managed_block(
        &original,
        &strategy_range,
        BEGIN_MARKER,
        END_MARKER,
        "Breeze capture resources",
    )?;
    let total_assignments = assignment_count(strategy_source, FIELD);
    let block = match managed {
        Some(block) => {
            ensure!(
                total_assignments == 1 && assignment_count(&original[block.clone()], FIELD) == 1,
                "{FIELD} must be owned exclusively by its AI-managed block"
            );
            block
        }
        None => {
            ensure!(
                total_assignments == 0,
                "existing {FIELD} must be enclosed by its AI-managed block"
            );
            strategy_range.end..strategy_range.end
        }
    };

    let before = candidate
        .capture_resources
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut after = before.clone();
    after.insert(candidate.resource.identity.clone());
    validate_existing_resources(&candidate.snapshot, &after)?;

    let old_block = &original[block.clone()];
    let new_block = render_managed_block(
        &after,
        newline(&original),
        old_block.is_empty() || old_block.ends_with('\n'),
    );
    let mut updated = String::with_capacity(original.len() + new_block.len());
    updated.push_str(&original[..block.start]);
    updated.push_str(&new_block);
    updated.push_str(&original[block.end..]);
    parse_and_validate(&updated, &feedback.config_path)
        .context("generated recorder config failed validation")?;

    let changed = updated != original;
    let diff = if changed {
        managed_block_diff(
            &feedback.config_path,
            &original,
            block.start,
            old_block,
            &new_block,
        )
    } else {
        String::new()
    };
    let shared_domain_resources = shared_domain_resources(&candidate.snapshot, &candidate.resource);

    Ok(BreezeResourceCapturePlan {
        config_path: feedback.config_path.clone(),
        original_config: original,
        updated_config: updated,
        snapshot_dir: candidate.snapshot_dir.clone(),
        expected_resource: candidate.resource.clone(),
        report: BreezeResourceCaptureReport {
            config: feedback.config_path,
            snapshot_dir: candidate.snapshot_dir,
            requested_resource: feedback.resource,
            resource: candidate.resource.name.clone(),
            resource_identity: candidate.resource.identity.clone(),
            descriptor: candidate.resource.descriptor_path.clone(),
            domains: candidate.resource.domains.iter().cloned().collect(),
            shared_domain_resources,
            source_revision: feedback.source_revision,
            source_evidence: feedback.source_evidence,
            capture_resources_before: before.into_iter().collect(),
            capture_resources_after: after.into_iter().collect(),
            changed,
            applied: false,
            diff,
        },
    })
}

struct Candidate {
    strategy_index: usize,
    snapshot_dir: PathBuf,
    capture_resources: Vec<String>,
    snapshot: Snapshot,
    resource: SnapshotResource,
}

struct LoadedStrategy {
    strategy_index: usize,
    snapshot_dir: PathBuf,
    capture_resources: Vec<String>,
    snapshot: Snapshot,
}

fn resolve_candidate(config: &AppConfig, selector: &str) -> Result<Candidate> {
    let mut loaded = Vec::new();
    for (strategy_index, strategy) in config.dns_mock.bypass_strategies.iter().enumerate() {
        let DnsBypassStrategyConfig::Breeze {
            snapshot_dir,
            capture_resources,
        } = strategy;
        loaded.push(LoadedStrategy {
            strategy_index,
            snapshot_dir: snapshot_dir.clone(),
            capture_resources: capture_resources.clone(),
            snapshot: Snapshot::load(snapshot_dir)?,
        });
    }

    let mut exact = Vec::new();
    let mut named = Vec::new();
    for (loaded_index, strategy) in loaded.iter().enumerate() {
        for (resource_index, resource) in strategy.snapshot.resources().iter().enumerate() {
            if resource.identity == selector {
                exact.push((loaded_index, resource_index));
            } else if resource.name == selector {
                named.push((loaded_index, resource_index));
            }
        }
    }
    let matches = if exact.is_empty() { named } else { exact };
    if matches.is_empty() {
        bail!(
            "Breeze resource {selector:?} does not exist in any configured snapshot bypass strategy"
        );
    }
    if matches.len() > 1 {
        let identities = matches
            .iter()
            .map(|(strategy, resource)| {
                loaded[*strategy].snapshot.resources()[*resource]
                    .identity
                    .as_str()
            })
            .collect::<Vec<_>>()
            .join(", ");
        bail!(
            "Breeze resource {selector:?} is ambiguous; use one exact descriptor identity: {identities}"
        );
    }

    let (loaded_index, resource_index) = matches[0];
    let selected = loaded.swap_remove(loaded_index);
    let resource = selected.snapshot.resources()[resource_index].clone();
    Ok(Candidate {
        strategy_index: selected.strategy_index,
        snapshot_dir: selected.snapshot_dir,
        capture_resources: selected.capture_resources,
        snapshot: selected.snapshot,
        resource,
    })
}

fn validate_existing_resources(snapshot: &Snapshot, selectors: &BTreeSet<String>) -> Result<()> {
    for selector in selectors {
        let resource = snapshot.resolve(selector)?;
        ensure!(
            !resource.domains.is_empty(),
            "configured Breeze capture resource {:?} contains no hostname backend",
            resource.identity
        );
    }
    Ok(())
}

fn shared_domain_resources(snapshot: &Snapshot, selected: &SnapshotResource) -> Vec<String> {
    snapshot
        .resources()
        .iter()
        .filter(|resource| {
            resource.identity != selected.identity
                && resource
                    .domains
                    .iter()
                    .any(|domain| selected.domains.contains(domain))
        })
        .map(|resource| resource.identity.clone())
        .collect()
}

fn validate_feedback(feedback: &BreezeResourceCaptureFeedback) -> Result<()> {
    validate_single_line("Breeze resource", &feedback.resource, 512)?;
    ensure!(
        !feedback.resource.contains(['/', '\\']),
        "Breeze resource must be a short name or descriptor filename"
    );
    validate_single_line("source revision", &feedback.source_revision, 256)?;
    validate_single_line("source evidence", &feedback.source_evidence, 1_024)?;
    Ok(())
}

fn validate_single_line(label: &str, value: &str, max_len: usize) -> Result<()> {
    ensure!(!value.trim().is_empty(), "{label} must not be empty");
    ensure!(
        value == value.trim() && !value.contains(['\r', '\n']),
        "{label} must be one line without surrounding whitespace"
    );
    ensure!(value.len() <= max_len, "{label} exceeds {max_len} bytes");
    Ok(())
}

fn ensure_regular_config(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect recorder config {}", path.display()))?;
    ensure!(metadata.is_file(), "recorder config must be a regular file");
    ensure!(
        !metadata.file_type().is_symlink(),
        "refusing to replace a symlinked recorder config"
    );
    Ok(())
}

fn read_config(path: &Path) -> Result<String> {
    fs::read_to_string(path)
        .with_context(|| format!("failed to read recorder config {}", path.display()))
}

fn render_managed_block(
    resources: &BTreeSet<String>,
    newline: &str,
    trailing_newline: bool,
) -> String {
    let mut output = String::new();
    push_line(&mut output, BEGIN_MARKER, newline);
    push_line(&mut output, &format!("{FIELD} = ["), newline);
    for resource in resources {
        let quoted = toml::Value::String(resource.clone()).to_string();
        push_line(&mut output, &format!("  {quoted},"), newline);
    }
    push_line(&mut output, "]", newline);
    output.push_str(END_MARKER);
    if trailing_newline {
        output.push_str(newline);
    }
    output
}

fn push_line(output: &mut String, line: &str, newline: &str) {
    let _ = write!(output, "{line}{newline}");
}

#[cfg(test)]
mod tests;
