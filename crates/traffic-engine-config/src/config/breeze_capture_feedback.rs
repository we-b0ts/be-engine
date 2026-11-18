use std::collections::BTreeSet;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr as _;

use anyhow::{Context, Result, bail, ensure};
use hyper::http::uri::Authority;
use serde::Serialize;

use crate::breeze::snapshot::{Snapshot, SnapshotResource};

use super::edit::write_atomic;
use super::rule_document::whole_file_diff;
use super::{
    AppConfig, DnsBypassStrategyConfig, SourceTrafficBreezeCaptureConfig, SourceTrafficPolicyConfig,
};

#[derive(Debug, Clone)]
pub struct BreezeResourceCaptureFeedback {
    pub project_config_path: PathBuf,
    pub rules_path: PathBuf,
    pub resource: String,
    pub source_revision: String,
    pub source_evidence: String,
}

#[derive(Debug, Clone)]
pub struct BreezeEndpointCaptureFeedback {
    pub project_config_path: PathBuf,
    pub rules_path: PathBuf,
    pub endpoint: String,
    pub source_revision: String,
    pub source_evidence: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BreezeResourceCaptureReport {
    pub rules: PathBuf,
    pub snapshot_dir: PathBuf,
    pub requested_resource: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_endpoint: Option<String>,
    pub resource: String,
    pub resource_identity: String,
    pub descriptor: PathBuf,
    pub domains: Vec<String>,
    pub shared_domain_resources: Vec<String>,
    pub source_revision: String,
    pub source_evidence: String,
    pub capture_resources_before: Vec<String>,
    pub capture_resources_after: Vec<String>,
    pub bypassed_domains_before: Vec<String>,
    pub changed: bool,
    pub applied: bool,
    pub diff: String,
}

#[derive(Debug)]
pub struct BreezeResourceCapturePlan {
    project_config_path: PathBuf,
    rules_path: PathBuf,
    original_project_config: String,
    original_rules: String,
    updated_rules: String,
    snapshot_dir: PathBuf,
    expected_resource: SnapshotResource,
    report: BreezeResourceCaptureReport,
}

impl BreezeResourceCapturePlan {
    pub fn report(&self) -> &BreezeResourceCaptureReport {
        &self.report
    }

    pub fn apply(self) -> Result<BreezeResourceCaptureReport> {
        let current = read_config(&self.project_config_path)?;
        ensure!(
            current == self.original_project_config,
            "project config changed after planning; rerun plan before applying"
        );
        ensure!(
            read_config(&self.rules_path)? == self.original_rules,
            "source traffic policy changed after planning; rerun plan before applying"
        );
        let snapshot = Snapshot::load(&self.snapshot_dir)?;
        let resource = snapshot.resolve(&self.expected_resource.identity)?;
        ensure!(
            resource == &self.expected_resource,
            "Breeze snapshot resource changed after planning; rerun plan before applying"
        );
        if self.report.changed {
            write_atomic(&self.rules_path, self.updated_rules.as_bytes())?;
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
    plan_capture(
        feedback.project_config_path,
        feedback.rules_path,
        CaptureSelector::Resource(feedback.resource),
        feedback.source_revision,
        feedback.source_evidence,
    )
}

pub fn plan_breeze_endpoint_capture(
    feedback: BreezeEndpointCaptureFeedback,
) -> Result<BreezeResourceCapturePlan> {
    validate_endpoint_feedback(&feedback)?;
    plan_capture(
        feedback.project_config_path,
        feedback.rules_path,
        CaptureSelector::Endpoint(feedback.endpoint),
        feedback.source_revision,
        feedback.source_evidence,
    )
}

enum CaptureSelector {
    Resource(String),
    Endpoint(String),
}

fn plan_capture(
    project_config_path: PathBuf,
    rules_path: PathBuf,
    selector: CaptureSelector,
    source_revision: String,
    source_evidence: String,
) -> Result<BreezeResourceCapturePlan> {
    ensure_regular_config(&project_config_path)?;
    ensure_regular_config(&rules_path)?;
    let original_project_config = read_config(&project_config_path)?;
    let original_rules = read_config(&rules_path)?;
    let config = AppConfig::load(&project_config_path)?;
    let (candidate, requested_resource, requested_endpoint) = match selector {
        CaptureSelector::Resource(resource) => {
            let candidate = resolve_candidate(&config, &resource)?;
            (candidate, resource, None)
        }
        CaptureSelector::Endpoint(endpoint) => {
            let selector = endpoint_selector(&endpoint)?;
            let candidate = resolve_endpoint_candidate(&config, &selector)?;
            let requested_resource = candidate.resource.name.clone();
            (candidate, requested_resource, Some(endpoint))
        }
    };
    ensure!(
        !candidate.resource.domains.is_empty(),
        "Breeze resource {:?} has no hostname backend; IP literals are not part of DNS bypass and cannot be enabled by this strategy",
        candidate.resource.identity
    );

    let before = candidate
        .capture_resources
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let captured_domains_before = captured_domains(&candidate.snapshot, &before)?;
    let bypassed_domains_before = candidate
        .resource
        .domains
        .difference(&captured_domains_before)
        .cloned()
        .collect();
    let mut after = before.clone();
    after.insert(candidate.resource.identity.clone());
    validate_existing_resources(&candidate.snapshot, &after)?;
    let mut rules = SourceTrafficPolicyConfig::parse(&original_rules, &rules_path)?;
    let overlay = breeze_overlay_mut(&mut rules, &candidate.snapshot_dir);
    overlay.capture_resources = after.iter().cloned().collect();
    let mut static_config = AppConfig::load_static(&project_config_path)?;
    rules.apply_to(&mut static_config)?;
    static_config.validate()?;
    let updated_rules = super::native_policy::render_updated(
        &original_rules,
        &rules,
        &crate::policy::Proof {
            source: format!(
                "{} at {}",
                candidate.resource.descriptor_path.display(),
                source_revision
            ),
            fact: source_evidence.clone(),
        },
    )?;
    let changed = updated_rules != original_rules;
    let diff = if changed {
        whole_file_diff(&rules_path, &original_rules, &updated_rules)
    } else {
        String::new()
    };
    let shared_domain_resources = shared_domain_resources(&candidate.snapshot, &candidate.resource);

    Ok(BreezeResourceCapturePlan {
        project_config_path,
        rules_path: rules_path.clone(),
        original_project_config,
        original_rules,
        updated_rules,
        snapshot_dir: candidate.snapshot_dir.clone(),
        expected_resource: candidate.resource.clone(),
        report: BreezeResourceCaptureReport {
            rules: rules_path,
            snapshot_dir: candidate.snapshot_dir,
            requested_resource,
            requested_endpoint,
            resource: candidate.resource.name.clone(),
            resource_identity: candidate.resource.identity.clone(),
            descriptor: candidate.resource.descriptor_path.clone(),
            domains: candidate.resource.domains.iter().cloned().collect(),
            shared_domain_resources,
            source_revision,
            source_evidence,
            capture_resources_before: before.into_iter().collect(),
            capture_resources_after: after.into_iter().collect(),
            bypassed_domains_before,
            changed,
            applied: false,
            diff,
        },
    })
}

fn captured_domains(snapshot: &Snapshot, selectors: &BTreeSet<String>) -> Result<BTreeSet<String>> {
    let mut domains = BTreeSet::new();
    for selector in selectors {
        domains.extend(snapshot.resolve(selector)?.domains.iter().cloned());
    }
    Ok(domains)
}

struct Candidate {
    snapshot_dir: PathBuf,
    capture_resources: Vec<String>,
    snapshot: Snapshot,
    resource: SnapshotResource,
}

struct LoadedStrategy {
    snapshot_dir: PathBuf,
    capture_resources: Vec<String>,
    snapshot: Snapshot,
}

fn resolve_candidate(config: &AppConfig, selector: &str) -> Result<Candidate> {
    let mut loaded = load_strategies(config)?;

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
        snapshot_dir: selected.snapshot_dir,
        capture_resources: selected.capture_resources,
        snapshot: selected.snapshot,
        resource,
    })
}

struct BackendEndpointSelector {
    domain: String,
    port: Option<u16>,
}

fn resolve_endpoint_candidate(
    config: &AppConfig,
    selector: &BackendEndpointSelector,
) -> Result<Candidate> {
    let mut loaded = load_strategies(config)?;
    let mut matches = Vec::new();
    let exact_endpoint = selector
        .port
        .map(|port| format!("{}:{port}", selector.domain));
    for (loaded_index, strategy) in loaded.iter().enumerate() {
        for (resource_index, resource) in strategy.snapshot.resources().iter().enumerate() {
            let selected = exact_endpoint.as_ref().map_or_else(
                || resource.domains.contains(&selector.domain),
                |endpoint| resource.endpoints.contains(endpoint),
            );
            if selected {
                matches.push((loaded_index, resource_index));
            }
        }
    }
    if matches.is_empty() {
        bail!(
            "backend endpoint {:?} does not belong to any resource in the configured Breeze snapshot bypass strategies",
            exact_endpoint.as_deref().unwrap_or(&selector.domain)
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
            "backend endpoint {:?} is shared by multiple Breeze resources; provide its source-proven port when available: {identities}",
            exact_endpoint.as_deref().unwrap_or(&selector.domain)
        );
    }

    let (loaded_index, resource_index) = matches[0];
    let selected = loaded.swap_remove(loaded_index);
    let resource = selected.snapshot.resources()[resource_index].clone();
    Ok(Candidate {
        snapshot_dir: selected.snapshot_dir,
        capture_resources: selected.capture_resources,
        snapshot: selected.snapshot,
        resource,
    })
}

fn load_strategies(config: &AppConfig) -> Result<Vec<LoadedStrategy>> {
    config
        .dns_mock
        .bypass_strategies
        .iter()
        .map(|strategy| {
            let DnsBypassStrategyConfig::Breeze {
                snapshot_dir,
                capture_resources,
            } = strategy;
            Ok(LoadedStrategy {
                snapshot_dir: snapshot_dir.clone(),
                capture_resources: capture_resources.clone(),
                snapshot: Snapshot::load(snapshot_dir)?,
            })
        })
        .collect()
}

fn endpoint_selector(endpoint: &str) -> Result<BackendEndpointSelector> {
    let authority = Authority::from_str(endpoint)
        .with_context(|| format!("backend endpoint {endpoint:?} is not a hostname[:port]"))?;
    let domain = authority.host().trim_end_matches('.').to_ascii_lowercase();
    let port = authority.port_u16();
    ensure!(
        authority.port().is_none() || port.is_some(),
        "backend endpoint contains an invalid port"
    );
    ensure!(
        domain.contains('.') && domain.parse::<IpAddr>().is_err(),
        "backend endpoint must contain a hostname domain; IP literals are not part of Breeze DNS bypass"
    );
    ensure!(
        domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        }),
        "backend endpoint contains an invalid hostname domain"
    );
    Ok(BackendEndpointSelector { domain, port })
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

fn validate_endpoint_feedback(feedback: &BreezeEndpointCaptureFeedback) -> Result<()> {
    validate_single_line("backend endpoint", &feedback.endpoint, 512)?;
    endpoint_selector(&feedback.endpoint)?;
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

fn breeze_overlay_mut<'a>(
    rules: &'a mut SourceTrafficPolicyConfig,
    snapshot_dir: &Path,
) -> &'a mut SourceTrafficBreezeCaptureConfig {
    if let Some(index) = rules
        .breeze_capture
        .iter()
        .position(|capture| capture.snapshot_dir == snapshot_dir)
    {
        return &mut rules.breeze_capture[index];
    }
    rules.breeze_capture.push(SourceTrafficBreezeCaptureConfig {
        snapshot_dir: snapshot_dir.to_path_buf(),
        capture_resources: Vec::new(),
    });
    rules
        .breeze_capture
        .last_mut()
        .expect("just inserted coordinator Breeze capture")
}

#[cfg(test)]
mod tests;
