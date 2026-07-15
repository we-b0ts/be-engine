use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::Serialize;

use super::document::plan_managed_update;
use super::evidence::{fingerprint_file, load_verified_evidence};
use super::{VerifiedApiExclude, validate_api};
use crate::config::AppConfig;
use crate::config::edit::write_atomic;

#[derive(Debug, Clone)]
pub struct VerifiedApiExcludeFeedback {
    pub config_path: PathBuf,
    pub rule_name: String,
    pub method: String,
    pub path_pattern: String,
    pub aggregate_report: PathBuf,
    pub assertion_report: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifiedApiExcludeReport {
    pub config: PathBuf,
    pub rule: String,
    pub method: String,
    pub path_pattern: String,
    pub aggregate_report: PathBuf,
    pub aggregate_fingerprint: String,
    pub assertion_report: PathBuf,
    pub assertion_fingerprint: String,
    pub case_source: PathBuf,
    pub threshold: usize,
    pub matching_case_ids: Vec<String>,
    pub consecutive_success_case_ids: Vec<String>,
    pub eligible: bool,
    pub blockers: Vec<String>,
    pub changed: bool,
    pub applied: bool,
    pub apis_before: Vec<VerifiedApiExclude>,
    pub apis_after: Vec<VerifiedApiExclude>,
    pub added: Vec<VerifiedApiExclude>,
    pub diff: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifiedApiExcludeEnsureStatus {
    Applied,
    AlreadyPresent,
    BelowThreshold,
}

impl fmt::Display for VerifiedApiExcludeEnsureStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Applied => "applied",
            Self::AlreadyPresent => "already_present",
            Self::BelowThreshold => "below_threshold",
        };
        formatter.write_str(value)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifiedApiExcludeEnsureReport {
    pub status: VerifiedApiExcludeEnsureStatus,
    pub plan: VerifiedApiExcludeReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apply: Option<VerifiedApiExcludeReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification: Option<VerifiedApiExcludeReport>,
}

#[derive(Debug)]
pub struct VerifiedApiExcludePlan {
    config_path: PathBuf,
    original: String,
    updated: String,
    report: VerifiedApiExcludeReport,
}

impl VerifiedApiExcludePlan {
    pub fn report(&self) -> &VerifiedApiExcludeReport {
        &self.report
    }

    pub fn apply(self) -> Result<VerifiedApiExcludeReport> {
        ensure!(
            self.report.eligible,
            "verified API exclude is not eligible: {}",
            self.report.blockers.join(", ")
        );
        let current = fs::read_to_string(&self.config_path).with_context(|| {
            format!(
                "failed to reread recorder config {}",
                self.config_path.display()
            )
        })?;
        ensure!(
            current == self.original,
            "recorder config changed after planning; rerun plan before applying"
        );
        ensure!(
            fingerprint_file(&self.report.aggregate_report, "aggregate report")?
                == self.report.aggregate_fingerprint,
            "aggregate report changed after planning; rerun plan before applying"
        );
        ensure!(
            fingerprint_file(&self.report.assertion_report, "assertion report")?
                == self.report.assertion_fingerprint,
            "assertion report changed after planning; rerun plan before applying"
        );
        if self.report.changed {
            write_atomic(&self.config_path, self.updated.as_bytes())?;
        }
        let mut report = self.report;
        report.applied = true;
        Ok(report)
    }
}

pub fn plan_verified_api_exclude(
    feedback: VerifiedApiExcludeFeedback,
) -> Result<VerifiedApiExcludePlan> {
    let config_path = canonical_file(&feedback.config_path, "recorder config")?;
    let original = fs::read_to_string(&config_path)
        .with_context(|| format!("failed to read recorder config {}", config_path.display()))?;
    let config = parse_config(&original, &config_path)?;
    let threshold = config.http_gateway.verified_excludes.consecutive_successes;
    ensure!(
        threshold > 0,
        "http_gateway.verified_excludes.consecutive_successes must be greater than zero"
    );
    let candidate = VerifiedApiExclude {
        rule: feedback.rule_name,
        method: feedback.method,
        path_pattern: feedback.path_pattern,
    };
    validate_api(&candidate, &config.http_gateway.rules)?;

    let evidence = load_verified_evidence(
        &feedback.aggregate_report,
        &feedback.assertion_report,
        &candidate,
    )?;
    let mut blockers = Vec::new();
    if !evidence.aggregate_complete {
        blockers.push("aggregate_incomplete".to_string());
    }
    if evidence.aggregate_dirty {
        blockers.push("aggregate_dirty".to_string());
    }
    if evidence.consecutive_success_case_ids.len() < threshold {
        blockers.push("consecutive_successes_below_threshold".to_string());
    }
    let eligible = blockers.is_empty();

    let managed = plan_managed_update(
        &original,
        &config_path,
        config.http_gateway.verified_excludes.apis,
        &candidate,
        eligible,
    )?;
    let report = VerifiedApiExcludeReport {
        config: config_path.clone(),
        rule: candidate.rule,
        method: candidate.method,
        path_pattern: candidate.path_pattern,
        aggregate_report: evidence.aggregate_path,
        aggregate_fingerprint: evidence.aggregate_fingerprint,
        assertion_report: evidence.assertion_path,
        assertion_fingerprint: evidence.assertion_fingerprint,
        case_source: evidence.case_source,
        threshold,
        matching_case_ids: evidence.matching_case_ids,
        consecutive_success_case_ids: evidence.consecutive_success_case_ids,
        eligible,
        blockers,
        changed: managed.changed,
        applied: false,
        apis_before: managed.before.into_iter().collect(),
        apis_after: managed.after.into_iter().collect(),
        added: managed.added,
        diff: managed.diff,
    };
    Ok(VerifiedApiExcludePlan {
        config_path,
        original,
        updated: managed.updated,
        report,
    })
}

pub fn ensure_verified_api_exclude(
    feedback: VerifiedApiExcludeFeedback,
) -> Result<VerifiedApiExcludeEnsureReport> {
    let plan = plan_verified_api_exclude(feedback.clone())?;
    let initial = plan.report().clone();
    if !initial.eligible {
        ensure!(
            initial.blockers == ["consecutive_successes_below_threshold"],
            "verified API exclude evidence is blocked: {}",
            initial.blockers.join(", ")
        );
        return Ok(VerifiedApiExcludeEnsureReport {
            status: VerifiedApiExcludeEnsureStatus::BelowThreshold,
            plan: initial,
            apply: None,
            verification: None,
        });
    }
    if !initial.changed {
        return Ok(VerifiedApiExcludeEnsureReport {
            status: VerifiedApiExcludeEnsureStatus::AlreadyPresent,
            plan: initial,
            apply: None,
            verification: None,
        });
    }

    let applied = plan.apply()?;
    let verification_plan = plan_verified_api_exclude(feedback)?;
    let verification = verification_plan.report().clone();
    ensure!(
        verification.eligible && !verification.changed,
        "verified API exclude apply did not converge to an eligible no-change plan"
    );
    Ok(VerifiedApiExcludeEnsureReport {
        status: VerifiedApiExcludeEnsureStatus::Applied,
        plan: initial,
        apply: Some(applied),
        verification: Some(verification),
    })
}

fn parse_config(raw: &str, path: &Path) -> Result<AppConfig> {
    let config = toml::from_str::<AppConfig>(raw)
        .with_context(|| format!("failed to parse recorder config {}", path.display()))?;
    config
        .validate()
        .with_context(|| format!("invalid recorder config {}", path.display()))?;
    Ok(config)
}

fn canonical_file(path: &Path, label: &str) -> Result<PathBuf> {
    let canonical = path
        .canonicalize()
        .with_context(|| format!("failed to resolve {label} {}", path.display()))?;
    ensure!(canonical.is_file(), "{label} must be a regular file");
    Ok(canonical)
}
