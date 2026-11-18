//! Stage-bound source/isolation receipts and agent-reported final quality checks.
use std::path::Path;

use anyhow::{Result, ensure};

use super::fingerprint;

#[path = "target_replay_isolation.rs"]
mod replay_isolation;

pub use replay_isolation::source_evidence_unchanged;

const REPORT_SCHEMA_VERSION: u8 = 3;
const POLICY_VERSION: &str = "delivery-quality-v4";

pub use traffic_rewrite_model::rewrite::quality::QualityScope;

pub use traffic_rewrite_model::rewrite::quality::QualityReport;

pub trait QualityReportMethods: Sized {
    #[cfg(any(test, feature = "test-support"))]
    fn passed(&self) -> bool;
    fn passed_for(&self, scope: QualityScope) -> bool;
    fn ensure_passed(&self) -> Result<()>;
    fn ensure_passed_for(&self, scope: QualityScope) -> Result<()>;
    fn ensure_pre_revalidation(&self, quality_check: &str) -> Result<()>;
}

impl QualityReportMethods for QualityReport {
    #[cfg(any(test, feature = "test-support"))]
    fn passed(&self) -> bool {
        self.passed_for(QualityScope::Integration)
    }

    fn passed_for(&self, scope: QualityScope) -> bool {
        self.ensure_passed_for(scope).is_ok()
    }

    fn ensure_passed(&self) -> Result<()> {
        self.ensure_passed_for(QualityScope::Integration)
    }

    fn ensure_passed_for(&self, scope: QualityScope) -> Result<()> {
        ensure!(
            self.schema_version == REPORT_SCHEMA_VERSION,
            "quality report uses an outdated check policy; rerun review check with the current configuration"
        );
        ensure!(
            self.scope == Some(scope),
            "quality report does not cover the required {scope:?} checks; rerun review check for this delivery stage"
        );
        ensure!(
            self.replay_isolation.passed(),
            "target replay isolation gate failed:\n{}",
            serde_json::to_string_pretty(&self.replay_isolation)?
        );
        ensure!(
            self.commands.is_empty(),
            "review no longer executes repository commands; rerun review check and report the agent-owned quality check"
        );
        if scope == QualityScope::PreRevalidation {
            ensure!(
                self.quality_check
                    .as_deref()
                    .is_some_and(|tool| !tool.is_empty()),
                "final review lacks the agent's successful quality_check; run the required tool before reporting it"
            );
        } else {
            ensure!(
                self.quality_check.is_none(),
                "ordinary review cannot attest the final quality check"
            );
        }
        ensure!(
            self.policy_fingerprint
                == policy_fingerprint_for(scope, self.quality_check.as_deref())?,
            "quality report uses an outdated or incomplete check policy; rerun review check with the current configuration"
        );
        Ok(())
    }

    /// Match the agent's reported tool against the canonical requirement.
    fn ensure_pre_revalidation(&self, quality_check: &str) -> Result<()> {
        self.ensure_passed_for(QualityScope::PreRevalidation)?;
        ensure!(
            self.quality_check.as_deref() == Some(quality_check),
            "final review quality_check differs from delivery.quality_check; run the required tool and report it on the current candidate"
        );
        Ok(())
    }
}

#[cfg(any(test, feature = "test-support"))]
pub fn run(root: &Path, base: &str, hardcode_ai_verified: &[String]) -> Result<QualityReport> {
    run_for(
        QualityScope::Integration,
        root,
        base,
        None,
        hardcode_ai_verified,
    )
}

#[cfg(any(test, feature = "test-support"))]
pub fn run_worker(
    root: &Path,
    base: &str,
    hardcode_ai_verified: &[String],
) -> Result<QualityReport> {
    run_for(QualityScope::Worker, root, base, None, hardcode_ai_verified)
}

pub fn run_pre_revalidation(
    root: &Path,
    base: &str,
    quality_check: &str,
    hardcode_ai_verified: &[String],
) -> Result<QualityReport> {
    run_for(
        QualityScope::PreRevalidation,
        root,
        base,
        Some(quality_check),
        hardcode_ai_verified,
    )
}

fn run_for(
    scope: QualityScope,
    root: &Path,
    base: &str,
    quality_check: Option<&str>,
    hardcode_ai_verified: &[String],
) -> Result<QualityReport> {
    Ok(QualityReport {
        schema_version: REPORT_SCHEMA_VERSION,
        scope: Some(scope),
        policy_fingerprint: policy_fingerprint_for(scope, quality_check)?,
        replay_isolation: replay_isolation::inspect_at_base(root, base, hardcode_ai_verified)?,
        quality_check: quality_check.map(str::to_owned),
        commands: Vec::new(),
    })
}

pub fn policy_fingerprint() -> Result<String> {
    policy_fingerprint_for(QualityScope::Integration, None)
}

fn policy_fingerprint_for(scope: QualityScope, quality_check: Option<&str>) -> Result<String> {
    Ok(fingerprint::id(&[
        POLICY_VERSION,
        &serde_json::to_string(&scope)?,
        crate::model::RULE_VERSION,
        replay_isolation::GATE_VERSION,
        &serde_json::to_string(&quality_check)?,
    ]))
}

pub fn gate_names() -> Vec<String> {
    ["source-review", replay_isolation::GATE_NAME]
        .into_iter()
        .map(str::to_string)
        .collect()
}

pub fn final_gate_names() -> Vec<String> {
    gate_names()
        .into_iter()
        .chain(["agent-quality-check".into()])
        .collect()
}
