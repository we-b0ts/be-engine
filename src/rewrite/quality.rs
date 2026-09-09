//! One delivery-time executor for replay isolation and configured quality gates.
use std::path::{Path, PathBuf};

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use crate::e2e_run::TargetQualityGateConfig;

use super::fingerprint;

mod commands;
#[path = "target_replay_isolation.rs"]
mod replay_isolation;

pub use replay_isolation::ReplayIsolationReport;
pub(in crate::rewrite) use replay_isolation::source_evidence_unchanged;

const REPORT_SCHEMA_VERSION: u8 = 1;
const POLICY_VERSION: &str = "delivery-quality-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityReport {
    pub schema_version: u8,
    pub policy_fingerprint: String,
    pub replay_isolation: ReplayIsolationReport,
    pub commands: Vec<QualityCommandReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityCommandReport {
    pub name: String,
    pub argv: Vec<String>,
    pub status: QualityCommandStatus,
    pub exit_code: Option<i32>,
    pub log_path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualityCommandStatus {
    Passed,
    Failed,
}

impl QualityCommandReport {
    fn passed(&self) -> bool {
        self.status == QualityCommandStatus::Passed
            && self.exit_code == Some(0)
            && self.error.is_none()
            && self.log_path.is_absolute()
    }
}

impl QualityReport {
    pub(in crate::rewrite) fn passed(&self, gates: &[TargetQualityGateConfig]) -> bool {
        self.schema_version == REPORT_SCHEMA_VERSION
            && policy_fingerprint(gates).is_ok_and(|policy| self.policy_fingerprint == policy)
            && self.replay_isolation.passed()
            && self.commands.len() == gates.len()
            && self.commands.iter().zip(gates).all(|(result, gate)| {
                result.name == gate.name && result.argv == gate.argv && result.passed()
            })
    }

    pub(in crate::rewrite) fn ensure_passed(
        &self,
        gates: &[TargetQualityGateConfig],
    ) -> Result<()> {
        ensure!(
            self.schema_version == REPORT_SCHEMA_VERSION
                && self.policy_fingerprint == policy_fingerprint(gates)?,
            "quality report uses an outdated check policy; rerun review check with the current configuration"
        );
        ensure!(
            self.replay_isolation.passed(),
            "target replay isolation gate failed:\n{}",
            serde_json::to_string_pretty(&self.replay_isolation)?
        );
        for (result, gate) in self.commands.iter().zip(gates) {
            ensure!(
                result.name == gate.name && result.argv == gate.argv,
                "quality report command differs from configured gate {:?}; rerun review check",
                gate.name
            );
            ensure!(
                result.passed(),
                "quality gate {:?} failed (exit code {:?}{}); inspect {} and rerun review check after repair",
                result.name,
                result.exit_code,
                result
                    .error
                    .as_ref()
                    .map(|error| format!(", {error}"))
                    .unwrap_or_default(),
                result.log_path.display()
            );
        }
        ensure!(
            self.commands.len() == gates.len(),
            "quality report contains {} of {} configured commands; rerun review check to complete all required gates",
            self.commands.len(),
            gates.len()
        );
        Ok(())
    }
}

pub(in crate::rewrite) fn run(
    root: &Path,
    base: &str,
    gates: &[TargetQualityGateConfig],
    hardcode_ai_verified: &[String],
) -> Result<QualityReport> {
    let replay_isolation = replay_isolation::inspect_at_base(root, base, hardcode_ai_verified)?;
    // Keep failures at delivery time and retain the evidence. Missing later gates
    // are deliberately not accepted as passing results after a failed check.
    let commands = if replay_isolation.passed() {
        commands::run(root, gates)?
    } else {
        Vec::new()
    };
    Ok(QualityReport {
        schema_version: REPORT_SCHEMA_VERSION,
        policy_fingerprint: policy_fingerprint(gates)?,
        replay_isolation,
        commands,
    })
}

pub(in crate::rewrite) fn policy_fingerprint(gates: &[TargetQualityGateConfig]) -> Result<String> {
    Ok(fingerprint::id(&[
        POLICY_VERSION,
        super::review::RULE_VERSION,
        replay_isolation::GATE_VERSION,
        &serde_json::to_string(gates)?,
    ]))
}

pub(in crate::rewrite) fn gate_names(gates: &[TargetQualityGateConfig]) -> Vec<String> {
    ["source-review", replay_isolation::GATE_NAME]
        .into_iter()
        .map(str::to_string)
        .chain(gates.iter().map(|gate| gate.name.clone()))
        .collect()
}

#[cfg(test)]
mod tests;
