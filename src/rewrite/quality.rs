//! Stage-bound review checks and the final candidate's repository command gate.
use std::path::{Path, PathBuf};

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use super::fingerprint;

mod commands;
#[path = "target_replay_isolation.rs"]
mod replay_isolation;

pub use replay_isolation::ReplayIsolationReport;
pub(in crate::rewrite) use replay_isolation::source_evidence_unchanged;

const REPORT_SCHEMA_VERSION: u8 = 2;
const POLICY_VERSION: &str = "delivery-quality-v3";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualityScope {
    Worker,
    Integration,
    PreRevalidation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityReport {
    pub schema_version: u8,
    // Historical receipts remain readable, but cannot pass stage admission.
    #[serde(default)]
    pub scope: Option<QualityScope>,
    pub policy_fingerprint: String,
    pub replay_isolation: ReplayIsolationReport,
    // Ordinary delivery stages perform engine checks only. Final review retains
    // the canonical repository command results for this frozen candidate.
    pub commands: Vec<QualityCommandReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityCommandReport {
    pub name: String,
    pub argv: Vec<String>,
    /// Candidate-relative execution directory; portable across Git worktrees.
    #[serde(default = "default_working_directory")]
    pub working_directory: PathBuf,
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

fn default_working_directory() -> PathBuf {
    PathBuf::from(".")
}

impl QualityCommandReport {
    fn passed(&self) -> bool {
        self.status == QualityCommandStatus::Passed
            && self.exit_code == Some(0)
            && self.error.is_none()
            && self.log_path.is_absolute()
            && !self.working_directory.as_os_str().is_empty()
            && !self.working_directory.is_absolute()
    }
}

impl QualityReport {
    pub(in crate::rewrite) fn passed(&self) -> bool {
        self.passed_for(QualityScope::Integration)
    }

    pub(in crate::rewrite) fn passed_for(&self, scope: QualityScope) -> bool {
        self.ensure_passed_for(scope).is_ok()
    }

    pub(in crate::rewrite) fn ensure_passed(&self) -> Result<()> {
        self.ensure_passed_for(QualityScope::Integration)
    }

    pub(in crate::rewrite) fn ensure_passed_for(&self, scope: QualityScope) -> Result<()> {
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
        if scope != QualityScope::PreRevalidation {
            ensure!(
                self.commands.is_empty(),
                "ordinary review quality receipt contains repository command results; rerun review check for this delivery stage"
            );
        }
        for command in &self.commands {
            ensure!(
                command.passed(),
                "quality gate {:?} failed (exit code {:?}{}); inspect {} and rerun review check --pre-revalidation after repair",
                command.name,
                command.exit_code,
                command
                    .error
                    .as_ref()
                    .map(|error| format!(", {error}"))
                    .unwrap_or_default(),
                command.log_path.display()
            );
        }
        ensure!(
            self.policy_fingerprint == policy_fingerprint_for(scope, &self.command_specs())?,
            "quality report uses an outdated or incomplete check policy; rerun review check with the current configuration"
        );
        Ok(())
    }

    /// Final admission must rederive commands from the candidate, rather than
    /// trusting the command inventory recorded in a potentially stale receipt.
    pub(in crate::rewrite) fn ensure_pre_revalidation(
        &self,
        root: &Path,
        managed_paths: &[PathBuf],
    ) -> Result<()> {
        self.ensure_passed_for(QualityScope::PreRevalidation)?;
        let expected = commands::inferred(root, managed_paths);
        ensure!(
            self.command_specs() == expected
                && self.policy_fingerprint
                    == policy_fingerprint_for(QualityScope::PreRevalidation, &expected)?,
            "final review command inventory differs from the candidate's required gates; rerun review check --pre-revalidation"
        );
        Ok(())
    }

    fn command_specs(&self) -> Vec<commands::CommandSpec> {
        self.commands
            .iter()
            .map(|command| commands::CommandSpec {
                name: command.name.clone(),
                argv: command.argv.clone(),
                working_directory: command.working_directory.clone(),
            })
            .collect()
    }
}

pub(in crate::rewrite) fn run(
    root: &Path,
    base: &str,
    hardcode_ai_verified: &[String],
) -> Result<QualityReport> {
    run_for(
        QualityScope::Integration,
        root,
        base,
        &[],
        hardcode_ai_verified,
    )
}

pub(in crate::rewrite) fn run_worker(
    root: &Path,
    base: &str,
    hardcode_ai_verified: &[String],
) -> Result<QualityReport> {
    run_for(QualityScope::Worker, root, base, &[], hardcode_ai_verified)
}

pub(in crate::rewrite) fn run_pre_revalidation(
    root: &Path,
    base: &str,
    managed_paths: &[PathBuf],
    hardcode_ai_verified: &[String],
) -> Result<QualityReport> {
    run_for(
        QualityScope::PreRevalidation,
        root,
        base,
        &commands::inferred(root, managed_paths),
        hardcode_ai_verified,
    )
}

fn run_for(
    scope: QualityScope,
    root: &Path,
    base: &str,
    gates: &[commands::CommandSpec],
    hardcode_ai_verified: &[String],
) -> Result<QualityReport> {
    let replay_isolation = replay_isolation::inspect_at_base(root, base, hardcode_ai_verified)?;
    // Do not execute repository code after a failed isolation check. Fail-fast
    // leaves an incomplete final report, which cannot pass final admission.
    let commands = if replay_isolation.passed() {
        commands::run(root, gates)?
    } else {
        Vec::new()
    };
    Ok(QualityReport {
        schema_version: REPORT_SCHEMA_VERSION,
        scope: Some(scope),
        policy_fingerprint: policy_fingerprint_for(scope, gates)?,
        replay_isolation,
        commands,
    })
}

pub(in crate::rewrite) fn policy_fingerprint() -> Result<String> {
    policy_fingerprint_for(QualityScope::Integration, &[])
}

fn policy_fingerprint_for(scope: QualityScope, gates: &[commands::CommandSpec]) -> Result<String> {
    Ok(fingerprint::id(&[
        POLICY_VERSION,
        &serde_json::to_string(&scope)?,
        super::review::RULE_VERSION,
        replay_isolation::GATE_VERSION,
        commands::POLICY_VERSION,
        &serde_json::to_string(gates)?,
    ]))
}

pub(in crate::rewrite) fn gate_names() -> Vec<String> {
    ["source-review", replay_isolation::GATE_NAME]
        .into_iter()
        .map(str::to_string)
        .collect()
}

pub(in crate::rewrite) fn final_gate_names(root: &Path, managed_paths: &[PathBuf]) -> Vec<String> {
    gate_names()
        .into_iter()
        .chain(
            commands::inferred(root, managed_paths)
                .into_iter()
                .map(|gate| gate.name),
        )
        .collect()
}

#[cfg(test)]
mod tests;
