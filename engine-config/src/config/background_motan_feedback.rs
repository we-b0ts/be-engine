use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use super::background_feedback::{RuleConfigPlan, plan_rule_config};
use super::edit::write_atomic;
use super::process_owned_dependencies::{self, BackgroundDependencyRuleConfig};

#[derive(Debug, Clone)]
pub struct MotanBackgroundDependencyFeedback {
    pub rules_path: PathBuf,
    pub replay_report_path: PathBuf,
    pub name: String,
    pub group: String,
    pub interface_name: String,
    pub method_name: String,
    pub source_revision: String,
    pub source_evidence: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MotanBackgroundDependencyReport {
    pub rules: PathBuf,
    pub replay_report: PathBuf,
    pub name: String,
    pub effective_name: String,
    pub reused_existing: bool,
    pub protocol: &'static str,
    pub group: String,
    pub interface_name: String,
    pub method_name: String,
    pub source_revision: String,
    pub source_evidence: String,
    pub matched_unused_exchanges: usize,
    pub matched_case_ids: Vec<String>,
    pub changed: bool,
    pub applied: bool,
    pub diff: String,
}

#[derive(Debug)]
pub struct MotanBackgroundDependencyPlan {
    rules_path: PathBuf,
    replay_report_path: PathBuf,
    original_rules: String,
    original_replay_report: String,
    updated_rules: String,
    report: MotanBackgroundDependencyReport,
}

impl MotanBackgroundDependencyPlan {
    pub fn report(&self) -> &MotanBackgroundDependencyReport {
        &self.report
    }

    pub fn apply(self) -> Result<MotanBackgroundDependencyReport> {
        ensure!(
            read_file(&self.rules_path, "process-owned rules")? == self.original_rules,
            "process-owned rules changed after planning; rerun plan before applying"
        );
        ensure!(
            read_file(&self.replay_report_path, "replay report")? == self.original_replay_report,
            "replay report changed after planning; rerun plan before applying"
        );
        if self.report.changed {
            write_atomic(&self.rules_path, self.updated_rules.as_bytes())?;
        }
        let mut report = self.report;
        report.applied = true;
        Ok(report)
    }
}

pub fn plan_motan_background_dependency(
    feedback: MotanBackgroundDependencyFeedback,
) -> Result<MotanBackgroundDependencyPlan> {
    let requested = BackgroundDependencyRuleConfig::Motan {
        name: feedback.name.clone(),
        group: feedback.group.clone(),
        interface_name: feedback.interface_name.clone(),
        method_name: feedback.method_name.clone(),
        source_revision: String::new(),
        source_evidence: feedback.source_evidence.clone(),
    };
    process_owned_dependencies::validate(std::slice::from_ref(&requested))?;

    let original_replay_report = read_file(&feedback.replay_report_path, "replay report")?;
    let evidence = parse_replay_evidence(
        &original_replay_report,
        &feedback.replay_report_path,
        &feedback.interface_name,
        &feedback.method_name,
    )?;
    let RuleConfigPlan {
        original,
        updated,
        changed,
        diff,
        effective_name,
        reused_existing,
    } = plan_rule_config(&feedback.rules_path, requested)?;

    Ok(MotanBackgroundDependencyPlan {
        rules_path: feedback.rules_path.clone(),
        replay_report_path: feedback.replay_report_path.clone(),
        original_rules: original,
        original_replay_report,
        updated_rules: updated,
        report: MotanBackgroundDependencyReport {
            rules: feedback.rules_path,
            replay_report: feedback.replay_report_path,
            name: feedback.name,
            effective_name,
            reused_existing,
            protocol: "motan",
            group: feedback.group,
            interface_name: feedback.interface_name,
            method_name: feedback.method_name,
            source_revision: feedback.source_revision,
            source_evidence: feedback.source_evidence,
            matched_unused_exchanges: evidence.count,
            matched_case_ids: evidence.case_ids,
            changed,
            applied: false,
            diff,
        },
    })
}

#[derive(Debug, Deserialize)]
struct ReplayEvidenceReport {
    version: u8,
    finalized: bool,
    #[serde(default)]
    motan: CommandProtocolEvidence,
}

#[derive(Debug, Default, Deserialize)]
struct CommandProtocolEvidence {
    #[serde(default)]
    unmatched: Vec<CommandEvidence>,
    #[serde(default)]
    unsupported: Vec<CommandEvidence>,
    #[serde(default)]
    unsafe_events: Vec<CommandEvidence>,
    #[serde(default)]
    unused_case: Vec<UnusedCommandEvidence>,
}

#[derive(Debug, Deserialize)]
struct CommandEvidence {
    command: String,
}

#[derive(Debug, Deserialize)]
struct UnusedCommandEvidence {
    case_id: Option<String>,
    command: String,
}

struct EvidenceMatch {
    count: usize,
    case_ids: Vec<String>,
}

fn parse_replay_evidence(
    raw: &str,
    report_path: &Path,
    interface_name: &str,
    method_name: &str,
) -> Result<EvidenceMatch> {
    let report: ReplayEvidenceReport = serde_json::from_str(raw)
        .with_context(|| format!("failed to parse replay report {}", report_path.display()))?;
    ensure!(
        report.version == 7,
        "Motan process-owned dependency evidence requires replay report version 7"
    );
    ensure!(
        report.finalized,
        "process-owned dependency evidence requires a finalized replay report"
    );
    let command = format!("{interface_name}#{method_name}");
    ensure!(
        !report
            .motan
            .unmatched
            .iter()
            .chain(&report.motan.unsupported)
            .chain(&report.motan.unsafe_events)
            .any(|event| event.command == command),
        "Motan background selector also matches unmatched, unsupported, or unsafe target traffic"
    );
    let matching = report
        .motan
        .unused_case
        .iter()
        .filter(|event| event.command == command)
        .collect::<Vec<_>>();
    ensure!(
        !matching.is_empty(),
        "Motan background selector matches no unused case exchange in the replay report"
    );
    let case_ids = matching
        .iter()
        .filter_map(|event| event.case_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    Ok(EvidenceMatch {
        count: matching.len(),
        case_ids,
    })
}

fn read_file(path: &Path, label: &str) -> Result<String> {
    fs::read_to_string(path).with_context(|| format!("failed to read {label} {}", path.display()))
}

#[cfg(test)]
#[path = "background_motan_feedback/tests.rs"]
mod tests;
