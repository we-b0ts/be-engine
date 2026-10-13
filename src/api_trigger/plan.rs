//! Stale-safe planning for API-origin Redis classification using existing recordings.
use crate::config::{ApiTriggerSource, BackgroundDependencyRuleConfig};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiTriggeredRedisSelector {
    pub ports: Vec<u16>,
    pub command: String,
    pub key_templates: Vec<String>,
    #[serde(default)]
    pub arguments: Vec<String>,
    pub trigger_source: ApiTriggerSource,
}

impl ApiTriggeredRedisSelector {
    pub(crate) fn rule(
        &self,
        name: &str,
        revision: &str,
        proof: &str,
    ) -> BackgroundDependencyRuleConfig {
        let mut ports = self.ports.clone();
        ports.sort_unstable();
        let mut templates = self.key_templates.clone();
        templates.sort();
        BackgroundDependencyRuleConfig::Redis {
            name: name.into(),
            ports,
            command: self.command.to_ascii_uppercase(),
            key_templates: templates,
            arguments: self.arguments.clone(),
            trigger_source: Some(self.trigger_source.clone()),
            keys: Vec::new(),
            key_patterns: Vec::new(),
            key_prefix: String::new(),
            key_suffix: String::new(),
            initial_load_timeout_ms: None,
            fields: Vec::new(),
            source_revision: revision.into(),
            source_evidence: proof.into(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ApiTriggeredRedisReport {
    pub name: String,
    pub effective_name: String,
    pub reused_existing: bool,
    pub matched_unused_exchanges: usize,
    pub matched_case_ids: Vec<String>,
    pub trigger_case_ids: Vec<String>,
    pub omitted_case_ids: usize,
    pub omitted_trigger_case_ids: usize,
    pub ambiguous_triggers: usize,
    pub ambiguous_references: usize,
    pub evidence_fingerprint: String,
    pub changed: bool,
    pub applied: bool,
    pub diff: String,
}

pub struct ApiTriggeredRedisPlan {
    rules_path: PathBuf,
    replay_path: PathBuf,
    source: PathBuf,
    rule: BackgroundDependencyRuleConfig,
    original_rules: String,
    original_replay: Vec<u8>,
    updated_rules: String,
    report: ApiTriggeredRedisReport,
}

impl ApiTriggeredRedisPlan {
    pub fn report(&self) -> &ApiTriggeredRedisReport {
        &self.report
    }
    pub fn apply(self) -> Result<ApiTriggeredRedisReport> {
        ensure!(
            fs::read_to_string(&self.rules_path)? == self.original_rules,
            "process-owned rules changed after planning; rerun plan"
        );
        ensure!(
            fs::read(&self.replay_path)? == self.original_replay,
            "Replay evidence changed after planning; rerun plan"
        );
        let index = super::load(&self.source, std::slice::from_ref(&self.rule))?;
        ensure!(
            index.evidence_fingerprint == self.report.evidence_fingerprint,
            "API trigger recording changed after planning; rerun plan"
        );
        if self.report.changed {
            crate::config::edit::write_atomic(&self.rules_path, self.updated_rules.as_bytes())?;
        }
        let mut report = self.report;
        report.applied = true;
        Ok(report)
    }
}

pub fn plan_api_triggered_redis(
    rules_path: &Path,
    replay_path: &Path,
    source: &Path,
    name: &str,
    revision: &str,
    proof: &str,
    selector: &ApiTriggeredRedisSelector,
) -> Result<ApiTriggeredRedisPlan> {
    let rule = selector.rule(name, revision, proof);
    crate::config::process_owned_dependencies::validate(std::slice::from_ref(&rule))?;
    let index = super::load(source, std::slice::from_ref(&rule))?;
    let original_replay = fs::read(replay_path)?;
    let raw = std::str::from_utf8(&original_replay)?;
    let replay: Value = crate::replay::report::parse_background_dependency_evidence(raw)?;
    ensure!(
        replay["version"].as_u64().is_some_and(|v| v >= 6) && replay["finalized"] == true,
        "API trigger plan requires finalized version-6-or-newer Replay evidence"
    );
    let mut case_ids = BTreeSet::new();
    let mut triggers = BTreeSet::new();
    let mut matched = 0;
    for event in replay["redis"]["unused_case"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let Some(case) = event["case_id"].as_str() else {
            continue;
        };
        let Some(witness) = index.witness(case, event) else {
            continue;
        };
        if event["command"] != selector.command.to_ascii_uppercase()
            || !selector
                .ports
                .iter()
                .any(|p| event["target"]["port"].as_u64() == Some(u64::from(*p)))
        {
            continue;
        }
        let membership = replay["cases"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|c| c["case_id"] == case)
            .and_then(|c| c["dependencies_path"].as_str());
        ensure!(
            membership
                .is_some_and(|p| fs::canonicalize(p).is_ok_and(|p| p == witness.dependencies_path)),
            "Replay case membership does not match immutable API trigger evidence"
        );
        matched += 1;
        case_ids.insert(case.to_string());
        triggers.insert(witness.trigger_case_id.clone());
    }
    ensure!(
        matched > 0,
        "no unused foreign-case Redis exchange has a unique API trigger; origins={}, ambiguous_origins={}, ambiguous_references={}; inspect source capture predicates",
        index.triggers,
        index.ambiguous_triggers,
        index.ambiguous_references
    );
    // No rule can suppress target-side failures on this command/resource.
    for field in ["unmatched", "unsupported", "unsafe_events"] {
        ensure!(
            !replay["redis"][field]
                .as_array()
                .into_iter()
                .flatten()
                .any(|event| event["command"]
                    .as_str()
                    .is_some_and(|s| s.eq_ignore_ascii_case(&selector.command))
                    && selector
                        .ports
                        .iter()
                        .any(|p| event["target"]["port"].as_u64() == Some(u64::from(*p)))),
            "API trigger selector overlaps {field} target Redis traffic"
        );
    }
    let config = crate::config::background_feedback::plan_rule_config(rules_path, rule.clone())?;
    Ok(ApiTriggeredRedisPlan {
        rules_path: rules_path.into(),
        replay_path: replay_path.into(),
        source: source.into(),
        rule,
        original_rules: config.original,
        original_replay,
        updated_rules: config.updated,
        report: ApiTriggeredRedisReport {
            name: name.into(),
            effective_name: config.effective_name,
            reused_existing: config.reused_existing,
            matched_unused_exchanges: matched,
            omitted_case_ids: case_ids.len().saturating_sub(32),
            omitted_trigger_case_ids: triggers.len().saturating_sub(32),
            matched_case_ids: case_ids.into_iter().take(32).collect(),
            trigger_case_ids: triggers.into_iter().take(32).collect(),
            ambiguous_triggers: index.ambiguous_triggers,
            ambiguous_references: index.ambiguous_references,
            evidence_fingerprint: index.evidence_fingerprint,
            changed: config.changed,
            applied: false,
            diff: config.diff,
        },
    })
}
