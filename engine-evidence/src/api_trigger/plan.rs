//! Shared stale-safe policy transaction for API-origin dependency classification.
use crate::config::{ApiTriggerSource, BackgroundDependencyRuleConfig};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiTriggeredRedisSelector {
    pub ports: Vec<u16>,
    pub command: String,
    #[serde(default)]
    pub key_templates: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_sequence: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script: Option<crate::ApiTriggerRedisScript>,
    #[serde(default)]
    pub arguments: Vec<String>,
    pub trigger_source: ApiTriggerSource,
}

impl ApiTriggeredRedisSelector {
    pub fn rule(&self, name: &str, revision: &str, proof: &str) -> BackgroundDependencyRuleConfig {
        let mut ports = self.ports.clone();
        ports.sort_unstable();
        let mut templates = self.key_templates.clone();
        templates.sort();
        BackgroundDependencyRuleConfig::Redis {
            key_sequence: self.key_sequence.clone(),
            script: self.script.clone(),
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
pub struct ApiTriggeredDependencyReport {
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
    pub ambiguous_transactions: usize,
    pub unmatched_evidence_reasons: Vec<String>,
    pub evidence_fingerprint: String,
    pub changed: bool,
    pub applied: bool,
    pub diff: String,
}

pub struct ApiTriggeredDependencyPlan {
    rules_path: PathBuf,
    replay_path: PathBuf,
    source: PathBuf,
    rules: Vec<BackgroundDependencyRuleConfig>,
    original_rules: String,
    original_replay: Vec<u8>,
    updated_rules: String,
    report: ApiTriggeredDependencyReport,
}

impl ApiTriggeredDependencyPlan {
    pub fn report(&self) -> &ApiTriggeredDependencyReport {
        &self.report
    }
    pub fn apply(self) -> Result<ApiTriggeredDependencyReport> {
        ensure!(
            fs::read_to_string(&self.rules_path)? == self.original_rules,
            "process-owned rules changed after planning; rerun plan"
        );
        ensure!(
            fs::read(&self.replay_path)? == self.original_replay,
            "Replay evidence changed after planning; rerun plan"
        );
        let index = super::load(&self.source, &self.rules)?;
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

pub type ApiTriggeredRedisReport = ApiTriggeredDependencyReport;
pub type ApiTriggeredRedisPlan = ApiTriggeredDependencyPlan;
pub type ApiTriggeredMysqlReport = ApiTriggeredDependencyReport;
pub type ApiTriggeredMysqlPlan = ApiTriggeredDependencyPlan;

pub fn plan_api_triggered_redis(
    rules_path: &Path,
    replay_path: &Path,
    source: &Path,
    name: &str,
    revision: &str,
    proof: &str,
    selector: &ApiTriggeredRedisSelector,
) -> Result<ApiTriggeredRedisPlan> {
    plan(
        rules_path,
        replay_path,
        source,
        selector.rule(name, revision, proof),
    )
}

pub(super) fn plan(
    rules_path: &Path,
    replay_path: &Path,
    source: &Path,
    rule: BackgroundDependencyRuleConfig,
) -> Result<ApiTriggeredDependencyPlan> {
    let name = rule.name().to_string();
    let mysql = matches!(rule, BackgroundDependencyRuleConfig::Mysql { .. });

    crate::config::process_owned_dependencies::validate(std::slice::from_ref(&rule))?;
    let config = crate::config::background_feedback::plan_rule_config(rules_path, rule.clone())?;
    let proposed = crate::config::SourceTrafficPolicyConfig::parse(&config.updated, rules_path)?;
    let rules: Vec<_> = proposed
        .process_owned_dependencies
        .into_iter()
        .filter(|r| r.trigger_source().is_some())
        .collect();
    let index = super::load(source, &rules)?;
    let original_replay = fs::read(replay_path)?;
    let raw = std::str::from_utf8(&original_replay)?;
    let replay: Value = serde_json::from_str(raw)?;
    ensure!(
        replay["version"].as_u64().is_some_and(|v| v >= 6) && replay["finalized"] == true,
        "API trigger plan requires finalized version-6-or-newer Replay evidence"
    );
    let mut case_ids = BTreeSet::new();
    let mut triggers = BTreeSet::new();
    let mut matched = 0;
    let mut consumed = BTreeMap::<String, usize>::new();
    let mut total_consumed = BTreeMap::<String, usize>::new();
    let unused = if mysql {
        &replay["unused_case_exchanges"]
    } else {
        &replay["redis"]["unused_case"]
    };
    for event in unused.as_array().into_iter().flatten() {
        let Some(case) = event["case_id"].as_str() else {
            continue;
        };
        let Some(witness) = index.witness(case, event) else {
            continue;
        };
        if witness.rule != config.effective_name {
            continue;
        }
        let key = super::evidence::key(case, event).expect("witness key");
        if mysql
            && let Some(fingerprint) = crate::config::api_trigger::mysql::key(case, event)
            && let Some(total) = index.witnesses.get(&fingerprint)
        {
            let count = total_consumed.entry(fingerprint).or_default();
            *count += 1;
            ensure!(
                *count <= total.exchanges,
                "Replay unused summaries exceed immutable API trigger witnesses"
            );
        }
        let count = consumed.entry(key).or_default();
        *count += 1;
        ensure!(
            *count <= witness.exchanges,
            "Replay unused summaries exceed immutable API trigger witnesses"
        );
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
    let mut rejections = BTreeSet::new();
    for event in unused.as_array().into_iter().flatten() {
        let Some(case) = event["case_id"].as_str() else {
            continue;
        };
        if index.witness(case, event).is_some() {
            continue;
        }
        if let Some(key) = super::evidence::key(case, event) {
            if let Some(reason) = index
                .selector_rejections
                .get(&config.effective_name)
                .and_then(|r| r.get(&key))
            {
                rejections.insert(reason.clone());
            }
            if mysql
                && crate::config::api_trigger::mysql::wire_key(case, event).is_none()
                && index.wire_witnesses.iter().any(|(wire, witness)| {
                    witness.rule == config.effective_name && wire.starts_with(&format!("{key}/"))
                })
            {
                rejections.insert("Replay summary lacks connection_id/query_sequence and identical SQL has ambiguous ownership; rerun Replay with the current engine using the existing recording; rerecording is unnecessary".into());
            }
        }
    }
    let rejections: Vec<_> = rejections.into_iter().take(8).collect();
    ensure!(
        matched > 0,
        "no unused foreign-case dependency has a unique API trigger; origins={}, ambiguous_origins={}, ambiguous_references={}; selector_rejections={:?}; inspect source capture predicates and selector fields",
        index.triggers,
        index.ambiguous_triggers,
        index.ambiguous_references,
        rejections
    );
    // Classification never repairs target-side dependency failures.
    if let BackgroundDependencyRuleConfig::Mysql { selector, .. } = &rule {
        for field in ["unmatched_queries", "unsupported_commands"] {
            ensure!(
                !replay[field].as_array().into_iter().flatten().any(|event| {
                    crate::config::process_owned_dependencies::mysql::evidence::identity_matches(
                        selector, event,
                    )
                }),
                "API trigger selector overlaps {field} target MySQL traffic"
            );
        }
    } else if let BackgroundDependencyRuleConfig::Redis { ports, command, .. } = &rule {
        for field in ["unmatched", "unsupported", "unsafe_events"] {
            ensure!(
                !replay["redis"][field]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|event| event["command"]
                        .as_str()
                        .is_some_and(|s| s.eq_ignore_ascii_case(command))
                        && ports
                            .iter()
                            .any(|p| event["target"]["port"].as_u64() == Some(u64::from(*p)))),
                "API trigger selector overlaps {field} target Redis traffic"
            );
        }
    }
    Ok(ApiTriggeredDependencyPlan {
        rules_path: rules_path.into(),
        replay_path: replay_path.into(),
        source: source.into(),
        rules,
        original_rules: config.original,
        original_replay,
        updated_rules: config.updated,
        report: ApiTriggeredDependencyReport {
            name,
            effective_name: config.effective_name,
            reused_existing: config.reused_existing,
            matched_unused_exchanges: matched,
            omitted_case_ids: case_ids.len().saturating_sub(32),
            omitted_trigger_case_ids: triggers.len().saturating_sub(32),
            matched_case_ids: case_ids.into_iter().take(32).collect(),
            trigger_case_ids: triggers.into_iter().take(32).collect(),
            ambiguous_triggers: index.ambiguous_triggers,
            ambiguous_references: index.ambiguous_references,
            ambiguous_transactions: index.ambiguous_transactions,
            unmatched_evidence_reasons: rejections,
            evidence_fingerprint: index.evidence_fingerprint,
            changed: config.changed,
            applied: false,
            diff: config.diff,
        },
    })
}
