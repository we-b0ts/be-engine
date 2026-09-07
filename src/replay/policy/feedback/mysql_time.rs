//! Plan explicit SQL time slots from failed replay and immutable MySQL evidence.
mod evidence;
use super::document::{render_dependency_rules, replace_dependency_rules};
use crate::config::edit::write_atomic;
use crate::replay::policy::config::{
    DependencyProtocol, MysqlSelector, MysqlTimeValueRule, ReplayDependencyRule, TargetSelector,
    TimeReference, TimeRule, load_replay_policy,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, path::PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MysqlTimeSelector {
    pub target_host: String,
    pub target_port: u16,
    pub database: String,
    pub username: String,
    pub sql: String,
    pub value_index: usize,
    pub tolerance: String,
    pub offset: String,
    pub format: String,
    pub timezone: String,
}

#[derive(Debug, Clone)]
pub struct MysqlTimeRuleFeedback {
    pub policy_path: PathBuf,
    pub replay_report_path: PathBuf,
    pub api: String,
    pub rule_id: String,
    pub selector: MysqlTimeSelector,
    pub source_evidence: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MysqlTimeRuleReport {
    pub policy: PathBuf,
    pub policy_fingerprint: String,
    pub requested_rule_id: String,
    pub effective_rule_id: String,
    pub selector: MysqlTimeSelector,
    pub source_evidence: String,
    pub evidence_case_id: String,
    pub reused_existing: bool,
    pub changed: bool,
    pub applied: bool,
    pub diff: String,
}

pub struct MysqlTimeRulePlan {
    original: String,
    updated: String,
    report: MysqlTimeRuleReport,
}

impl MysqlTimeRulePlan {
    pub fn report(&self) -> &MysqlTimeRuleReport {
        &self.report
    }
    pub fn apply(self) -> Result<MysqlTimeRuleReport> {
        ensure!(
            fs::read_to_string(&self.report.policy)? == self.original,
            "replay policy changed after planning; rerun plan before applying"
        );
        if self.report.changed {
            write_atomic(&self.report.policy, self.updated.as_bytes())?;
        }
        Ok(MysqlTimeRuleReport {
            applied: true,
            ..self.report
        })
    }
}

pub fn plan_mysql_time_rule(feedback: MysqlTimeRuleFeedback) -> Result<MysqlTimeRulePlan> {
    let original = fs::read_to_string(&feedback.policy_path)?;
    let mut loaded = load_replay_policy(&feedback.policy_path)?;
    let s = &feedback.selector;
    ensure!(
        !s.database.trim().is_empty() && s.target_port > 0,
        "SQL time rule requires a database and a valid evidence endpoint port"
    );
    crate::config::process_owned_dependencies::validate_source_evidence(&feedback.source_evidence)?;
    let time = TimeRule {
        relative_to: TimeReference::ReplayNow,
        offset: s.offset.clone(),
        tolerance: s.tolerance.clone(),
        format: Some(s.format.clone()),
        timezone: Some(s.timezone.clone()),
    };
    let proposed = ReplayDependencyRule {
        id: feedback.rule_id.clone(),
        case_selector: None,
        protocol: DependencyProtocol::Mysql,
        target: TargetSelector::default(),
        mysql: Some(MysqlSelector {
            command: "COM_QUERY".into(),
            sql: s.sql.clone(),
            database: Some(s.database.clone()),
            username: None,
            params: BTreeMap::new(),
            sql_values: BTreeMap::from([(
                s.value_index,
                MysqlTimeValueRule {
                    source_evidence: String::new(),
                    time: time.clone(),
                },
            )]),
        }),
        http: None,
        memcached: None,
    };
    // Validate before opening evidence so invalid slots cannot index values.
    let mut document = loaded.document.clone();
    document.dependency_rules = vec![proposed.clone()];
    super::super::config::validate_document(&document)?;
    let evidence_case_id = evidence::validate(&feedback, &time)?;
    let mut shape = serde_json::to_value(&proposed)?;
    shape.as_object_mut().unwrap().remove("id");
    let reusable = loaded.document.dependency_rules.iter().find_map(|rule| {
        let mut other = serde_json::to_value(rule).ok()?;
        other.as_object_mut()?.remove("id");
        (other == shape).then_some(rule.id.clone())
    });
    ensure!(
        loaded.document.dependency_rules.iter().all(
            |rule| rule.id != feedback.rule_id || reusable.as_deref() == Some(rule.id.as_str())
        ),
        "SQL time rule id already selects different fields or validation"
    );
    let reused_existing = reusable.is_some();
    let effective_rule_id = reusable.unwrap_or_else(|| feedback.rule_id.clone());
    if !reused_existing {
        loaded.document.dependency_rules.push(proposed);
    }
    let updated = replace_dependency_rules(&original, &loaded.document.dependency_rules)?;
    let changed = original != updated;
    let diff = if changed {
        format!(
            "--- {}\n+++ {}\n@@ dependency_rules @@\n{}",
            feedback.policy_path.display(),
            feedback.policy_path.display(),
            render_dependency_rules(&loaded.document.dependency_rules)?
        )
    } else {
        String::new()
    };
    Ok(MysqlTimeRulePlan {
        original,
        updated,
        report: MysqlTimeRuleReport {
            policy: feedback.policy_path,
            policy_fingerprint: loaded.fingerprint,
            requested_rule_id: feedback.rule_id,
            effective_rule_id,
            selector: feedback.selector,
            source_evidence: feedback.source_evidence,
            evidence_case_id,
            reused_existing,
            changed,
            applied: false,
            diff,
        },
    })
}

#[cfg(test)]
mod tests;
