//! Plan explicit SQL time slots from failed replay and immutable MySQL evidence.
mod evidence;
use super::document::{render_dependency_rules, replace_dependency_rules};
use crate::config::edit::write_atomic;
use crate::replay::policy::config::{
    DependencyProtocol, MysqlSelector, MysqlTimeFieldRule, MysqlTimeValueRule,
    ReplayDependencyRule, TargetSelector, TimeReference, TimeRule, load_replay_policy,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, btree_map::Entry},
    fs,
    path::PathBuf,
};

fn default_tolerance() -> String {
    "5s".into()
}

fn default_offset() -> String {
    "0s".into()
}

fn default_format() -> String {
    "%Y-%m-%d %H:%M:%S%.f".into()
}

fn default_timezone() -> String {
    "+00:00".into()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MysqlTimeValueSelector {
    pub value_index: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json_pointer: Option<String>,
    #[serde(default = "default_tolerance", skip_serializing)]
    pub tolerance: String,
    #[serde(default = "default_offset", skip_serializing)]
    pub offset: String,
    #[serde(default = "default_format")]
    pub format: String,
    #[serde(default = "default_timezone", skip_serializing)]
    pub timezone: String,
}

impl MysqlTimeValueSelector {
    fn time_rule(&self) -> TimeRule {
        TimeRule {
            relative_to: TimeReference::PreserveRelative,
            offset: "0s".into(),
            tolerance: self.tolerance.clone(),
            format: Some(self.format.clone()),
            timezone: Some(default_timezone()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "MysqlTimeSelectorConfig", into = "MysqlTimeSelectorOutput")]
pub struct MysqlTimeSelector {
    pub target_host: String,
    pub target_port: u16,
    pub database: String,
    pub username: String,
    pub sql: String,
    pub tables: Vec<String>,
    pub table_patterns: Vec<String>,
    pub table_series: Option<crate::MysqlTableSeries>,
    pub time_values: Vec<MysqlTimeValueSelector>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum MysqlTimeSelectorOutput {
    Legacy {
        target_host: String,
        target_port: u16,
        database: String,
        username: String,
        sql: String,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        tables: Vec<String>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        table_patterns: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        table_series: Option<crate::MysqlTableSeries>,
        value_index: usize,
        format: String,
    },
    Multiple {
        target_host: String,
        target_port: u16,
        database: String,
        username: String,
        sql: String,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        tables: Vec<String>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        table_patterns: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        table_series: Option<crate::MysqlTableSeries>,
        time_values: Vec<MysqlTimeValueSelector>,
    },
}

impl From<MysqlTimeSelector> for MysqlTimeSelectorOutput {
    fn from(selector: MysqlTimeSelector) -> Self {
        let MysqlTimeSelector {
            target_host,
            target_port,
            database,
            username,
            sql,
            tables,
            table_patterns,
            table_series,
            mut time_values,
        } = selector;
        if time_values.len() == 1 && time_values[0].json_pointer.is_none() {
            let selected = time_values.pop().expect("one selected MySQL time value");
            Self::Legacy {
                target_host,
                target_port,
                database,
                username,
                sql,
                tables,
                table_patterns,
                table_series,
                value_index: selected.value_index,
                format: selected.format,
            }
        } else {
            Self::Multiple {
                target_host,
                target_port,
                database,
                username,
                sql,
                tables,
                table_patterns,
                table_series,
                time_values,
            }
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MysqlTimeSelectorConfig {
    target_host: String,
    target_port: u16,
    database: String,
    username: String,
    sql: String,
    #[serde(default)]
    tables: Vec<String>,
    #[serde(default)]
    table_patterns: Vec<String>,
    #[serde(default)]
    table_series: Option<crate::MysqlTableSeries>,
    #[serde(default)]
    time_values: Vec<MysqlTimeValueSelector>,
    #[serde(default)]
    value_index: Option<usize>,
    #[serde(default)]
    tolerance: Option<String>,
    #[serde(default)]
    offset: Option<String>,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    timezone: Option<String>,
}

impl TryFrom<MysqlTimeSelectorConfig> for MysqlTimeSelector {
    type Error = anyhow::Error;

    fn try_from(config: MysqlTimeSelectorConfig) -> Result<Self> {
        let legacy_options_present = config.tolerance.is_some()
            || config.offset.is_some()
            || config.format.is_some()
            || config.timezone.is_some();
        let time_values = if config.time_values.is_empty() {
            vec![MysqlTimeValueSelector {
                value_index: config
                    .value_index
                    .context("MySQL time selector requires at least one time value")?,
                json_pointer: None,
                tolerance: config.tolerance.unwrap_or_else(default_tolerance),
                offset: config.offset.unwrap_or_else(default_offset),
                format: config.format.unwrap_or_else(default_format),
                timezone: config.timezone.unwrap_or_else(default_timezone),
            }]
        } else {
            ensure!(
                config.value_index.is_none() && !legacy_options_present,
                "MySQL time selector cannot combine time_values with legacy value options"
            );
            config.time_values
        };
        Ok(Self {
            target_host: config.target_host,
            target_port: config.target_port,
            database: config.database,
            username: config.username,
            sql: config.sql,
            tables: config.tables,
            table_patterns: config.table_patterns,
            table_series: config.table_series,
            time_values,
        })
    }
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

impl MysqlTimeRuleFeedback {
    /// Shared by SQL-time admission and coordinator recovery; no policy mutation.
    pub(crate) fn policy_evidence_stale(
        policy_path: &std::path::Path,
        report: &serde_json::Value,
    ) -> Result<bool> {
        let loaded = load_replay_policy(policy_path)?;
        Ok(dynamic_policy_stale(&loaded, report))
    }
}

fn dynamic_policy_stale(
    loaded: &super::super::config::LoadedReplayPolicy,
    report: &serde_json::Value,
) -> bool {
    // Legacy SQL-time evidence without dynamic bindings remains usable.
    !loaded.document.dynamic_values.is_empty()
        && report["replay_policy"]["fingerprint"].as_str() != Some(loaded.fingerprint.as_str())
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

pub(in crate::replay::policy::feedback) fn configured_sql_values(
    selector: &MysqlTimeSelector,
) -> Result<BTreeMap<usize, MysqlTimeValueRule>> {
    ensure!(
        !selector.time_values.is_empty(),
        "SQL time rule requires at least one selected time value"
    );
    let mut configured = BTreeMap::new();
    for selected in &selector.time_values {
        let field = MysqlTimeFieldRule {
            source_evidence: String::new(),
            time: selected.time_rule(),
        };
        match (
            configured.entry(selected.value_index),
            &selected.json_pointer,
        ) {
            (Entry::Vacant(entry), None) => {
                entry.insert(MysqlTimeValueRule::Scalar(field));
            }
            (Entry::Vacant(entry), Some(pointer)) => {
                entry.insert(MysqlTimeValueRule::Json(BTreeMap::from([(
                    pointer.clone(),
                    field,
                )])));
            }
            (Entry::Occupied(_), None) => anyhow::bail!(
                "SQL time slot {} cannot select multiple scalar or JSON time values",
                selected.value_index
            ),
            (Entry::Occupied(mut entry), Some(pointer)) => {
                let MysqlTimeValueRule::Json(fields) = entry.get_mut() else {
                    anyhow::bail!(
                        "SQL time slot {} cannot combine scalar and JSON time values",
                        selected.value_index
                    );
                };
                ensure!(
                    fields.insert(pointer.clone(), field).is_none(),
                    "SQL time slot {} repeats JSON Pointer {pointer:?}",
                    selected.value_index
                );
            }
        }
    }
    Ok(configured)
}

impl MysqlTimeRulePlan {
    pub fn report(&self) -> &MysqlTimeRuleReport {
        &self.report
    }
    pub fn apply(self) -> Result<MysqlTimeRuleReport> {
        crate::policy::retired_authoring()?;
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
    crate::policy::retired_authoring()?;
    let original = fs::read_to_string(&feedback.policy_path)?;
    let mut loaded = load_replay_policy(&feedback.policy_path)?;
    let s = &feedback.selector;
    ensure!(
        !s.database.trim().is_empty() && s.target_port > 0,
        "SQL time rule requires a database and a valid evidence endpoint port"
    );
    crate::config::process_owned_dependencies::validate_source_evidence(&feedback.source_evidence)?;
    let sql_values = configured_sql_values(s)?;
    let proposed = proposed_rule(&feedback.rule_id, s)?;
    // Validate before opening evidence so invalid slots cannot index values.
    let mut document = loaded.document.clone();
    document.dependency_rules = vec![proposed.clone()];
    super::super::config::validate_document(&document)?;
    let evidence_case_id = evidence::validate(&feedback, &sql_values)?;
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
    let updated = replace_dependency_rules(&original, &loaded.document)?;
    let changed = original != updated;
    let diff = if changed {
        format!(
            "--- {}\n+++ {}\n@@ dependency_rules @@\n{}",
            feedback.policy_path.display(),
            feedback.policy_path.display(),
            render_dependency_rules(&loaded.document)?
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

pub(in crate::replay::policy::feedback) fn proposed_rule(
    id: &str,
    s: &MysqlTimeSelector,
) -> Result<ReplayDependencyRule> {
    Ok(ReplayDependencyRule {
        id: id.into(),
        replay_scope: Default::default(),
        source_evidence: String::new(),
        when: None,
        case_selector: None,
        redis: None,
        protocol: DependencyProtocol::Mysql,
        target: TargetSelector::default(),
        mysql: Some(MysqlSelector {
            response_time_shift: BTreeMap::new(),
            command: "COM_QUERY".into(),
            sql: s.sql.clone(),
            tables: s.tables.clone(),
            table_patterns: s.table_patterns.clone(),
            table_series: s.table_series.clone(),
            database: Some(s.database.clone()),
            username: None,
            params: BTreeMap::new(),
            sql_values: configured_sql_values(s)?,
        }),
        http: None,
        memcached: None,
    })
}

#[cfg(test)]
mod tests;
