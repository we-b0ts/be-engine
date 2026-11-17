//! Plan explicit SQL time slots from failed replay and immutable MySQL evidence.
#[cfg(test)]
use crate::policy::runtime::config::{
    DependencyProtocol, MysqlSelector, MysqlTimeFieldRule, MysqlTimeValueRule,
    ReplayDependencyRule, TargetSelector, TimeReference, TimeRule,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::collections::{BTreeMap, btree_map::Entry};
use std::path::PathBuf;

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

#[cfg(test)]
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
    report: MysqlTimeRuleReport,
}

#[cfg(test)]
pub(crate) fn configured_sql_values(
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
            anchor: crate::policy::TimeAnchor::DependencyRequestStart,
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
        Err(crate::policy::legacy_authoring_error())
    }
}

pub fn plan_mysql_time_rule(_feedback: MysqlTimeRuleFeedback) -> Result<MysqlTimeRulePlan> {
    Err(crate::policy::legacy_authoring_error())
}

#[cfg(test)]
pub(crate) fn proposed_rule(id: &str, s: &MysqlTimeSelector) -> Result<ReplayDependencyRule> {
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
