//! Joint identity/time planning reuses the ordinary capture and SQL time contracts.
#[cfg(test)]
use super::*;
#[cfg(test)]
use crate::policy::runtime::{config::ReplayDependencyRule, dynamic_values::DynamicValueCapture};
#[cfg(test)]
mod overlap;
#[cfg(test)]
use overlap::validate as validate_time_overlaps;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DynamicValueMysqlTimeRule {
    pub id: String,
    pub time_values: Vec<crate::MysqlTimeValueSelector>,
    pub source_evidence: String,
}

#[cfg(test)]
impl DynamicValueMysqlTimeRule {
    pub(crate) fn proposed(&self, identity: &DynamicValueRule) -> Result<ReplayDependencyRule> {
        let DynamicValueCapture::Mysql {
            target,
            database,
            sql,
            tables,
            table_patterns,
            table_series,
            value_index,
            json_pointer,
        } = &identity.capture
        else {
            anyhow::bail!("a MySQL time companion requires a MySQL dynamic capture");
        };
        ensure!(
            self.id != identity.id,
            "identity and time rules require distinct ids"
        );
        ensure!(
            self.time_values.iter().all(|time| {
                time.value_index != *value_index
                    || match (json_pointer, &time.json_pointer) {
                        (Some(identity), Some(time)) => {
                            !crate::policy::runtime::response_locations_overlap(identity, time)
                        }
                        _ => false,
                    }
            }),
            "identity and time selections overlap"
        );
        crate::config::process_owned_dependencies::validate_source_evidence(&self.source_evidence)?;
        let mut rule = super::super::mysql_time::proposed_rule(
            &self.id,
            &crate::MysqlTimeSelector {
                target_host: target.host.clone(),
                target_port: target.port,
                database: database.clone(),
                username: String::new(),
                sql: sql.clone(),
                tables: tables.clone(),
                table_patterns: table_patterns.clone(),
                table_series: table_series.clone(),
                time_values: self.time_values.clone(),
            },
        )?;
        rule.target.host = Some(target.host.clone());
        rule.target.port = Some(target.port);
        rule.when = identity.when.clone();
        for value in rule
            .mysql
            .as_mut()
            .expect("MySQL time selector")
            .sql_values
            .values_mut()
        {
            match value {
                crate::policy::runtime::config::MysqlTimeValueRule::Scalar(field) => {
                    field.source_evidence = self.source_evidence.clone();
                }
                crate::policy::runtime::config::MysqlTimeValueRule::Json(fields) => {
                    for field in fields.values_mut() {
                        field.source_evidence = self.source_evidence.clone();
                    }
                }
            }
        }
        Ok(rule)
    }
}

#[cfg(test)]
mod tests;
