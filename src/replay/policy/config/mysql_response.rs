//! Schema and bounded selectors for source-proven MySQL result timestamps.
use super::*;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::replay::policy) struct MysqlResponseTimeField {
    pub time: super::TimeReference,
    pub format: MysqlResponseTimeFormat,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preserve_values: Vec<String>,
}

impl MysqlResponseTimeField {
    pub(in crate::replay::policy) fn preserved_values(
        &self,
    ) -> Result<BTreeSet<chrono::NaiveDateTime>> {
        ensure!(
            self.preserve_values.len() <= 16,
            "MySQL time shift supports at most sixteen fixed values per column"
        );
        let values = self
            .preserve_values
            .iter()
            .map(|value| crate::replay::mysql::time_shift::parse_datetime(value))
            .collect::<Result<BTreeSet<_>>>()?;
        ensure!(
            values.len() == self.preserve_values.len(),
            "duplicate fixed MySQL time value"
        );
        Ok(values)
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::replay::policy) enum MysqlResponseTimeFormat {
    MysqlDatetime,
}

pub(in crate::replay::policy) fn validate_rule(rule: &ReplayDependencyRule) -> Result<()> {
    let mysql = rule
        .mysql
        .as_ref()
        .context("MySQL response time rule requires mysql")?;
    ensure!(
        rule.case_selector.is_some()
            && rule.target.host.is_some()
            && rule.target.port.is_some()
            && mysql.database.is_some(),
        "MySQL response time shift requires an API case, exact endpoint and database"
    );
    ensure!(
        rule.replay_scope == ReplayScope::Case
            && rule
                .target
                .host
                .as_ref()
                .is_some_and(|host| !host.is_empty() && !host.contains(['*', '?']))
            && rule.target.port.is_some_and(|port| port != 0)
            && mysql
                .database
                .as_ref()
                .is_some_and(|database| !database.is_empty())
            && matches!(mysql.command.as_str(), "COM_QUERY" | "COM_STMT_EXECUTE"),
        "MySQL response time shift requires a case-owned SELECT at an exact endpoint"
    );
    ensure!(
        mysql.params.is_empty() && mysql.sql_values.is_empty(),
        "MySQL response time shift must be separate from request value rules"
    );
    ensure!(
        (1..=32).contains(&mysql.response_time_shift.len()),
        "MySQL response time shift requires 1..32 columns"
    );
    crate::config::process_owned_dependencies::validate_source_evidence(&rule.source_evidence)?;
    let template = crate::replay::policy::sql_template::SqlValueTemplate::new(
        &mysql.sql,
        &mysql.tables,
        &mysql.table_patterns,
        mysql.table_series.as_ref(),
    )?;
    ensure!(
        template.tokens().first().is_some_and(|t| t.is("select")),
        "MySQL response time shift requires a SELECT template"
    );
    ensure!(
        mysql
            .response_time_shift
            .keys()
            .all(|name| !name.is_empty() && name.len() <= 128 && !name.contains(['*', '\0'])),
        "MySQL response time shift requires exact column names"
    );
    for field in mysql.response_time_shift.values() {
        field.preserved_values()?;
    }
    Ok(())
}
