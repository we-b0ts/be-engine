//! Compile immutable MySQL rule selectors once per loaded Replay policy.
//! Request anchors, parameter values and consumption remain live caller state.
use super::*;
use crate::replay::policy::sql_template::SqlValueTemplate;

#[derive(Debug)]
enum SqlSelector {
    Pattern(String),
    Template(SqlValueTemplate),
}

#[derive(Debug)]
pub(in crate::replay::policy) struct MysqlSelectors {
    sql: BTreeMap<String, SqlSelector>,
}

impl MysqlSelectors {
    pub(in crate::replay::policy) fn new(rules: &[ReplayDependencyRule]) -> Result<Self> {
        let mut sql = BTreeMap::new();
        for rule in rules
            .iter()
            .filter(|rule| rule.protocol == DependencyProtocol::Mysql)
        {
            let Some(mysql) = &rule.mysql else {
                continue;
            };
            let selector = if !mysql.sql_values.is_empty() || !mysql.response_time_shift.is_empty()
            {
                SqlSelector::Template(SqlValueTemplate::new(
                    &mysql.sql,
                    &mysql.tables,
                    &mysql.table_patterns,
                    mysql.table_series.as_ref(),
                )?)
            } else {
                SqlSelector::Pattern(crate::mysql::sql::normalize_pattern(&mysql.sql))
            };
            sql.insert(rule.id.clone(), selector);
        }
        Ok(Self { sql })
    }

    pub(super) fn template(&self, rule_id: &str) -> Option<&SqlValueTemplate> {
        match self.sql.get(rule_id)? {
            SqlSelector::Template(template) => Some(template),
            SqlSelector::Pattern(_) => None,
        }
    }

    pub(in crate::replay::policy) fn matches_sql(
        &self,
        rule: &ReplayDependencyRule,
        sql: Option<&str>,
    ) -> bool {
        let Some(sql) = sql else {
            return false;
        };
        match self.sql.get(&rule.id) {
            Some(SqlSelector::Template(template)) => template.matches(sql),
            Some(SqlSelector::Pattern(pattern)) => {
                text_pattern_matches(pattern, &normalize_sql(sql))
            }
            None => false,
        }
    }

    pub(in crate::replay::policy) fn matches(
        &self,
        rule: &ReplayDependencyRule,
        identity: &ReplaySessionIdentity,
        command: &str,
        sql: Option<&str>,
    ) -> bool {
        let Some(mysql) = &rule.mysql else {
            return false;
        };
        if !(mysql.command.eq_ignore_ascii_case(command)
            || ((!mysql.sql_values.is_empty() || !mysql.response_time_shift.is_empty())
                && matches!(command, "COM_QUERY" | "COM_STMT_EXECUTE")))
            || !rule_matches_target(rule, identity.target.as_ref())
            || mysql
                .database
                .as_deref()
                .is_some_and(|database| identity.database.as_deref() != Some(database))
            || mysql
                .username
                .as_deref()
                .is_some_and(|username| identity.username.as_deref() != Some(username))
        {
            return false;
        }
        self.matches_sql(rule, sql)
    }
}
