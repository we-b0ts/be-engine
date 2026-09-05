//! Bounded selectors for source-proven process-owned MySQL reads.
use crate::mysql::sql::{Token, tokens};
use crate::recorder::MysqlExchangeEvent;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MysqlBackgroundSelector {
    pub target_host: String,
    pub target_port: u16,
    pub database: String,
    pub username: String,
    /// A single read with {{table}} and explicitly variable literal positions (?).
    pub sql: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tables: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub table_series: Option<MysqlBackgroundTableSeries>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MysqlBackgroundTableSeries {
    pub prefix: String,
    pub start: u32,
    pub end: u32,
    pub width: usize,
}

const TABLE_MARKER: &str = "__traffic_background_table__";

impl MysqlBackgroundSelector {
    pub(super) fn validate(&self) -> Result<()> {
        super::validate_single_line("MySQL target host", &self.target_host, 253)?;
        ensure!(
            self.target_host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b)),
            "MySQL selector requires an exact host"
        );
        ensure!(self.target_port > 0, "MySQL selector port must be nonzero");
        super::validate_single_line("MySQL database", &self.database, 64)?;
        super::validate_single_line("MySQL username", &self.username, 128)?;
        super::validate_single_line("MySQL SQL selector", &self.sql, 8192)?;
        let tables = self.table_names()?;
        ensure!(
            !tables.is_empty(),
            "MySQL selector requires tables or a bounded table_series"
        );
        let template = self.template().ok_or_else(|| anyhow::anyhow!("MySQL selector requires one read-only SELECT with FROM {{{{table}}}} and a WHERE clause"))?;
        ensure!(
            template
                .iter()
                .filter(|t| **t == Token::Placeholder)
                .count()
                <= 16,
            "MySQL selector has too many variable positions"
        );
        Ok(())
    }

    pub(crate) fn table_names(&self) -> Result<std::collections::BTreeSet<String>> {
        ensure!(
            self.tables.len() <= 4096,
            "MySQL selector has too many tables"
        );
        let mut tables = self
            .tables
            .iter()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        ensure!(
            tables.len() == self.tables.len(),
            "MySQL selector tables must be unique"
        );
        if let Some(series) = &self.table_series {
            ensure!(
                series.start <= series.end
                    && series.end - series.start < 4096
                    && series.width <= 10,
                "MySQL table series must be bounded to at most 4096 tables and width <= 10"
            );
            for suffix in series.start..=series.end {
                tables.insert(format!(
                    "{}{:0width$}",
                    series.prefix,
                    suffix,
                    width = series.width
                ));
            }
        }
        ensure!(tables.len() <= 4096, "MySQL selector has too many tables");
        for name in &tables {
            ensure!(
                !name.is_empty()
                    && name.len() <= 64
                    && !name.as_bytes()[0].is_ascii_digit()
                    && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'),
                "MySQL selector tables must be ASCII identifiers"
            );
        }
        Ok(tables)
    }

    fn template(&self) -> Option<Vec<Token>> {
        if !self.sql.contains("{{table}}") {
            return None;
        }
        let sql = self.sql.replace("{{table}}", TABLE_MARKER);
        let access = crate::mysql::access::analyze_sql(&sql);
        if access.class != crate::access_policy::OperationClass::Read || !access.statements_complete
        {
            return None;
        }
        let template = tokens(&sql)?;
        if !template.first()?.is("select") || !template.iter().any(|t| t.is("where")) {
            return None;
        }
        if template.iter().filter(|t| t.is("select")).count() != 1 {
            return None;
        }
        if template.iter().any(|t| {
            [
                "join", "union", "into", "for", "lock", ":=", "@", "@@", "{", "}",
            ]
            .iter()
            .any(|s| t.is(s))
        }) {
            return None;
        }
        let from = template.iter().position(|t| t.is("from"))?;
        if !template.get(from + 1)?.is(TABLE_MARKER) {
            return None;
        }
        // No comma joins or extra tables. Permit an optional table alias only.
        let where_pos = template.iter().position(|t| t.is("where"))?;
        let between = template.get(from + 2..where_pos)?;
        if !matches!(between, [] | [Token::Word(_)])
            && !matches!(between, [a, Token::Word(_)] if a.is("as"))
        {
            return None;
        }
        Some(template)
    }

    pub(crate) fn matches_query(
        &self,
        host: Option<&str>,
        port: Option<u16>,
        database: Option<&str>,
        username: Option<&str>,
        command: &str,
        sql: Option<&str>,
    ) -> bool {
        if !host.is_some_and(|host| host.eq_ignore_ascii_case(&self.target_host))
            || port != Some(self.target_port)
            || database != Some(self.database.as_str())
            || username != Some(self.username.as_str())
            || !matches!(command, "COM_QUERY" | "COM_STMT_EXECUTE")
        {
            return false;
        }
        let (Some(template), Some(actual)) = (self.template(), sql.and_then(tokens)) else {
            return false;
        };
        let Ok(tables) = self.table_names() else {
            return false;
        };
        let mut physical_table = None;
        template.len() == actual.len()
            && template.iter().zip(&actual).all(|(t, a)| {
                if t.is(TABLE_MARKER) {
                    let Token::Word(name) = a else {
                        return false;
                    };
                    if !tables.contains(name) {
                        return false;
                    }
                    if let Some(previous) = physical_table {
                        previous == name
                    } else {
                        physical_table = Some(name);
                        true
                    }
                } else {
                    t == a || (*t == Token::Placeholder && a.is_value())
                }
            })
    }

    pub(super) fn matches(&self, event: &MysqlExchangeEvent) -> bool {
        event.parse_warnings.is_empty()
            && !event.response.rows_truncated
            && event.response.status == "resultset"
            && self.matches_query(
                event.target_host.as_deref(),
                event.target_port,
                event.database.as_deref(),
                event.username.as_deref(),
                &event.command,
                event.sql.as_deref(),
            )
    }

    pub(super) fn overlaps(&self, other: &Self) -> bool {
        if !self.target_host.eq_ignore_ascii_case(&other.target_host)
            || self.target_port != other.target_port
            || self.database != other.database
            || self.username != other.username
        {
            return false;
        }
        let (Some(left), Some(right)) = (self.template(), other.template()) else {
            return false;
        };
        let shape = left.len() == right.len()
            && left.iter().zip(&right).all(|(a, b)| {
                a == b
                    || (*a == Token::Placeholder && b.is_value())
                    || (*b == Token::Placeholder && a.is_value())
            });
        shape
            && self
                .table_names()
                .ok()
                .zip(other.table_names().ok())
                .is_some_and(|(a, b)| !a.is_disjoint(&b))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn selector() -> MysqlBackgroundSelector {
        MysqlBackgroundSelector {
            target_host: "mysql.internal".into(),
            target_port: 3306,
            database: "appdb".into(),
            username: "root".into(),
            sql: "SELECT id FROM {{table}} WHERE status='RUNNING' AND created_at>=?".into(),
            tables: vec!["video_tasks".into()],
            table_series: Some(MysqlBackgroundTableSeries {
                prefix: "video_tasks_".into(),
                start: 0,
                end: 1023,
                width: 4,
            }),
        }
    }
    #[test]
    fn bounds_background_reads_by_identity_table_and_predicate() {
        let s = selector();
        s.validate().unwrap();
        let matches = |sql| {
            s.matches_query(
                Some("mysql.internal"),
                Some(3306),
                Some("appdb"),
                Some("root"),
                "COM_QUERY",
                Some(sql),
            )
        };
        assert!(matches(
            "SELECT id FROM video_tasks_0509 WHERE status='RUNNING' AND created_at>='2026-09-05'"
        ));
        assert!(matches(
            "SELECT id FROM video_tasks WHERE status='RUNNING' AND created_at>='2026-09-05'"
        ));
        assert!(!matches(
            "SELECT id FROM video_tasks_1024 WHERE status='RUNNING' AND created_at>='2026-09-05'"
        ));
        assert!(!matches(
            "SELECT id FROM video_tasks_0509 WHERE status='DONE' AND created_at>='2026-09-05'"
        ));
        assert!(!matches(
            "SELECT id FROM video_tasks_0509 WHERE status='RUNNING'"
        ));
        assert!(!s.matches_query(
            Some("other.internal"),
            Some(3306),
            Some("appdb"),
            Some("root"),
            "COM_QUERY",
            Some("SELECT id FROM video_tasks WHERE status='RUNNING' AND created_at>=1")
        ));
        assert!(s.overlaps(&s));
    }
    #[test]
    fn rejects_broad_write_and_unbounded_selectors() {
        for sql in [
            "DELETE FROM {{table}} WHERE id=?",
            "SELECT * FROM {{table}}",
            "SELECT * FROM {{table}} WHERE id=? FOR UPDATE",
            "SELECT * FROM {{table}}, users WHERE id=?",
            "SELECT * FROM {{table}} WHERE id=?; DELETE FROM users",
        ] {
            let mut s = selector();
            s.sql = sql.into();
            assert!(s.validate().is_err(), "{sql}");
        }
        let mut s = selector();
        s.table_series.as_mut().unwrap().end = u32::MAX;
        assert!(s.validate().is_err());
    }
}
