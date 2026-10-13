//! Bounded selectors for source-proven process-owned MySQL reads.
use crate::mysql::sql::{Token, tokens};
use crate::recorder::MysqlExchangeEvent;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

mod api;
pub(crate) mod evidence;
pub use crate::config::mysql_tables::MysqlTableSeries as MysqlBackgroundTableSeries;
use crate::config::mysql_tables::TableMatcher;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MysqlBackgroundSelector {
    pub target_host: String,
    pub target_port: u16,
    pub database: String,
    pub username: String,
    /// A single read with {{table}}, AS {{table}}_suffix aliases and variable literals (?).
    pub sql: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tables: Vec<String>,
    /// Identifier patterns with one `*`, for example `subtasks_*` or `*_archive`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub table_patterns: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub table_series: Option<MysqlBackgroundTableSeries>,
}

const TABLE_MARKER: &str = "__traffic_background_table__";

impl MysqlBackgroundSelector {
    pub(crate) fn validate(&self) -> Result<()> {
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
        TableMatcher::new(
            &self.tables,
            &self.table_patterns,
            self.table_series.as_ref(),
        )?;
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

    pub(crate) fn template(&self) -> Option<Vec<Token>> {
        if !self.sql.contains("{{table}}") || self.sql.contains(TABLE_MARKER) {
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
        // Only whole table identifiers and explicit projection aliases may
        // expand. Never interpolate literals or arbitrary identifier fragments.
        let expansions = template
            .iter()
            .enumerate()
            .filter(|(i, token)| {
                token.is(TABLE_MARKER)
                    || (*i < from
                        && i.checked_sub(1).is_some_and(|p| template[p].is("as"))
                        && alias_suffix(token).is_some())
            })
            .count();
        if expansions != self.sql.matches("{{table}}").count() {
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
        let Ok(tables) = TableMatcher::new(
            &self.tables,
            &self.table_patterns,
            self.table_series.as_ref(),
        ) else {
            return false;
        };
        let from = template.iter().position(|t| t.is("from")).unwrap();
        let Some(Token::Word(table)) = actual.get(from + 1) else {
            return false;
        };
        tables.matches(table)
            && instantiate(&template, table).is_some_and(|template| {
                template.len() == actual.len()
                    && template
                        .iter()
                        .zip(&actual)
                        .all(|(t, a)| t == a || (*t == Token::Placeholder && a.is_value()))
            })
    }

    pub(crate) fn matches(&self, event: &MysqlExchangeEvent) -> bool {
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
        let (Some(left), Some(right)) = (self.api_template(), other.api_template()) else {
            return false;
        };
        let (Ok(a), Ok(b)) = (
            TableMatcher::new(
                &self.tables,
                &self.table_patterns,
                self.table_series.as_ref(),
            ),
            TableMatcher::new(
                &other.tables,
                &other.table_patterns,
                other.table_series.as_ref(),
            ),
        ) else {
            return false;
        };
        match overlap_table(&left, &right) {
            Some(Some(table)) => a.matches(&table) && b.matches(&table),
            Some(None) => a.overlaps(&b),
            None => false,
        }
    }
}

// A literal projection alias can constrain an otherwise patterned table name.
// Solve that binding before intersecting the physical table selectors.
fn overlap_table(left: &[Token], right: &[Token]) -> Option<Option<String>> {
    if left.len() != right.len() {
        return None;
    }
    let mut table = None;
    for (a, b) in left.iter().zip(right) {
        let suffix = |t: &Token| {
            if t.is(TABLE_MARKER) {
                Some(String::new())
            } else {
                alias_suffix(t).map(|s| format!("_{s}"))
            }
        };
        let candidate = match (suffix(a), suffix(b)) {
            (Some(a), Some(b)) if a == b => continue,
            (Some(_), Some(_)) => return None,
            (Some(suffix), None) => literal_table(b, &suffix)?,
            (None, Some(suffix)) => literal_table(a, &suffix)?,
            (None, None)
                if a == b
                    || (*a == Token::Placeholder && b.is_value())
                    || (*b == Token::Placeholder && a.is_value()) =>
            {
                continue;
            }
            _ => return None,
        };
        if table.as_ref().is_some_and(|table| table != &candidate) {
            return None;
        }
        table = Some(candidate);
    }
    Some(table)
}

fn literal_table(token: &Token, suffix: &str) -> Option<String> {
    let Token::Word(word) = token else {
        return None;
    };
    Some(word.strip_suffix(suffix)?.to_string())
}

fn alias_suffix(token: &Token) -> Option<&str> {
    let Token::Word(word) = token else {
        return None;
    };
    let suffix = word.strip_prefix(TABLE_MARKER)?.strip_prefix('_')?;
    (!suffix.is_empty()
        && !suffix.contains(TABLE_MARKER)
        && suffix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_'))
    .then_some(suffix)
}

fn instantiate(template: &[Token], table: &str) -> Option<Vec<Token>> {
    template
        .iter()
        .map(|token| {
            if token.is(TABLE_MARKER) {
                Some(Token::Word(table.to_owned()))
            } else if let Some(suffix) = alias_suffix(token) {
                let alias = format!("{table}_{suffix}");
                (alias.len() <= 256).then_some(Token::Word(alias))
            } else {
                Some(token.clone())
            }
        })
        .collect()
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
            table_patterns: Vec::new(),
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
        let matches = |sql: &str| {
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

    #[test]
    fn shard_aliases_bind_to_the_same_bounded_physical_table() {
        let mut s = selector();
        s.sql = "SELECT {{table}}.id AS {{table}}_id FROM {{table}} WHERE {{table}}.status='RUNNING' AND {{table}}.created_at>=?".into();
        s.validate().unwrap();
        let matches = |sql: &str| {
            s.matches_query(
                Some("mysql.internal"),
                Some(3306),
                Some("appdb"),
                Some("root"),
                "COM_QUERY",
                Some(sql),
            )
        };
        for table in ["video_tasks", "video_tasks_0000", "video_tasks_1023"] {
            assert!(matches(&format!(
                "SELECT `{table}`.id AS `{table}_id` FROM `{table}` WHERE `{table}`.status='RUNNING' AND `{table}`.created_at>='2026-09-05'"
            )));
        }
        for sql in [
            "SELECT video_tasks_0000.id AS video_tasks_0001_id FROM video_tasks_0000 WHERE video_tasks_0000.status='RUNNING' AND video_tasks_0000.created_at>=1",
            "SELECT video_tasks_0001.id AS video_tasks_0000_id FROM video_tasks_0000 WHERE video_tasks_0000.status='RUNNING' AND video_tasks_0000.created_at>=1",
            "SELECT video_tasks_1024.id AS video_tasks_1024_id FROM video_tasks_1024 WHERE video_tasks_1024.status='RUNNING' AND video_tasks_1024.created_at>=1",
            "SELECT video_tasks_0000.id AS video_tasks_0000_id FROM video_tasks_0000 WHERE video_tasks_0000.status='DONE' AND video_tasks_0000.created_at>=1",
            "SELECT video_tasks_0000.name AS video_tasks_0000_id FROM video_tasks_0000 WHERE video_tasks_0000.status='RUNNING' AND video_tasks_0000.created_at>=1",
        ] {
            assert!(!matches(sql), "{sql}");
        }
        let mut literal_alias = s.clone();
        literal_alias.tables = vec!["video_tasks_0000".into()];
        literal_alias.table_series = None;
        literal_alias.sql = s.sql.replace("{{table}}_id", "video_tasks_0000_id");
        assert!(s.overlaps(&literal_alias));
        assert!(literal_alias.overlaps(&s));
        literal_alias.sql = s.sql.replace("{{table}}_id", "unrelated_id");
        assert!(!s.overlaps(&literal_alias));
    }

    #[test]
    fn table_expansion_rejects_literals_and_arbitrary_identifier_fragments() {
        for sql in [
            "SELECT '{{table}}' FROM {{table}} WHERE status='RUNNING'",
            "SELECT id AS prefix_{{table}} FROM {{table}} WHERE status='RUNNING'",
            "SELECT {{table}}_id FROM {{table}} WHERE status='RUNNING'",
            "SELECT id AS {{table}}_ FROM {{table}} WHERE status='RUNNING'",
            "SELECT id AS {{table}}_{{table}} FROM {{table}} WHERE status='RUNNING'",
            "SELECT id FROM {{table}} WHERE status='{{table}}'",
            "SELECT __traffic_background_table__ FROM {{table}} WHERE status='RUNNING'",
        ] {
            let mut s = selector();
            s.sql = sql.into();
            assert!(s.validate().is_err(), "{sql}");
        }
    }

    #[test]
    fn table_patterns_match_identifier_affixes_without_loosening_sql() {
        let mut s = selector();
        s.tables.clear();
        s.table_series = None;
        s.table_patterns = vec![
            "video_tasks_*".into(),
            "*_archive".into(),
            "recovery_*_pending".into(),
        ];
        s.sql = "SELECT {{table}}.id AS {{table}}_id FROM {{table}} WHERE status='RUNNING' AND created_at>=?".into();
        s.validate().unwrap();
        let matches = |table: &str, status: &str, alias: &str| {
            s.matches_query(
            Some("mysql.internal"), Some(3306), Some("appdb"), Some("root"), "COM_QUERY",
            Some(&format!("SELECT {table}.id AS {alias} FROM {table} WHERE status='{status}' AND created_at>=1")))
        };
        for table in [
            "video_tasks_0640",
            "video_tasks_east",
            "tasks_archive",
            "recovery_us_pending",
        ] {
            assert!(matches(table, "RUNNING", &format!("{table}_id")), "{table}");
            assert!(!matches(table, "DONE", &format!("{table}_id")));
            assert!(!matches(table, "RUNNING", "other_table_id"));
        }
        for table in [
            "video_tasks",
            "other_tasks_0640",
            "tasks_archived",
            "recovery_us_done",
            "Video_tasks_0640",
        ] {
            assert!(
                !matches(table, "RUNNING", &format!("{table}_id")),
                "{table}"
            );
        }
    }

    #[test]
    fn pattern_overlap_obeys_table_and_alias_constraints() {
        let mut a = selector();
        a.tables.clear();
        a.table_series = None;
        a.table_patterns = vec!["video_tasks_*".into()];
        a.sql = "SELECT id AS {{table}}_id FROM {{table}} WHERE status='RUNNING'".into();
        let mut b = a.clone();
        b.table_patterns = vec!["*_archive".into()];
        assert!(a.overlaps(&b) && b.overlaps(&a));
        b.sql = b.sql.replace("{{table}}_id", "video_tasks_east_archive_id");
        assert!(a.overlaps(&b) && b.overlaps(&a));
        b.sql = b
            .sql
            .replace("video_tasks_east_archive_id", "video_tasks_east_id");
        assert!(!a.overlaps(&b) && !b.overlaps(&a));
        b = a.clone();
        b.table_patterns = vec!["other_*".into()];
        assert!(!a.overlaps(&b));
        b.table_patterns.clear();
        b.tables = vec!["video_tasks_0640".into()];
        assert!(a.overlaps(&b));
        b.tables.clear();
        b.table_series = selector().table_series;
        assert!(a.overlaps(&b));
        b.sql = b.sql.replace("RUNNING", "DONE");
        assert!(!a.overlaps(&b));
    }

    #[test]
    fn table_pattern_validation_and_identifier_length_are_bounded() {
        let mut s = selector();
        s.tables.clear();
        s.table_series = None;
        for pattern in [
            "*",
            "",
            "tasks",
            "**",
            "tasks_*_*",
            "tasks_%",
            "db.tasks_*",
            "1tasks_*",
            "tasks_*;",
            "任务_*",
        ] {
            s.table_patterns = vec![pattern.into()];
            assert!(s.validate().is_err(), "{pattern}");
        }
        s.table_patterns = vec!["tasks_*".into(), "tasks_*".into()];
        assert!(s.validate().is_err());
        s.table_patterns = vec![format!("{}*", "a".repeat(64))];
        s.validate().unwrap();
        let matcher =
            TableMatcher::new(&s.tables, &s.table_patterns, s.table_series.as_ref()).unwrap();
        assert!(matcher.matches(&"a".repeat(64)));
        assert!(!matcher.matches(&"a".repeat(65)));
        let mut b = s.clone();
        b.table_patterns = vec!["*_z".into()];
        assert!(!s.overlaps(&b));
        // Optional patterns keep existing persisted selectors compatible.
        let mut serialized = serde_json::to_value(selector()).unwrap();
        serialized.as_object_mut().unwrap().remove("table_patterns");
        let old: MysqlBackgroundSelector = serde_json::from_value(serialized).unwrap();
        assert!(old.table_patterns.is_empty());
        old.validate().unwrap();
    }
}
