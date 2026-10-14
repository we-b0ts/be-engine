//! Bind one declared physical table without changing SQL values or predicates.
use super::{bounded_statement_tokens, bounded_tokens, extract};
use crate::config::mysql_tables::TableMatcher;
use crate::mysql::sql::Token;
use anyhow::{Context, Result, ensure};

const TABLE: &str = "__traffic_time_table__";

#[derive(Debug)]
pub(in crate::replay::policy) struct SqlValueTemplate {
    tokens: Vec<Token>,
    tables: Option<TableMatcher>,
}

impl SqlValueTemplate {
    pub(in crate::replay::policy) fn new(
        sql: &str,
        tables: &[String],
        patterns: &[String],
        series: Option<&crate::MysqlTableSeries>,
    ) -> Result<Self> {
        ensure!(sql.len() <= 64 * 1024, "oversized MySQL SQL template");
        ensure!(!sql.contains(TABLE), "reserved MySQL table template marker");
        let declared = !tables.is_empty() || !patterns.is_empty() || series.is_some();
        let count = sql.matches("{{table}}").count();
        ensure!(
            declared == (count > 0),
            "MySQL {{{{table}}}} requires tables, table_patterns or table_series, and table selectors require {{{{table}}}}"
        );
        let tokens = bounded_tokens(&sql.replace("{{table}}", TABLE))
            .context("invalid or oversized MySQL SQL template")?;
        let matcher = if declared {
            let matcher = TableMatcher::new(tables, patterns, series)?;
            let positions = tokens
                .iter()
                .enumerate()
                .filter(|(_, t)| t.is(TABLE))
                .collect::<Vec<_>>();
            ensure!(
                positions.len() == count,
                "MySQL {{{{table}}}} must be a whole table identifier or qualifier; literals and identifier fragments are unsupported"
            );
            let is_table = |position: usize| {
                position.checked_sub(1).is_some_and(|p| {
                    ["update", "into", "from", "join"]
                        .iter()
                        .any(|keyword| tokens[p].is(keyword))
                })
            };
            ensure!(
                positions.iter().any(|(p, _)| is_table(*p)),
                "MySQL table template must select a physical table"
            );
            ensure!(
                positions
                    .iter()
                    .all(|(p, _)| is_table(*p) || tokens.get(p + 1).is_some_and(|t| t.is("."))),
                "MySQL table template cannot select a column or alias"
            );
            Some(matcher)
        } else {
            None
        };
        Ok(Self {
            tokens,
            tables: matcher,
        })
    }

    pub(in crate::replay::policy) fn tokens(&self) -> &[Token] {
        &self.tokens
    }

    pub(in crate::replay::policy) fn bind(&self, actual: &[Token]) -> Option<Vec<Token>> {
        if self.tokens.len() != actual.len() {
            return None;
        }
        let Some(tables) = &self.tables else {
            return Some(self.tokens.clone());
        };
        let position = self.tokens.iter().position(|token| token.is(TABLE))?;
        let Token::Word(table) = &actual[position] else {
            return None;
        };
        if !tables.matches(table) {
            return None;
        }
        let bound = self
            .tokens
            .iter()
            .map(|token| {
                if token.is(TABLE) {
                    Token::Word(table.clone())
                } else {
                    token.clone()
                }
            })
            .collect::<Vec<_>>();
        extract(&bound, actual)?;
        Some(bound)
    }

    pub(in crate::replay::policy) fn matches(&self, sql: &str) -> bool {
        // This is only a rejection shortcut. Ambiguous prefixes still use the
        // full tokenizer, and matching verbs still require every normal check.
        if let (Some(actual), Some(Token::Word(expected))) =
            (plain_statement_verb(sql), self.tokens.first())
            && !expected.eq_ignore_ascii_case(actual)
        {
            return false;
        }
        bounded_statement_tokens(sql).is_some_and(|actual| {
            self.bind(&actual)
                .is_some_and(|bound| extract(&bound, &actual).is_some())
        })
    }
}

fn plain_statement_verb(sql: &str) -> Option<&str> {
    // Bound the peek even for oversized or whitespace-only input. Comments,
    // quoted words and unusual separators intentionally fall back to parsing.
    let start = sql
        .as_bytes()
        .iter()
        .take(64)
        .position(|byte| !byte.is_ascii_whitespace())?;
    let verb = sql.get(start..start + 6)?;
    if !sql.as_bytes().get(start + 6)?.is_ascii_whitespace() {
        return None;
    }
    ["select", "insert", "update", "delete"]
        .iter()
        .any(|expected| expected.eq_ignore_ascii_case(verb))
        .then_some(verb)
}
