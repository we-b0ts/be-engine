//! Bind one declared physical table without changing SQL values or predicates.
use super::{bounded_statement_tokens, bounded_tokens, extract};
use crate::config::mysql_tables::TableMatcher;
use crate::mysql::sql::{Token, table_template};
use anyhow::{Context, Result, ensure};

const TABLE: &str = "__traffic_time_table__";

#[derive(Debug)]
pub(in crate::replay::policy) struct SqlValueTemplate {
    tokens: Vec<Token>,
    tables: Option<TableMatcher>,
}

impl SqlValueTemplate {
    pub(in crate::replay::policy) fn from_value_selector(
        selector: &crate::policy::MatchSpec,
    ) -> Result<Self> {
        Self::new(
            selector.sql.as_deref().context("SQL template is absent")?,
            &selector.tables,
            &selector.table_patterns,
            selector.table_series.as_ref(),
        )
    }

    pub(in crate::replay::policy) fn new(
        sql: &str,
        tables: &[String],
        patterns: &[String],
        series: Option<&crate::MysqlTableSeries>,
    ) -> Result<Self> {
        ensure!(sql.len() <= 64 * 1024, "oversized MySQL SQL template");
        let declared = !tables.is_empty() || !patterns.is_empty() || series.is_some();
        let count = sql.matches("{{table}}").count();
        ensure!(
            count == 0 || !sql.contains(TABLE),
            "reserved MySQL table template marker"
        );
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
                .filter(|(position, token)| {
                    token.is(TABLE) || table_template::projection_alias(&tokens, *position, TABLE)
                })
                .collect::<Vec<_>>();
            ensure!(
                positions.len() == count,
                "MySQL {{{{table}}}} requires a whole table identifier, qualifier or explicit SELECT projection alias; other identifier fragments and literals are unsupported"
            );
            let is_table = |position: usize| {
                position.checked_sub(1).is_some_and(|p| {
                    ["update", "into", "from", "join"]
                        .iter()
                        .any(|keyword| tokens[p].is(keyword))
                })
            };
            ensure!(
                positions
                    .iter()
                    .any(|(p, token)| token.is(TABLE) && is_table(*p)),
                "MySQL table template must select a physical table"
            );
            ensure!(
                positions.iter().all(|(p, token)| {
                    token.is(TABLE)
                        && (is_table(*p) || tokens.get(p + 1).is_some_and(|t| t.is(".")))
                        || table_template::projection_alias(&tokens, *p, TABLE)
                }),
                "MySQL table template cannot select a column or table alias"
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
        let bound = table_template::instantiate(&self.tokens, TABLE, table)?;
        extract(&bound, actual)?;
        Some(bound)
    }

    // Policy admission needs the whole declared table range, not only the
    // physical table observed in the current planning witness.
    pub(in crate::replay::policy) fn overlaps(&self, other: &Self) -> bool {
        table_template::overlap(
            &self.tokens,
            self.tables.as_ref().map(|_| TABLE),
            &other.tokens,
            other.tables.as_ref().map(|_| TABLE),
        )
        .is_some_and(|constraints| {
            constraints.compatible(
                |table| self.tables.as_ref().is_some_and(|tables| tables.matches(table)),
                |table| other.tables.as_ref().is_some_and(|tables| tables.matches(table)),
                || matches!((&self.tables, &other.tables), (Some(left), Some(right)) if left.overlaps(right)),
            )
        })
    }

    pub(in crate::replay::policy) fn matches(&self, sql: &str) -> bool {
        if !self.could_match(sql) {
            return false;
        }
        bounded_statement_tokens(sql).is_some_and(|actual| self.matches_tokens(&actual))
    }

    pub(in crate::replay::policy) fn could_match(&self, sql: &str) -> bool {
        // This is only a rejection shortcut. Ambiguous prefixes still use the
        // full tokenizer, and matching verbs still require every normal check.
        if let (Some(actual), Some(Token::Word(expected))) =
            (plain_statement_verb(sql), self.tokens.first())
            && !expected.eq_ignore_ascii_case(actual)
        {
            return false;
        }
        true
    }

    pub(in crate::replay::policy) fn matches_tokens(&self, actual: &[Token]) -> bool {
        if self.tokens.len() != actual.len() {
            return false;
        }
        let table = if let Some(tables) = &self.tables {
            let Some(position) = self.tokens.iter().position(|token| token.is(TABLE)) else {
                return false;
            };
            let Token::Word(table) = &actual[position] else {
                return false;
            };
            if !tables.matches(table) {
                return false;
            }
            Some(table)
        } else {
            None
        };
        self.tokens.iter().zip(actual).all(|(expected, actual)| {
            if let Some(table) = table {
                table_template::matches_token(expected, actual, TABLE, table)
            } else {
                expected == actual
                    || *expected == Token::Placeholder
                        && (actual.is_value() || *actual == Token::Placeholder)
            }
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
    let length = sql.as_bytes()[start..]
        .iter()
        .take(64)
        .take_while(|byte| byte.is_ascii_alphabetic())
        .count();
    if length == 0 || !sql.as_bytes().get(start + length)?.is_ascii_whitespace() {
        return None;
    }
    sql.get(start..start + length)
}
