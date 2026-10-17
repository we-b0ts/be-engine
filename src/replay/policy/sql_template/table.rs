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

    // Policy admission needs the whole declared table range, not only the
    // physical table observed in the current planning witness.
    pub(in crate::replay::policy) fn overlaps(&self, other: &Self) -> bool {
        if self.tokens.len() != other.tokens.len() {
            return false;
        }
        let mut left_table = None;
        let mut right_table = None;
        let mut shared_table = false;
        for (left, right) in self.tokens.iter().zip(&other.tokens) {
            match (
                self.tables.is_some() && left.is(TABLE),
                other.tables.is_some() && right.is(TABLE),
            ) {
                (true, true) => shared_table = true,
                (true, false) => {
                    if !constrain_table(self, right, &mut left_table) {
                        return false;
                    }
                }
                (false, true) => {
                    if !constrain_table(other, left, &mut right_table) {
                        return false;
                    }
                }
                (false, false) => {
                    if left != right
                        && !(*left == Token::Placeholder && right.is_value()
                            || *right == Token::Placeholder && left.is_value())
                    {
                        return false;
                    }
                }
            }
        }
        if !shared_table {
            return true;
        }
        let (Some(left), Some(right)) = (&self.tables, &other.tables) else {
            return false;
        };
        match (left_table, right_table) {
            (Some(a), Some(b)) => a == b,
            (Some(table), None) => right.matches(&table),
            (None, Some(table)) => left.matches(&table),
            (None, None) => left.overlaps(right),
        }
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
            if expected.is(TABLE)
                && let Some(table) = table
            {
                matches!(actual, Token::Word(name) if name == table)
            } else {
                expected == actual
                    || *expected == Token::Placeholder
                        && (actual.is_value() || *actual == Token::Placeholder)
            }
        })
    }
}

fn constrain_table(template: &SqlValueTemplate, token: &Token, bound: &mut Option<String>) -> bool {
    let Token::Word(table) = token else {
        return false;
    };
    if bound.as_ref().is_some_and(|previous| previous != table)
        || !template
            .tables
            .as_ref()
            .is_some_and(|tables| tables.matches(table))
    {
        return false;
    }
    *bound = Some(table.clone());
    true
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
