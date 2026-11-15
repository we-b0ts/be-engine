//! Physical table selectors, independent of SQL template expansion.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MysqlTableSeries {
    pub prefix: String,
    pub start: u32,
    pub end: u32,
    pub width: usize,
}

#[derive(Debug)]
pub struct TableMatcher {
    exact: BTreeSet<String>,
    patterns: Vec<Pattern>,
    series: Option<MysqlTableSeries>,
}

#[derive(Debug)]
struct Pattern {
    prefix: String,
    suffix: String,
}

impl TableMatcher {
    pub fn new(
        tables: &[String],
        table_patterns: &[String],
        table_series: Option<&MysqlTableSeries>,
    ) -> Result<Self> {
        ensure!(tables.len() <= 4096, "MySQL selector has too many tables");
        let exact: BTreeSet<_> = tables.iter().cloned().collect();
        ensure!(
            exact.len() == tables.len(),
            "MySQL selector tables must be unique"
        );
        if let Some(series) = table_series {
            ensure!(
                series.start <= series.end
                    && series.end - series.start < 4096
                    && series.width <= 10,
                "MySQL table series must be bounded to at most 4096 tables and width <= 10"
            );
            ensure!(
                identifier(&series.prefix)
                    && series.prefix.len() + series.width.max(decimal_width(series.end)) <= 64,
                "MySQL selector tables must be ASCII identifiers"
            );
            let overlap = exact.iter().filter(|table| series.matches(table)).count();
            ensure!(
                exact.len() + (series.end - series.start) as usize + 1 - overlap <= 4096,
                "MySQL selector has too many tables"
            );
        }
        ensure!(exact.len() <= 4096, "MySQL selector has too many tables");
        ensure!(
            exact.iter().all(|name| identifier(name)),
            "MySQL selector tables must be ASCII identifiers"
        );
        ensure!(
            table_patterns.len() <= 64,
            "MySQL selector has too many table patterns"
        );
        let mut seen = BTreeSet::new();
        let mut patterns = Vec::new();
        for pattern in table_patterns {
            ensure!(seen.insert(pattern), "MySQL table patterns must be unique");
            let Some((prefix, suffix)) = pattern.split_once('*') else {
                anyhow::bail!(
                    "MySQL table pattern requires exactly one *; use tables for exact names"
                );
            };
            ensure!(
                pattern.len() <= 65
                    && prefix.len() + suffix.len() > 0
                    && prefix.bytes().chain(suffix.bytes()).all(identifier_byte)
                    && !prefix.as_bytes().first().is_some_and(u8::is_ascii_digit),
                "MySQL table pattern requires ASCII identifier affixes and exactly one *; a bare wildcard is not supported"
            );
            patterns.push(Pattern {
                prefix: prefix.to_owned(),
                suffix: suffix.to_owned(),
            });
        }
        ensure!(
            !exact.is_empty() || !patterns.is_empty() || table_series.is_some(),
            "MySQL selector requires tables, a bounded table_series or table_patterns"
        );
        Ok(Self {
            exact,
            patterns,
            series: table_series.cloned(),
        })
    }

    pub fn matches(&self, table: &str) -> bool {
        identifier(table)
            && (self.exact.contains(table)
                || self
                    .series
                    .as_ref()
                    .is_some_and(|series| series.matches(table))
                || self.patterns.iter().any(|p| p.matches(table)))
    }

    pub fn overlaps(&self, other: &Self) -> bool {
        self.exact.iter().any(|table| other.matches(table))
            || other.exact.iter().any(|table| self.matches(table))
            // Overlap validation is bounded and infrequent. Runtime matching
            // never allocates or enumerates the series' physical table names.
            || self.series.as_ref().is_some_and(|series| series.overlaps(other))
            || other.series.as_ref().is_some_and(|series| series.overlaps(self))
            || self
                .patterns
                .iter()
                .any(|a| other.patterns.iter().any(|b| a.overlaps(b)))
    }
}

impl MysqlTableSeries {
    fn matches(&self, table: &str) -> bool {
        let Some(suffix) = table.strip_prefix(&self.prefix) else {
            return false;
        };
        if suffix.is_empty() || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
            return false;
        }
        let Ok(value) = suffix.parse::<u32>() else {
            return false;
        };
        (self.start..=self.end).contains(&value)
            && suffix.len() == self.width.max(decimal_width(value))
    }

    fn overlaps(&self, other: &TableMatcher) -> bool {
        (self.start..=self.end).any(|value| {
            other.matches(&format!(
                "{}{:0width$}",
                self.prefix,
                value,
                width = self.width
            ))
        })
    }
}

fn decimal_width(value: u32) -> usize {
    value.max(1).ilog10() as usize + 1
}

impl Pattern {
    fn matches(&self, table: &str) -> bool {
        table.len() >= self.prefix.len() + self.suffix.len()
            && table.starts_with(&self.prefix)
            && table.ends_with(&self.suffix)
    }

    fn overlaps(&self, other: &Self) -> bool {
        // Test compatible fixed bytes at each legal identifier length. Free
        // positions can always be filled with '_'; never enumerate table names.
        let minimum = (self.prefix.len() + self.suffix.len())
            .max(other.prefix.len() + other.suffix.len())
            .max(1);
        (minimum..=64).any(|len| {
            (0..len).all(|i| {
                let a = self.fixed_byte(i, len);
                let b = other.fixed_byte(i, len);
                !(a.is_some() && b.is_some() && a != b
                    || i == 0 && a.or(b).is_some_and(|b| b.is_ascii_digit()))
            })
        })
    }

    fn fixed_byte(&self, index: usize, len: usize) -> Option<u8> {
        self.prefix.as_bytes().get(index).copied().or_else(|| {
            index
                .checked_sub(len - self.suffix.len())
                .and_then(|i| self.suffix.as_bytes().get(i))
                .copied()
        })
    }
}

fn identifier_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn identifier(table: &str) -> bool {
    !table.is_empty()
        && table.len() <= 64
        && !table.as_bytes()[0].is_ascii_digit()
        && table.bytes().all(identifier_byte)
}

#[cfg(test)]
mod tests;
