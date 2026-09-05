//! Physical table selectors, independent of SQL template expansion.
use super::MysqlBackgroundSelector;
use anyhow::{Result, ensure};
use std::collections::BTreeSet;

pub(super) struct TableMatcher<'a> {
    exact: BTreeSet<String>,
    patterns: Vec<Pattern<'a>>,
}

struct Pattern<'a> {
    prefix: &'a str,
    suffix: &'a str,
}

impl<'a> TableMatcher<'a> {
    pub(super) fn new(selector: &'a MysqlBackgroundSelector) -> Result<Self> {
        ensure!(
            selector.tables.len() <= 4096,
            "MySQL selector has too many tables"
        );
        let mut exact: BTreeSet<_> = selector.tables.iter().cloned().collect();
        ensure!(
            exact.len() == selector.tables.len(),
            "MySQL selector tables must be unique"
        );
        if let Some(series) = &selector.table_series {
            ensure!(
                series.start <= series.end
                    && series.end - series.start < 4096
                    && series.width <= 10,
                "MySQL table series must be bounded to at most 4096 tables and width <= 10"
            );
            for suffix in series.start..=series.end {
                exact.insert(format!(
                    "{}{:0width$}",
                    series.prefix,
                    suffix,
                    width = series.width
                ));
            }
        }
        ensure!(exact.len() <= 4096, "MySQL selector has too many tables");
        ensure!(
            exact.iter().all(|name| identifier(name)),
            "MySQL selector tables must be ASCII identifiers"
        );
        ensure!(
            selector.table_patterns.len() <= 64,
            "MySQL selector has too many table patterns"
        );
        let mut seen = BTreeSet::new();
        let mut patterns = Vec::new();
        for pattern in &selector.table_patterns {
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
            patterns.push(Pattern { prefix, suffix });
        }
        ensure!(
            !exact.is_empty() || !patterns.is_empty(),
            "MySQL selector requires tables, a bounded table_series or table_patterns"
        );
        Ok(Self { exact, patterns })
    }

    pub(super) fn matches(&self, table: &str) -> bool {
        identifier(table)
            && (self.exact.contains(table) || self.patterns.iter().any(|p| p.matches(table)))
    }

    pub(super) fn overlaps(&self, other: &Self) -> bool {
        self.exact.iter().any(|table| other.matches(table))
            || other.exact.iter().any(|table| self.matches(table))
            || self
                .patterns
                .iter()
                .any(|a| other.patterns.iter().any(|b| a.overlaps(b)))
    }
}

impl Pattern<'_> {
    fn matches(&self, table: &str) -> bool {
        table.len() >= self.prefix.len() + self.suffix.len()
            && table.starts_with(self.prefix)
            && table.ends_with(self.suffix)
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
