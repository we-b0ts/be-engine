//! Global physical MySQL scalar declarations. Payload codecs are inferred separately.
use std::collections::BTreeMap;

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use super::GlobalField;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MysqlPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    #[serde(default, deserialize_with = "super::strict_map::unique_map")]
    pub tables: BTreeMap<String, GlobalMysqlTable>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GlobalMysqlTable {
    pub pattern: String,
    #[serde(deserialize_with = "super::strict_map::unique_map")]
    pub fields: BTreeMap<String, GlobalField>,
}

impl MysqlPolicy {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.database
                .as_ref()
                .is_none_or(|database| identifier(database)),
            "mysql.database requires an exact ASCII database identifier"
        );
        ensure!(
            self.tables.len() <= 4096,
            "mysql.tables exceeds 4096 entries"
        );
        for (name, table) in &self.tables {
            ensure!(
                !name.is_empty() && name.len() <= 128,
                "invalid MySQL logical table name"
            );
            ensure!(
                valid_pattern(&table.pattern),
                "MySQL table pattern requires an ASCII table identifier with an optional * wildcard; declare its database in mysql.database"
            );
            ensure!(
                !table.fields.is_empty() && table.fields.len() <= 4096,
                "MySQL table requires 1..4096 scalar fields"
            );
            for (column, field) in &table.fields {
                ensure!(
                    identifier(column),
                    "MySQL field must be an ASCII column identifier"
                );
                field.validate()?;
                ensure!(
                    matches!(
                        field,
                        GlobalField::Time { .. }
                            | GlobalField::Identity { .. }
                            | GlobalField::Duration { .. }
                    ),
                    "MySQL scalar columns accept time, identity or duration; JSON protocols and arrays use json.fields"
                );
            }
        }
        let tables = self.tables.values().collect::<Vec<_>>();
        for (index, left) in tables.iter().enumerate() {
            for right in &tables[index + 1..] {
                if !patterns_overlap(&left.pattern, &right.pattern) {
                    continue;
                }
                for (column, field) in &left.fields {
                    for (other, contract) in &right.fields {
                        ensure!(
                            !column.eq_ignore_ascii_case(other) || field == contract,
                            "overlapping MySQL table patterns assign different formats to the same column"
                        );
                    }
                }
            }
        }
        Ok(())
    }

    pub(crate) fn field(
        &self,
        database: Option<&str>,
        table: &str,
        column: &str,
    ) -> Result<Option<&GlobalField>> {
        if !self.matches_database(database) {
            return Ok(None);
        }
        let mut result = None;
        for declaration in self.tables.values() {
            let selected = wildcard(&declaration.pattern, table);
            if !selected {
                continue;
            }
            for (name, field) in &declaration.fields {
                if name.eq_ignore_ascii_case(column) {
                    ensure!(
                        result.is_none_or(|prior| prior == field),
                        "overlapping MySQL field declarations disagree"
                    );
                    result = Some(field);
                }
            }
        }
        Ok(result)
    }

    pub(crate) fn matches_database(&self, database: Option<&str>) -> bool {
        self.database
            .as_deref()
            .is_none_or(|selected| database == Some(selected))
    }
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && !value.as_bytes()[0].is_ascii_digit()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$'))
}

fn valid_pattern(pattern: &str) -> bool {
    let parts = [pattern];
    parts.iter().all(|part| {
        !part.is_empty()
            && part.len() <= 65
            && part.bytes().filter(|byte| *byte == b'*').count() <= 1
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$' | b'*'))
            && !part.as_bytes()[0].is_ascii_digit()
    })
}

fn wildcard(pattern: &str, value: &str) -> bool {
    if let Some((prefix, suffix)) = pattern.split_once('*') {
        value.len() >= prefix.len() + suffix.len()
            && value.starts_with(prefix)
            && value.ends_with(suffix)
    } else {
        pattern == value
    }
}

fn patterns_overlap(left: &str, right: &str) -> bool {
    overlaps(left, right)
}

fn overlaps(left: &str, right: &str) -> bool {
    let fixed = |pattern: &str, len: usize, index: usize| {
        if let Some((prefix, suffix)) = pattern.split_once('*') {
            if len < prefix.len() + suffix.len() {
                return None;
            }
            Some(if index < prefix.len() {
                Some(prefix.as_bytes()[index])
            } else if index >= len - suffix.len() {
                Some(suffix.as_bytes()[index - (len - suffix.len())])
            } else {
                None
            })
        } else if len == pattern.len() {
            Some(Some(pattern.as_bytes()[index]))
        } else {
            None
        }
    };
    (1..=64).any(|len| {
        (0..len).all(
            |index| match (fixed(left, len, index), fixed(right, len, index)) {
                (Some(Some(left)), Some(Some(right))) => left == right,
                (Some(_), Some(_)) => true,
                _ => false,
            },
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn physical_patterns_use_actual_schema_and_table() {
        let policy: MysqlPolicy = serde_yaml::from_str(
            "database: task\ntables:\n  tasks:\n    pattern: tasks_*\n    fields:\n      id: {kind: identity, formats: [uuid]}\n",
        ).unwrap();
        policy.validate().unwrap();
        assert!(
            policy
                .field(Some("task"), "tasks_001", "id")
                .unwrap()
                .is_some()
        );
        assert!(
            policy
                .field(Some("other"), "tasks_001", "id")
                .unwrap()
                .is_none()
        );
        assert!(
            policy
                .field(Some("task"), "tasks_001", "count")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn declarations_reject_duplicate_columns_and_unsupported_syntax() {
        assert!(serde_yaml::from_str::<MysqlPolicy>("tables: {t: {pattern: tasks, fields: {id: {kind: identity, formats: [uuid]}, id: {kind: identity, formats: [uuid]}}}}").is_err());
        for pattern in ["a.b.c", "a/**", "", "task**", "1task"] {
            assert!(!valid_pattern(pattern));
        }
        assert!(!valid_pattern("app.tasks_*"));
        assert!(patterns_overlap("tasks_*", "tasks_001"));
        assert!(!patterns_overlap("tasks_a*", "tasks_b*"));
    }
}
