use std::collections::HashSet;
use std::path::PathBuf;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::mysql::operation::MysqlWriteOperation;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct RecordingConfig {
    pub output_dir: PathBuf,
    pub max_body_bytes: usize,
    pub redact_headers: Vec<String>,
    pub access_policy: RecordingAccessPolicy,
    pub access_rules: Vec<RecordingAccessRuleConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "protocol", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecordingAccessRuleConfig {
    Mysql {
        name: String,
        effect: RecordingAccessRuleEffect,
        operations: Vec<MysqlWriteOperation>,
        #[serde(default)]
        routes: Vec<String>,
        #[serde(default)]
        targets: Vec<String>,
        databases: Vec<String>,
        tables: Vec<String>,
    },
}

impl RecordingAccessRuleConfig {
    pub fn name(&self) -> &str {
        match self {
            Self::Mysql { name, .. } => name,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecordingAccessRuleEffect {
    Allow,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecordingAccessPolicy {
    #[default]
    Unrestricted,
    BlockKnownWrites,
}

impl RecordingAccessPolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unrestricted => "unrestricted",
            Self::BlockKnownWrites => "block_known_writes",
        }
    }
}

impl RecordingConfig {
    pub(super) fn validate(&self) -> Result<()> {
        let mut names = HashSet::new();
        for rule in &self.access_rules {
            let name = rule.name();
            if name.trim().is_empty() {
                bail!("recording access rule name must not be empty");
            }
            if !names.insert(name) {
                bail!("duplicate recording access rule name {name:?}");
            }
            match rule {
                RecordingAccessRuleConfig::Mysql {
                    operations,
                    routes,
                    targets,
                    databases,
                    tables,
                    ..
                } => {
                    validate_operations(name, operations)?;
                    if routes.is_empty() && targets.is_empty() {
                        bail!(
                            "MySQL access rule {name:?} must include at least one route or target"
                        );
                    }
                    validate_values(name, "routes", routes)?;
                    validate_values(name, "targets", targets)?;
                    if databases.is_empty() {
                        bail!("MySQL access rule {name:?} must include at least one database");
                    }
                    validate_values(name, "databases", databases)?;
                    if tables.is_empty() {
                        bail!("MySQL access rule {name:?} must include at least one table");
                    }
                    validate_values(name, "tables", tables)?;
                }
            }
        }
        Ok(())
    }
}

fn validate_operations(rule_name: &str, operations: &[MysqlWriteOperation]) -> Result<()> {
    if operations.is_empty() {
        bail!("MySQL access rule {rule_name:?} must include at least one operation");
    }
    let mut unique = HashSet::new();
    for operation in operations {
        if !unique.insert(operation) {
            bail!(
                "MySQL access rule {rule_name:?} has duplicate operation {:?}",
                operation.as_str()
            );
        }
    }
    Ok(())
}

fn validate_values(rule_name: &str, field: &str, values: &[String]) -> Result<()> {
    let mut unique = HashSet::new();
    for value in values {
        if value.trim().is_empty() {
            bail!("MySQL access rule {rule_name:?} has an empty {field} value");
        }
        if !unique.insert(value) {
            bail!("MySQL access rule {rule_name:?} has duplicate {field} value {value:?}");
        }
    }
    Ok(())
}

impl Default for RecordingConfig {
    fn default() -> Self {
        Self {
            output_dir: PathBuf::from("./recordings"),
            max_body_bytes: 1024 * 1024,
            redact_headers: vec![
                "authorization".to_string(),
                "cookie".to_string(),
                "set-cookie".to_string(),
                "proxy-authorization".to_string(),
                "proxy-authenticate".to_string(),
            ],
            access_policy: RecordingAccessPolicy::Unrestricted,
            access_rules: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;

    #[test]
    fn parses_recording_access_policy() {
        let config: AppConfig = toml::from_str(
            r#"
            [recording]
            access_policy = "block_known_writes"
            "#,
        )
        .unwrap();

        assert_eq!(
            config.recording.access_policy,
            RecordingAccessPolicy::BlockKnownWrites
        );
        assert!(
            toml::from_str::<AppConfig>(
                r#"
            [recording]
            access_policy = "allow_known_reads"
            "#
            )
            .is_err()
        );
    }

    #[test]
    fn parses_and_serializes_mysql_access_rule() {
        let config: AppConfig = toml::from_str(
            r#"
            [recording]
            access_policy = "block_known_writes"

            [[recording.access_rules]]
            name = "allow-request-log"
            effect = "allow"
            protocol = "mysql"
            operations = ["insert", "update"]
            routes = ["audit-db"]
            targets = ["mysql-log.internal:3306"]
            databases = ["pluto"]
            tables = ["request_log"]
            "#,
        )
        .unwrap();
        config.validate().unwrap();

        assert_eq!(config.recording.access_rules.len(), 1);
        assert_eq!(config.recording.access_rules[0].name(), "allow-request-log");
        let serialized = toml::to_string(&config).unwrap();
        let round_trip: AppConfig = toml::from_str(&serialized).unwrap();
        assert_eq!(
            round_trip.recording.access_rules,
            config.recording.access_rules
        );
    }

    #[test]
    fn rejects_unsafe_mysql_access_rules() {
        assert!(
            toml::from_str::<AppConfig>(
                r#"
                [[recording.access_rules]]
                name = "missing-operations"
                effect = "allow"
                protocol = "mysql"
                routes = ["audit-db"]
                databases = ["pluto"]
                tables = ["request_log"]
                "#,
            )
            .is_err()
        );
        assert!(
            toml::from_str::<AppConfig>(
                r#"
                [[recording.access_rules]]
                name = "ddl"
                effect = "allow"
                protocol = "mysql"
                operations = ["drop"]
                routes = ["audit-db"]
                databases = ["pluto"]
                tables = ["request_log"]
                "#,
            )
            .is_err()
        );

        for invalid in [
            r#"
            [[recording.access_rules]]
            name = "empty-operations"
            effect = "allow"
            protocol = "mysql"
            operations = []
            routes = ["audit-db"]
            databases = ["pluto"]
            tables = ["request_log"]
            "#,
            r#"
            [[recording.access_rules]]
            name = "unscoped"
            effect = "allow"
            protocol = "mysql"
            operations = ["insert"]
            databases = ["pluto"]
            tables = ["request_log"]
            "#,
        ] {
            let config: AppConfig = toml::from_str(invalid).unwrap();
            assert!(config.validate().is_err());
        }
    }
}
