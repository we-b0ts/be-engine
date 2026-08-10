use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use super::{BackgroundDependencyRuleConfig, DEFAULT_BODY_LIMIT_BYTES};
use crate::mysql::operation::MysqlWriteOperation;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct RecordingConfig {
    pub output_dir: PathBuf,
    pub max_body_bytes: usize,
    pub max_decoded_body_bytes: Option<usize>,
    pub traffic_jsonl: TrafficJsonlMode,
    pub jsonl_buffer_capacity_bytes: usize,
    pub jsonl_flush_interval_ms: u64,
    pub writer_queue_capacity: usize,
    pub cache_snapshot_max_waiters_per_entry: usize,
    pub cache_snapshot_fill_timeout_ms: u64,
    pub post_ready_settle_ms: u64,
    pub post_ready_max_wait_ms: u64,
    #[serde(alias = "case_dependency_quiet_period_ms")]
    pub case_dependency_post_response_window_ms: u64,
    pub case_dependency_drain_timeout_ms: u64,
    pub shutdown_case_drain_timeout_ms: u64,
    pub encrypt_request_headers: Vec<String>,
    pub redact_headers: Vec<String>,
    pub access_policy: RecordingAccessPolicy,
    pub access_rules: Vec<RecordingAccessRuleConfig>,
    pub background_dependencies: Vec<BackgroundDependencyRuleConfig>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrafficJsonlMode {
    #[default]
    Full,
    Errors,
    Off,
}

impl TrafficJsonlMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Errors => "errors",
            Self::Off => "off",
        }
    }
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
    const MIN_POST_READY_QUIET_PERIOD_MS: u64 = 15_000;

    pub(crate) fn post_ready_quiet_period(&self) -> Duration {
        let milliseconds = if self.post_ready_settle_ms == 0 {
            0
        } else {
            self.post_ready_settle_ms
                .max(Self::MIN_POST_READY_QUIET_PERIOD_MS)
        };
        Duration::from_millis(milliseconds)
    }

    pub(crate) fn post_ready_max_wait(&self) -> Duration {
        Duration::from_millis(self.post_ready_max_wait_ms)
    }

    pub fn decoded_body_limit(&self) -> usize {
        self.max_decoded_body_bytes.unwrap_or(self.max_body_bytes)
    }

    pub(super) fn validate_body_limits(&self) -> Result<()> {
        if self.max_body_bytes == 0 {
            bail!("recording.max_body_bytes must be greater than zero");
        }
        if self.max_decoded_body_bytes == Some(0) {
            bail!("recording.max_decoded_body_bytes must be greater than zero");
        }
        Ok(())
    }

    pub(super) fn validate(&self) -> Result<()> {
        self.validate_body_limits()?;
        if self.jsonl_buffer_capacity_bytes == 0 {
            bail!("recording.jsonl_buffer_capacity_bytes must be greater than zero");
        }
        if self.jsonl_flush_interval_ms == 0 {
            bail!("recording.jsonl_flush_interval_ms must be greater than zero");
        }
        if self.writer_queue_capacity == 0 {
            bail!("recording.writer_queue_capacity must be greater than zero");
        }
        if self.cache_snapshot_max_waiters_per_entry == 0 {
            bail!("recording.cache_snapshot_max_waiters_per_entry must be greater than zero");
        }
        if self.cache_snapshot_fill_timeout_ms == 0 {
            bail!("recording.cache_snapshot_fill_timeout_ms must be greater than zero");
        }
        if self.post_ready_max_wait_ms == 0 {
            bail!("recording.post_ready_max_wait_ms must be greater than zero");
        }
        if self.post_ready_quiet_period() > self.post_ready_max_wait() {
            bail!(
                "recording.post_ready_max_wait_ms must be at least the effective post-ready quiet period"
            );
        }
        if self.case_dependency_drain_timeout_ms == 0 {
            bail!("recording.case_dependency_drain_timeout_ms must be greater than zero");
        }
        if self.shutdown_case_drain_timeout_ms == 0 {
            bail!("recording.shutdown_case_drain_timeout_ms must be greater than zero");
        }
        self.validate_request_header_encryption()?;
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
        super::background_dependencies::validate(&self.background_dependencies)?;
        Ok(())
    }

    pub(super) fn validate_request_header_encryption(&self) -> Result<()> {
        validate_encrypted_request_headers(&self.encrypt_request_headers)
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
            max_body_bytes: DEFAULT_BODY_LIMIT_BYTES,
            max_decoded_body_bytes: None,
            traffic_jsonl: TrafficJsonlMode::Full,
            jsonl_buffer_capacity_bytes: 256 * 1024,
            jsonl_flush_interval_ms: 1_000,
            writer_queue_capacity: 65_536,
            cache_snapshot_max_waiters_per_entry: 1_024,
            cache_snapshot_fill_timeout_ms: 30_000,
            post_ready_settle_ms: 15_000,
            post_ready_max_wait_ms: 180_000,
            case_dependency_post_response_window_ms: 100,
            case_dependency_drain_timeout_ms: 5_000,
            shutdown_case_drain_timeout_ms: 5_000,
            encrypt_request_headers: Vec::new(),
            redact_headers: vec![
                "authorization".to_string(),
                "cookie".to_string(),
                "set-cookie".to_string(),
                "proxy-authorization".to_string(),
                "proxy-authenticate".to_string(),
            ],
            access_policy: RecordingAccessPolicy::Unrestricted,
            access_rules: Vec::new(),
            background_dependencies: Vec::new(),
        }
    }
}

fn validate_encrypted_request_headers(names: &[String]) -> Result<()> {
    let mut unique = HashSet::new();
    for name in names {
        if name.trim().is_empty() {
            bail!("recording.encrypt_request_headers must not contain an empty name");
        }
        let normalized = name.to_ascii_lowercase();
        normalized
            .parse::<hyper::header::HeaderName>()
            .map_err(|_| {
                anyhow::anyhow!(
                    "recording.encrypt_request_headers contains invalid header name {name:?}"
                )
            })?;
        if !unique.insert(normalized) {
            bail!("recording.encrypt_request_headers contains duplicate header name {name:?}");
        }
    }
    Ok(())
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
    fn validates_case_dependency_drain_timing() {
        let mut config = AppConfig::default();
        assert_eq!(config.recording.post_ready_settle_ms, 15_000);
        assert_eq!(config.recording.post_ready_max_wait_ms, 180_000);
        assert_eq!(config.recording.shutdown_case_drain_timeout_ms, 5_000);
        config.recording.case_dependency_post_response_window_ms = 0;
        config.validate().unwrap();

        config.recording.case_dependency_drain_timeout_ms = 0;
        assert!(config.validate().is_err());

        config.recording.case_dependency_drain_timeout_ms = 1;
        config.recording.shutdown_case_drain_timeout_ms = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn normalizes_legacy_post_ready_settle_to_the_fifteen_second_minimum() {
        let mut config = AppConfig::default();
        config.recording.post_ready_settle_ms = 10_000;

        assert_eq!(
            config.recording.post_ready_quiet_period(),
            Duration::from_secs(15)
        );
        config.validate().unwrap();

        config.recording.post_ready_max_wait_ms = 14_999;
        assert!(config.validate().is_err());

        config.recording.post_ready_settle_ms = 0;
        config.validate().unwrap();
        assert!(config.recording.post_ready_quiet_period().is_zero());
    }

    #[test]
    fn decoded_body_limit_defaults_to_wire_limit() {
        let mut config = AppConfig::default();
        assert_eq!(config.recording.max_body_bytes, DEFAULT_BODY_LIMIT_BYTES);
        assert_eq!(
            config.recording.decoded_body_limit(),
            DEFAULT_BODY_LIMIT_BYTES
        );
        config.recording.max_body_bytes = 1234;
        assert_eq!(config.recording.decoded_body_limit(), 1234);

        config.recording.max_decoded_body_bytes = Some(5678);
        assert_eq!(config.recording.decoded_body_limit(), 5678);

        config.recording.max_decoded_body_bytes = Some(0);
        assert!(config.validate().is_err());
    }

    #[test]
    fn accepts_legacy_quiet_period_as_post_response_window() {
        let config: AppConfig = toml::from_str(
            r#"
            [recording]
            case_dependency_quiet_period_ms = 250
            "#,
        )
        .unwrap();

        assert_eq!(
            config.recording.case_dependency_post_response_window_ms,
            250
        );
    }

    #[test]
    fn parses_jsonl_output_and_buffer_settings() {
        let config: AppConfig = toml::from_str(
            r#"
            [recording]
            traffic_jsonl = "off"
            jsonl_buffer_capacity_bytes = 524288
            jsonl_flush_interval_ms = 250
            writer_queue_capacity = 8192
            "#,
        )
        .unwrap();

        assert_eq!(config.recording.traffic_jsonl, TrafficJsonlMode::Off);
        assert_eq!(config.recording.jsonl_buffer_capacity_bytes, 524_288);
        assert_eq!(config.recording.jsonl_flush_interval_ms, 250);
        assert_eq!(config.recording.writer_queue_capacity, 8_192);
        config.validate().unwrap();
    }

    #[test]
    fn rejects_zero_writer_queue_capacity() {
        let config = RecordingConfig {
            writer_queue_capacity: 0,
            ..Default::default()
        };

        let error = config.validate().unwrap_err();

        assert!(
            error
                .to_string()
                .contains("recording.writer_queue_capacity must be greater than zero")
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

    #[test]
    fn validates_encrypted_request_header_names_case_insensitively() {
        let mut config = AppConfig::default();
        config.recording.encrypt_request_headers = vec!["Authorization".to_string()];
        config.validate().unwrap();

        config
            .recording
            .encrypt_request_headers
            .push("authorization".to_string());
        assert!(config.validate().is_err());

        config.recording.encrypt_request_headers = vec!["not a header".to_string()];
        assert!(config.validate().is_err());
    }
}
