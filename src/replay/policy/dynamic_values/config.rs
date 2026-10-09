//! One source-proven capture location and explicit endpoints for automatic references.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DynamicValueTarget {
    pub host: String,
    pub port: u16,
}

impl DynamicValueTarget {
    pub(super) fn matches(&self, target: &crate::replay::TargetKey) -> bool {
        self.port == target.port && self.host.eq_ignore_ascii_case(&target.host)
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            !self.host.is_empty()
                && self.host.len() <= 255
                && !self.host.contains(char::is_whitespace)
                && self.port > 0,
            "dynamic values require an exact host and nonzero port"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "snake_case", deny_unknown_fields)]
pub enum DynamicValueCapture {
    Mysql {
        target: DynamicValueTarget,
        database: String,
        sql: String,
        value_index: usize,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        json_pointer: Option<String>,
    },
    Redis {
        target: DynamicValueTarget,
        database: i64,
        command: String,
        key: String,
        argument_index: usize,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        json_pointer: Option<String>,
    },
    Http {
        target: DynamicValueTarget,
        method: String,
        path: String,
        json_pointer: String,
    },
}

impl DynamicValueCapture {
    pub(super) fn target(&self) -> &DynamicValueTarget {
        match self {
            Self::Mysql { target, .. } | Self::Redis { target, .. } | Self::Http { target, .. } => {
                target
            }
        }
    }
    fn validate(&self) -> Result<()> {
        self.target().validate()?;
        match self {
            Self::Mysql {
                database,
                sql,
                value_index,
                json_pointer,
                ..
            } => {
                ensure!(
                    !database.is_empty() && database.len() <= 255,
                    "dynamic MySQL capture requires a database"
                );
                let tokens = super::super::sql_template::bounded_tokens(sql)
                    .ok_or_else(|| anyhow::anyhow!("invalid dynamic SQL template"))?;
                ensure!(
                    tokens
                        .first()
                        .is_some_and(|token| ["select", "insert", "update", "delete"]
                            .iter()
                            .any(|verb| token.is(verb))),
                    "dynamic capture requires a business SQL template"
                );
                ensure!(
                    *value_index
                        < tokens
                            .iter()
                            .filter(|token| **token == crate::mysql::sql::Token::Placeholder)
                            .count(),
                    "dynamic capture value_index exceeds SQL template slots"
                );
                if let Some(pointer) = json_pointer {
                    validate_pointer(pointer)?;
                }
            }
            Self::Redis {
                database,
                command,
                key,
                argument_index,
                json_pointer,
                ..
            } => {
                ensure!(
                    *database >= 0 && !key.is_empty() && key.len() <= 1024,
                    "dynamic Redis capture requires a database and exact key"
                );
                ensure!(
                    command == "SET" && *argument_index == 1
                        || command == "HSET"
                            && *argument_index >= 2
                            && *argument_index <= 128
                            && argument_index.is_multiple_of(2),
                    "Redis capture selects SET value (index 1) or HSET value (even index >= 2)"
                );
                if let Some(pointer) = json_pointer {
                    validate_pointer(pointer)?;
                }
            }
            Self::Http {
                method,
                path,
                json_pointer,
                ..
            } => {
                ensure!(
                    method.len() <= 32
                        && method.parse::<hyper::Method>().is_ok()
                        && method.bytes().all(|byte| byte.is_ascii_uppercase()),
                    "dynamic HTTP capture requires an uppercase method"
                );
                crate::path_pattern::validate_path_pattern(path)?;
                validate_pointer(json_pointer)?;
            }
        }
        Ok(())
    }
}

fn validate_pointer(pointer: &str) -> Result<()> {
    super::super::response::validate_json_pointer(pointer)?;
    ensure!(
        !pointer.split('/').any(|part| part == "*"),
        "dynamic capture JSON pointer must be exact"
    );
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DynamicValueFormat {
    Uuid,
    UuidV4,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DynamicValueType {
    #[default]
    String,
    Integer,
}

impl DynamicValueType {
    fn is_string(&self) -> bool {
        *self == Self::String
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DynamicValueRule {
    #[serde(default, skip_serializing_if = "DynamicValueType::is_string")]
    pub value_type: DynamicValueType,
    pub id: String,
    #[serde(default)]
    pub api: String,
    pub targets: Vec<DynamicValueTarget>,
    pub capture: DynamicValueCapture,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<DynamicValueFormat>,
    #[serde(default)]
    pub source_evidence: String,
}

impl DynamicValueRule {
    pub(in crate::replay) fn validate(&self) -> Result<()> {
        ensure!(
            !self.id.is_empty()
                && self.id.len() <= 128
                && self
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')),
            "invalid dynamic value rule id"
        );
        ensure!(
            matches!(
                self.api
                    .parse::<crate::recording_api::RecordingApiScope>()?,
                crate::recording_api::RecordingApiScope::Route(_)
            ),
            "dynamic value API must be an HTTP route"
        );
        ensure!(
            !self.targets.is_empty() && self.targets.len() <= 32,
            "dynamic values require 1-32 scoped endpoints"
        );
        for target in &self.targets {
            target.validate()?;
        }
        self.capture.validate()?;
        ensure!(
            self.value_type == DynamicValueType::String
                || matches!(self.capture, DynamicValueCapture::Http { .. })
                    && self.format.is_none(),
            "integer dynamic values require an HTTP JSON capture without a string format"
        );
        let target = self.capture.target();
        ensure!(
            self.targets.iter().any(|endpoint| endpoint == target),
            "dynamic capture endpoint must belong to targets"
        );
        crate::config::process_owned_dependencies::validate_source_evidence(&self.source_evidence)?;
        Ok(())
    }

    pub(in crate::replay) fn validate_value(&self, value: &str) -> Result<()> {
        if self.value_type == DynamicValueType::Integer {
            let value: serde_json::Value = serde_json::from_str(value)?;
            ensure!(
                value.is_i64() || value.is_u64(),
                "dynamic identity must be a JSON integer"
            );
            return Ok(());
        }
        ensure!(
            !value.is_empty() && value.len() <= 1024,
            "dynamic identities must be nonempty strings of at most 1024 bytes"
        );
        if let Some(format) = self.format {
            let uuid = uuid::Uuid::parse_str(value)?;
            ensure!(
                format != DynamicValueFormat::UuidV4 || uuid.get_version_num() == 4,
                "dynamic identity must be UUID v4"
            );
        }
        Ok(())
    }
}

pub(in crate::replay) fn validate(rules: &[DynamicValueRule]) -> Result<()> {
    let mut ids = std::collections::BTreeSet::new();
    ensure!(
        rules.len() <= 64,
        "at most 64 dynamic value rules are supported"
    );
    for (index, rule) in rules.iter().enumerate() {
        rule.validate()?;
        ensure!(ids.insert(&rule.id), "duplicate dynamic value rule id");
        ensure!(
            !rules[..index]
                .iter()
                .any(
                    |other| crate::path_pattern::path_patterns_overlap(&other.api, &rule.api)
                        && other.capture == rule.capture
                ),
            "duplicate dynamic value capture location"
        );
    }
    Ok(())
}
