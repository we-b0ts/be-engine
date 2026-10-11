//! Compact SQL time configuration; retain the original nested syntax on input.
use super::{
    MysqlTimeFieldRule, MysqlTimeValueRule, TimeReference, TimeRule, parse_duration, parse_timezone,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const FORMAT: &str = "%Y-%m-%d %H:%M:%S%.f";
const TIMEZONE: &str = "+00:00";

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
enum TimeConfig {
    Reference(TimeReference),
    Detailed(TimeRule),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TimeFieldConfig {
    time: TimeConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tolerance: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    offset: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    timezone: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    source_evidence: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct JsonConfig {
    json: BTreeMap<String, TimeFieldConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub(super) enum Config {
    Scalar(TimeFieldConfig),
    Json(JsonConfig),
}

impl TryFrom<TimeFieldConfig> for MysqlTimeFieldRule {
    type Error = anyhow::Error;

    fn try_from(config: TimeFieldConfig) -> Result<Self> {
        let mut time = match config.time {
            TimeConfig::Reference(relative_to) => TimeRule {
                relative_to,
                tolerance: config.tolerance.unwrap_or_else(|| "5s".into()),
                offset: config.offset.unwrap_or_else(|| "0s".into()),
                format: Some(config.format.unwrap_or_else(|| FORMAT.into())),
                timezone: Some(config.timezone.unwrap_or_else(|| TIMEZONE.into())),
            },
            TimeConfig::Detailed(time) => {
                ensure!(
                    config.tolerance.is_none()
                        && config.offset.is_none()
                        && config.format.is_none()
                        && config.timezone.is_none(),
                    "nested SQL time rules cannot also set outer time options"
                );
                time
            }
        };
        ensure!(
            parse_duration(&time.tolerance)? == 5_000,
            "MySQL SQL time tolerance is fixed at 5s"
        );
        // Legacy options remain readable, but a shared timezone and source
        // offset cancel in the source/target difference. No rule sets a clock.
        parse_duration(&time.offset)?;
        if let Some(timezone) = &time.timezone {
            parse_timezone(timezone)?;
        }
        time.relative_to = TimeReference::PreserveRelative;
        time.tolerance = "5s".into();
        time.offset = "0s".into();
        time.timezone = Some(TIMEZONE.into());
        Ok(Self {
            source_evidence: config.source_evidence,
            time,
        })
    }
}

impl From<MysqlTimeFieldRule> for TimeFieldConfig {
    fn from(rule: MysqlTimeFieldRule) -> Self {
        // Keep legacy automatic format detection when no format was supplied.
        let compact = rule.time.format.is_some();
        if compact {
            TimeFieldConfig {
                time: TimeConfig::Reference(TimeReference::PreserveRelative),
                tolerance: None,
                offset: None,
                format: rule.time.format.filter(|value| value != FORMAT),
                timezone: None,
                source_evidence: rule.source_evidence,
            }
        } else {
            TimeFieldConfig {
                time: TimeConfig::Detailed(rule.time),
                tolerance: None,
                offset: None,
                format: None,
                timezone: None,
                source_evidence: rule.source_evidence,
            }
        }
    }
}

impl TryFrom<Config> for MysqlTimeValueRule {
    type Error = anyhow::Error;

    fn try_from(config: Config) -> Result<Self> {
        match config {
            Config::Scalar(field) => Ok(Self::Scalar(field.try_into()?)),
            Config::Json(config) => {
                ensure!(
                    !config.json.is_empty(),
                    "MySQL JSON time rule must select at least one JSON Pointer"
                );
                Ok(Self::Json(
                    config
                        .json
                        .into_iter()
                        .map(|(pointer, field)| Ok((pointer, field.try_into()?)))
                        .collect::<Result<_>>()?,
                ))
            }
        }
    }
}

impl From<MysqlTimeValueRule> for Config {
    fn from(rule: MysqlTimeValueRule) -> Self {
        match rule {
            MysqlTimeValueRule::Scalar(field) => Self::Scalar(field.into()),
            MysqlTimeValueRule::Json(fields) => Self::Json(JsonConfig {
                json: fields
                    .into_iter()
                    .map(|(pointer, field)| (pointer, field.into()))
                    .collect(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replay::policy::value::parse_time;
    use serde_json::json;

    #[test]
    fn compact_sql_time_defaults_and_original_syntax_round_trip_without_semantic_changes() {
        for yaml in [
            "time: replay_now",
            "time: replay_now\ntolerance: 5s\noffset: -1s\nformat: '%Y/%m/%d %H:%M:%S'\ntimezone: '+08:00'",
            "time: {relative_to: replay_now, tolerance: 5s}",
            "time: {relative_to: replay_now, tolerance: 5s, format: '%Y-%m-%d %H:%M:%S%.f'}",
        ] {
            let rule: MysqlTimeValueRule = serde_yaml::from_str(yaml).unwrap();
            let encoded = serde_yaml::to_string(&rule).unwrap();
            let decoded: MysqlTimeValueRule = serde_yaml::from_str(&encoded).unwrap();
            assert_eq!(
                serde_json::to_value(&rule).unwrap(),
                serde_json::to_value(&decoded).unwrap()
            );
        }
        let rule: MysqlTimeValueRule = serde_yaml::from_str("time: replay_now").unwrap();
        let MysqlTimeValueRule::Scalar(rule) = rule else {
            panic!("expected scalar rule")
        };
        assert_eq!(rule.time.tolerance, "5s");
        assert!(parse_time(&json!("2026-09-07 13:38:18.474219"), &rule.time).is_ok());
        assert!(
            serde_yaml::from_str::<MysqlTimeValueRule>(
                "time: {relative_to: replay_now, tolerance: 5s}\ntolerance: 9s"
            )
            .is_err()
        );
        assert!(serde_yaml::from_str::<MysqlTimeValueRule>("time: anything").is_err());
    }

    #[test]
    fn json_sql_time_fields_round_trip_with_independent_formats() {
        let yaml = r#"
json:
  /spec/observedAt:
    time: replay_now
    format: "%+"
  /updatedAt:
    time: replay_now
    tolerance: 5s
"#;
        let rule: MysqlTimeValueRule = serde_yaml::from_str(yaml).unwrap();
        let encoded = serde_yaml::to_string(&rule).unwrap();
        let decoded: MysqlTimeValueRule = serde_yaml::from_str(&encoded).unwrap();
        assert_eq!(
            serde_json::to_value(rule).unwrap(),
            serde_json::to_value(decoded).unwrap()
        );
        assert!(serde_yaml::from_str::<MysqlTimeValueRule>("json: {}").is_err());
    }
}
