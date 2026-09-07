//! Compact SQL time configuration; retain the original nested syntax on input.
use super::{MysqlTimeValueRule, TimeReference, TimeRule};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

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
pub(super) struct Config {
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

impl TryFrom<Config> for MysqlTimeValueRule {
    type Error = anyhow::Error;

    fn try_from(config: Config) -> Result<Self> {
        let time = match config.time {
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
        Ok(Self {
            source_evidence: config.source_evidence,
            time,
        })
    }
}

impl From<MysqlTimeValueRule> for Config {
    fn from(rule: MysqlTimeValueRule) -> Self {
        // Missing format/timezone in the original syntax has different parsing
        // semantics; retain that syntax rather than assigning compact defaults.
        let compact = rule.time.format.is_some() && rule.time.timezone.is_some();
        if compact {
            Self {
                time: TimeConfig::Reference(rule.time.relative_to),
                tolerance: Some(rule.time.tolerance),
                offset: (rule.time.offset != "0s").then_some(rule.time.offset),
                format: rule.time.format.filter(|value| value != FORMAT),
                timezone: rule.time.timezone.filter(|value| value != TIMEZONE),
                source_evidence: rule.source_evidence,
            }
        } else {
            Self {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replay::policy::value::parse_time;
    use serde_json::json;

    #[test]
    fn compact_sql_time_defaults_and_original_syntax_round_trip_without_semantic_changes() {
        for yaml in [
            "time: replay_now",
            "time: replay_now\ntolerance: 2s\noffset: -1s\nformat: '%Y/%m/%d %H:%M:%S'\ntimezone: '+08:00'",
            "time: {relative_to: replay_now, tolerance: 5s}",
            "time: {relative_to: replay_now, tolerance: 5s, format: '%Y-%m-%d %H:%M:%S%.f'}",
        ] {
            let rule: MysqlTimeValueRule = serde_yaml::from_str(yaml).unwrap();
            let encoded = serde_yaml::to_string(&rule).unwrap();
            let decoded: MysqlTimeValueRule = serde_yaml::from_str(&encoded).unwrap();
            assert_eq!(
                serde_json::to_value(&rule.time).unwrap(),
                serde_json::to_value(&decoded.time).unwrap()
            );
        }
        let rule: MysqlTimeValueRule = serde_yaml::from_str("time: replay_now").unwrap();
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
}
