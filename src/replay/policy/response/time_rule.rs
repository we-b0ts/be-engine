use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use super::ResponseRuleKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum ResponseDurationUnit {
    Seconds,
    Milliseconds,
    Minutes,
    Hours,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum ResponseTimestampFormat {
    UnixSeconds,
    UnixMilliseconds,
    Rfc3339,
    AmzDate,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum ResponseTimestampMode {
    #[default]
    RequestWindow,
    PreserveRelative,
}

impl ResponseTimestampMode {
    fn is_request_window(&self) -> bool {
        *self == Self::RequestWindow
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResponseTimeRule {
    Timestamp {
        format: ResponseTimestampFormat,
        #[serde(
            default,
            skip_serializing_if = "ResponseTimestampMode::is_request_window"
        )]
        mode: ResponseTimestampMode,
    },
    Duration {
        unit: ResponseDurationUnit,
    },
}

impl ResponseTimeRule {
    pub fn from_options(
        kind: Option<ResponseRuleKind>,
        unit: Option<ResponseDurationUnit>,
        format: Option<ResponseTimestampFormat>,
    ) -> Result<Option<Self>> {
        Self::from_options_with_mode(kind, unit, format, None)
    }

    pub fn from_options_with_mode(
        kind: Option<ResponseRuleKind>,
        unit: Option<ResponseDurationUnit>,
        format: Option<ResponseTimestampFormat>,
        mode: Option<ResponseTimestampMode>,
    ) -> Result<Option<Self>> {
        match kind {
            Some(ResponseRuleKind::Timestamp) => {
                ensure!(
                    unit.is_none(),
                    "timestamp rules use --timestamp-format / format, not unit"
                );
                let format = format.ok_or_else(|| anyhow::anyhow!(
                    "timestamp rules require --timestamp-format / format (unix_seconds, unix_milliseconds, rfc3339, amz_date)"
                ))?;
                Ok(Some(Self::Timestamp {
                    format,
                    mode: mode.unwrap_or_default(),
                }))
            }
            Some(ResponseRuleKind::Duration) => {
                ensure!(
                    format.is_none() && mode.is_none(),
                    "duration rules use --unit / unit, not timestamp format or mode"
                );
                let unit = unit.ok_or_else(|| {
                    anyhow::anyhow!("duration rules require --unit / unit (milliseconds, seconds, minutes, hours)")
                })?;
                Ok(Some(Self::Duration { unit }))
            }
            _ => {
                ensure!(
                    unit.is_none() && format.is_none() && mode.is_none(),
                    "time settings require a timestamp or duration rule"
                );
                Ok(None)
            }
        }
    }

    pub fn unit(self) -> Option<ResponseDurationUnit> {
        match self {
            Self::Duration { unit } => Some(unit),
            _ => None,
        }
    }

    pub fn format(self) -> Option<ResponseTimestampFormat> {
        match self {
            Self::Timestamp { format, .. } => Some(format),
            _ => None,
        }
    }

    pub fn timestamp_mode(self) -> Option<ResponseTimestampMode> {
        match self {
            Self::Timestamp { mode, .. } => Some(mode),
            _ => None,
        }
    }

    pub(in crate::replay) fn validate(kind: ResponseRuleKind, time: Option<Self>) -> Result<()> {
        Self::from_options_with_mode(
            Some(kind),
            time.and_then(Self::unit),
            time.and_then(Self::format),
            time.and_then(Self::timestamp_mode),
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::replay::policy::response::{ResponseRules, validate_response_rules};

    #[test]
    fn time_rule_schema_requires_explicit_compatible_settings() {
        for (kind, settings, valid) in [
            ("timestamp", "format: unix_seconds", true),
            ("timestamp", "format: rfc3339", true),
            (
                "timestamp",
                "format: rfc3339\n        time: preserve_relative",
                true,
            ),
            (
                "timestamp",
                "format: unix_seconds\n        time: request_window",
                true,
            ),
            ("timestamp", "time: preserve_relative", false),
            ("duration", "unit: hours", true),
            ("duration", "unit: minutes", true),
            ("timestamp", "", false),
            ("duration", "", false),
            ("timestamp", "unit: seconds", false),
            ("duration", "format: rfc3339", false),
            (
                "duration",
                "unit: seconds\n        time: preserve_relative",
                false,
            ),
            ("uuid", "unit: hours", false),
            ("random", "format: unix_seconds", false),
            ("random", "time: preserve_relative", false),
        ] {
            let yaml = format!(
                "json:\n  'GET /api/items':\n    {kind}:\n      - pointer: /data/*/value\n        {settings}\n        source_evidence: src/items.rs:value\n        source_example: '1'\n        target_example: '2'\n"
            );
            let rules: ResponseRules = serde_yaml::from_str(&yaml).unwrap();
            assert_eq!(
                validate_response_rules(&rules).is_ok(),
                valid,
                "{kind} {settings}"
            );
        }
    }

    #[test]
    fn legacy_timestamp_profiles_keep_the_default_and_reject_unknown_modes() {
        let raw = r#"{"kind":"timestamp","format":"rfc3339"}"#;
        let rule: super::ResponseTimeRule = serde_json::from_str(raw).unwrap();
        assert_eq!(
            rule.timestamp_mode(),
            Some(super::ResponseTimestampMode::RequestWindow)
        );
        assert_eq!(
            serde_json::to_value(rule).unwrap(),
            serde_json::from_str::<serde_json::Value>(raw).unwrap()
        );
        assert!(
            serde_json::from_str::<super::ResponseTimeRule>(
                r#"{"kind":"timestamp","format":"rfc3339","mode":"ignore"}"#
            )
            .is_err()
        );
    }
}
