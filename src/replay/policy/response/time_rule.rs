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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResponseTimeRule {
    Timestamp { format: ResponseTimestampFormat },
    Duration { unit: ResponseDurationUnit },
}

impl ResponseTimeRule {
    pub fn from_options(
        kind: Option<ResponseRuleKind>,
        unit: Option<ResponseDurationUnit>,
        format: Option<ResponseTimestampFormat>,
    ) -> Result<Option<Self>> {
        match kind {
            Some(ResponseRuleKind::Timestamp) => {
                ensure!(
                    unit.is_none(),
                    "timestamp rules use --timestamp-format / format, not unit"
                );
                let format = format.ok_or_else(|| anyhow::anyhow!(
                    "timestamp rules require --timestamp-format / format (unix_seconds, unix_milliseconds, rfc3339)"
                ))?;
                Ok(Some(Self::Timestamp { format }))
            }
            Some(ResponseRuleKind::Duration) => {
                ensure!(
                    format.is_none(),
                    "duration rules use --unit / unit, not timestamp format"
                );
                let unit = unit.ok_or_else(|| {
                    anyhow::anyhow!("duration rules require --unit / unit (milliseconds, seconds, minutes, hours)")
                })?;
                Ok(Some(Self::Duration { unit }))
            }
            _ => {
                ensure!(
                    unit.is_none() && format.is_none(),
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
            Self::Timestamp { format } => Some(format),
            _ => None,
        }
    }

    pub(in crate::replay) fn validate(kind: ResponseRuleKind, time: Option<Self>) -> Result<()> {
        Self::from_options(
            Some(kind),
            time.and_then(Self::unit),
            time.and_then(Self::format),
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
            ("duration", "unit: hours", true),
            ("duration", "unit: minutes", true),
            ("timestamp", "", false),
            ("duration", "", false),
            ("timestamp", "unit: seconds", false),
            ("duration", "format: rfc3339", false),
            ("uuid", "unit: hours", false),
            ("random", "format: unix_seconds", false),
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
}
