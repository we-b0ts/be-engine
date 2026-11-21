//! Compact Redis key/hash-field selectors, with legacy tagged input compatibility.
use super::RedisValueKeySelector;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
#[serde(untagged)]
pub(super) enum Config {
    Exact(String),
    Pattern(Pattern),
}

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Pattern {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    prefix: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    suffix: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    numeric: bool,
}

impl TryFrom<Config> for RedisValueKeySelector {
    type Error = anyhow::Error;
    fn try_from(config: Config) -> Result<Self> {
        let selector = match config {
            Config::Exact(value) => Self::Exact { value },
            Config::Pattern(p) => match p.kind.as_deref() {
                Some("exact") => {
                    ensure!(
                        p.prefix.is_empty() && p.suffix.is_empty() && !p.numeric,
                        "exact Redis selector cannot contain a pattern"
                    );
                    Self::Exact {
                        value: p.value.ok_or_else(|| {
                            anyhow::anyhow!("exact Redis selector requires value")
                        })?,
                    }
                }
                None | Some("affix" | "numeric") => {
                    ensure!(
                        p.value.is_none(),
                        "pattern Redis selector cannot contain value"
                    );
                    ensure!(
                        p.kind.as_deref() != Some("affix") || !p.numeric,
                        "conflicting Redis selector kinds"
                    );
                    if p.numeric || p.kind.as_deref() == Some("numeric") {
                        Self::Numeric {
                            prefix: p.prefix,
                            suffix: p.suffix,
                        }
                    } else {
                        Self::Affix {
                            prefix: p.prefix,
                            suffix: p.suffix,
                        }
                    }
                }
                _ => anyhow::bail!("unknown Redis selector kind"),
            },
        };
        selector.validate()?;
        Ok(selector)
    }
}

impl From<RedisValueKeySelector> for Config {
    fn from(value: RedisValueKeySelector) -> Self {
        match value {
            RedisValueKeySelector::Exact { value } => Self::Exact(value),
            RedisValueKeySelector::Affix { prefix, suffix } => Self::Pattern(Pattern {
                prefix,
                suffix,
                ..Default::default()
            }),
            RedisValueKeySelector::Numeric { prefix, suffix } => Self::Pattern(Pattern {
                prefix,
                suffix,
                numeric: true,
                ..Default::default()
            }),
        }
    }
}
