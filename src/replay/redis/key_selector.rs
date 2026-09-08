//! Redis key and hash-field byte selectors shared by request and response rules.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
mod config;
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "config::Config", into = "config::Config")]
pub enum RedisValueKeySelector {
    Exact {
        value: String,
    },
    Affix {
        #[serde(default)]
        prefix: String,
        #[serde(default)]
        suffix: String,
    },
    Numeric {
        #[serde(default)]
        prefix: String,
        #[serde(default)]
        suffix: String,
    },
}
impl RedisValueKeySelector {
    pub(crate) fn matches(&self, key: &[u8]) -> bool {
        use crate::config::process_owned_dependencies::{
            matches_redis_key, matches_redis_numeric_key_pattern,
        };
        match self {
            Self::Exact { value } => key == value.as_bytes(),
            Self::Affix { prefix, suffix } => {
                matches_redis_key(key, prefix.as_bytes(), suffix.as_bytes())
            }
            Self::Numeric { prefix, suffix } => {
                matches_redis_numeric_key_pattern(key, prefix.as_bytes(), suffix.as_bytes())
            }
        }
    }
    pub(in crate::replay) fn validate(&self) -> Result<()> {
        let valid = match self {
            Self::Exact { value } => !value.is_empty() && value.len() <= 1024,
            Self::Affix { prefix, suffix } => {
                !(prefix.is_empty() && suffix.is_empty()) && prefix.len() + suffix.len() <= 1024
            }
            Self::Numeric { prefix, suffix } => prefix.len() + suffix.len() <= 1024,
        };
        ensure!(
            valid,
            "Redis value rules require a bounded exact key or nonempty key affixes"
        );
        Ok(())
    }
    pub(in crate::replay) fn overlaps(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Exact { value }, other) | (other, Self::Exact { value }) => {
                other.matches(value.as_bytes())
            }
            (
                Self::Affix {
                    prefix: a,
                    suffix: b,
                }
                | Self::Numeric {
                    prefix: a,
                    suffix: b,
                },
                Self::Affix {
                    prefix: c,
                    suffix: d,
                }
                | Self::Numeric {
                    prefix: c,
                    suffix: d,
                },
            ) => (a.starts_with(c) || c.starts_with(a)) && (b.ends_with(d) || d.ends_with(b)),
        }
    }
}
