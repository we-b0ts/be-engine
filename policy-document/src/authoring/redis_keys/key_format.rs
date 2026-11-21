//! Physical key formats project to the existing key correspondence owner.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use crate::native::{KeyIdentityFormat, NativeKeyContract};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum KeyFormat {
    Identity {
        formats: Vec<Identity>,
    },
    TimeWindow {
        seconds: u32,
        #[serde(default = "colon", skip_serializing_if = "is_colon")]
        separator: char,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        segment: Option<usize>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "IdentityDocument", into = "IdentityDocument")]
pub struct Identity {
    pub prefix: String,
    pub shape: Shape,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shape {
    UuidV4,
    Hex(usize),
    Base64url(usize),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum IdentityDocument {
    Named(IdentityName),
    Hex {
        #[serde(default, skip_serializing_if = "String::is_empty")]
        prefix: String,
        hex: usize,
    },
    Base64url {
        #[serde(default, skip_serializing_if = "String::is_empty")]
        prefix: String,
        base64url: usize,
    },
    Prefixed {
        prefix: String,
        format: IdentityName,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityName {
    UuidV4,
}

impl From<IdentityDocument> for Identity {
    fn from(value: IdentityDocument) -> Self {
        let (prefix, shape) = match value {
            IdentityDocument::Named(IdentityName::UuidV4) => (String::new(), Shape::UuidV4),
            IdentityDocument::Prefixed {
                prefix,
                format: IdentityName::UuidV4,
            } => (prefix, Shape::UuidV4),
            IdentityDocument::Hex { prefix, hex } => (prefix, Shape::Hex(hex)),
            IdentityDocument::Base64url { prefix, base64url } => {
                (prefix, Shape::Base64url(base64url))
            }
        };
        Self { prefix, shape }
    }
}

impl From<Identity> for IdentityDocument {
    fn from(value: Identity) -> Self {
        match value.shape {
            Shape::UuidV4 if value.prefix.is_empty() => Self::Named(IdentityName::UuidV4),
            Shape::UuidV4 => Self::Prefixed {
                prefix: value.prefix,
                format: IdentityName::UuidV4,
            },
            Shape::Hex(hex) => Self::Hex {
                prefix: value.prefix,
                hex,
            },
            Shape::Base64url(base64url) => Self::Base64url {
                prefix: value.prefix,
                base64url,
            },
        }
    }
}

pub fn colon() -> char {
    ':'
}
pub fn is_colon(value: &char) -> bool {
    *value == ':'
}

pub fn affixes(pattern: &str) -> Result<(&str, &str)> {
    ensure!(
        !pattern.is_empty()
            && pattern.len() <= 1024
            && !pattern.chars().any(char::is_control)
            && !pattern.contains(['{', '}'])
            && pattern.bytes().filter(|&byte| byte == b'*').count() == 1,
        "Redis key_format requires one bounded wildcard identity/time slot"
    );
    let (prefix, suffix) = pattern.split_once('*').expect("validated wildcard");
    ensure!(
        !prefix.is_empty() || !suffix.is_empty(),
        "Redis key_format requires fixed key affixes"
    );
    Ok((prefix, suffix))
}

impl KeyFormat {
    pub fn lower(&self, pattern: &str) -> Result<NativeKeyContract> {
        let (prefix, suffix) = affixes(pattern)?;
        Ok(match self {
            Self::Identity { formats } => {
                ensure!(
                    formats.len() == 1,
                    "Redis key identity requires exactly one declared format"
                );
                let identity = &formats[0];
                ensure!(
                    !identity.prefix.chars().any(char::is_control)
                        && !identity.prefix.contains(['{', '}', '*']),
                    "invalid literal Redis key identity prefix"
                );
                let template = format!("{prefix}{}{{value}}{suffix}", identity.prefix);
                ensure!(
                    template.len() <= 1024,
                    "Redis key identity template exceeds 1024 bytes"
                );
                let format = match identity.shape {
                    Shape::UuidV4 => KeyIdentityFormat::UuidV4,
                    Shape::Hex(characters) => {
                        ensure!(
                            (2..=512).contains(&characters) && characters % 2 == 0,
                            "Redis hexadecimal key identity requires 2..512 even characters"
                        );
                        KeyIdentityFormat::Hex {
                            bytes: characters / 2,
                        }
                    }
                    Shape::Base64url(characters) => {
                        ensure!(
                            (2..=342).contains(&characters),
                            "Redis base64url key identity exceeds its byte bound"
                        );
                        let bytes = characters * 6 / 8;
                        ensure!(
                            (1..=256).contains(&bytes) && (bytes * 8).div_ceil(6) == characters,
                            "Redis base64url key identity length is not canonical unpadded encoding"
                        );
                        KeyIdentityFormat::Base64url { bytes }
                    }
                };
                NativeKeyContract::Capture { template, format }
            }
            Self::TimeWindow {
                seconds,
                separator,
                segment,
            } => {
                ensure!(
                    (1..=31_536_000).contains(seconds)
                        && separator.is_ascii_punctuation()
                        && !matches!(separator, '{' | '}' | '\\')
                        && segment.is_none_or(|index| index < 64),
                    "invalid bounded Redis key time window"
                );
                NativeKeyContract::TimeWindow {
                    window_seconds: *seconds,
                    separator: *separator,
                    segment_index: *segment,
                }
            }
        })
    }
}

/// Return only formats whose re-expansion preserves the exact native contract.
pub fn reverse(pattern: &str, contract: &NativeKeyContract) -> Result<Option<KeyFormat>> {
    let (prefix, suffix) = affixes(pattern)?;
    let result = match contract {
        NativeKeyContract::TimeWindow {
            window_seconds,
            separator,
            segment_index,
        } => KeyFormat::TimeWindow {
            seconds: *window_seconds,
            separator: *separator,
            segment: *segment_index,
        },
        NativeKeyContract::Capture { template, format } => {
            let Some((before, after)) = template.split_once("{value}") else {
                return Ok(None);
            };
            let Some(identity_prefix) = before.strip_prefix(prefix) else {
                return Ok(None);
            };
            if after != suffix {
                return Ok(None);
            }
            let shape = match format {
                KeyIdentityFormat::UuidV4 => Shape::UuidV4,
                KeyIdentityFormat::Hex { bytes } => Shape::Hex(
                    bytes
                        .checked_mul(2)
                        .ok_or_else(|| anyhow::anyhow!("key hex size overflow"))?,
                ),
                KeyIdentityFormat::Base64url { bytes } => Shape::Base64url(
                    bytes
                        .checked_mul(8)
                        .ok_or_else(|| anyhow::anyhow!("key base64 size overflow"))?
                        .div_ceil(6),
                ),
            };
            KeyFormat::Identity {
                formats: vec![Identity {
                    prefix: identity_prefix.into(),
                    shape,
                }],
            }
        }
        NativeKeyContract::Reference(_) => return Ok(None),
    };
    Ok((result.lower(pattern)? == *contract).then_some(result))
}
