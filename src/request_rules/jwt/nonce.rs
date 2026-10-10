//! Explicit nonce formats; identity and authorization claims remain exact.
use anyhow::{Result, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DynamicClaim {
    /// Original syntax: only `/jti`, with UUID v4 semantics.
    Legacy(String),
    Typed(NonceClaim),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NonceClaim {
    pub pointer: String,
    pub format: NonceFormat,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decoded_bytes: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NonceFormat {
    UuidV4,
    Base64url,
}

impl DynamicClaim {
    pub(crate) fn pointer(&self) -> &str {
        match self {
            Self::Legacy(pointer) => pointer,
            Self::Typed(rule) => &rule.pointer,
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        match self {
            Self::Legacy(pointer) => ensure!(
                pointer == "/jti",
                "string JWT dynamic claims support only UUID v4 /jti"
            ),
            Self::Typed(rule) => {
                ensure!(
                    matches!(rule.pointer.as_str(), "/jti" | "/nonce"),
                    "typed JWT dynamic claims select only /jti or /nonce"
                );
                match rule.format {
                    NonceFormat::UuidV4 => ensure!(
                        rule.decoded_bytes.is_none(),
                        "UUID v4 nonce does not use decoded_bytes"
                    ),
                    NonceFormat::Base64url => ensure!(
                        rule.decoded_bytes
                            .is_some_and(|size| (1..=256).contains(&size)),
                        "base64url nonce requires decoded_bytes between 1 and 256"
                    ),
                }
            }
        }
        Ok(())
    }

    pub(crate) fn accepts(&self, value: &str) -> bool {
        match self {
            Self::Typed(NonceClaim {
                format: NonceFormat::Base64url,
                decoded_bytes,
                ..
            }) => {
                // Canonical, unpadded URL-safe encoding, including unused trailing bits.
                value.len() <= 342
                    && URL_SAFE_NO_PAD.decode(value).ok().is_some_and(|bytes| {
                        Some(bytes.len()) == *decoded_bytes
                            && URL_SAFE_NO_PAD.encode(bytes) == value
                    })
            }
            _ => uuid::Uuid::parse_str(value).ok().is_some_and(|id| {
                id.get_version_num() == 4 && id.get_variant() == uuid::Variant::RFC4122
            }),
        }
    }
}
