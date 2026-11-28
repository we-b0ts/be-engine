//! Named signature references with pure source validation.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use traffic_policy_schema::native::{SignatureAlgorithm, StartupKey};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SignatureDefinition {
    Jwt {
        algorithm: SignatureAlgorithm,
        key: StartupKey,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        infer: bool,
    },
    Md5SortedFields {
        key: StartupKey,
    },
}

impl SignatureDefinition {
    pub fn inferred(&self) -> bool {
        matches!(self, Self::Jwt { infer: true, .. })
    }

    pub fn validate(&self) -> Result<()> {
        let key = match self {
            Self::Jwt { key, .. } | Self::Md5SortedFields { key } => key,
        };
        traffic_policy_compiler::native_compile::validate_startup_key(key)
    }
}

pub const MAX_INFERRED_JWT_PROFILES: usize = 16;

pub fn validate(definitions: &BTreeMap<String, SignatureDefinition>) -> Result<()> {
    ensure!(
        definitions.len() <= 256,
        "signatures exceeds 256 definitions"
    );
    ensure!(
        definitions
            .values()
            .filter(|profile| profile.inferred())
            .count()
            <= MAX_INFERRED_JWT_PROFILES,
        "signatures exceeds {MAX_INFERRED_JWT_PROFILES} inferred JWT profiles"
    );
    for (name, definition) in definitions {
        ensure!(
            !name.is_empty()
                && name.len() <= 128
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')),
            "signature names require 1..128 ASCII letters, digits, underscores, hyphens or dots"
        );
        definition.validate()?;
    }
    Ok(())
}
