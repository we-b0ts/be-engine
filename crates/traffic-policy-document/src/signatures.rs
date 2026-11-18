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
    },
    Md5SortedFields {
        key: StartupKey,
    },
}

impl SignatureDefinition {
    pub fn validate(&self) -> Result<()> {
        let key = match self {
            Self::Jwt { key, .. } | Self::Md5SortedFields { key } => key,
        };
        traffic_policy_compiler::native_compile::validate_startup_key(key)
    }
}

pub fn validate(definitions: &BTreeMap<String, SignatureDefinition>) -> Result<()> {
    ensure!(
        definitions.len() <= 256,
        "signatures exceeds 256 definitions"
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
