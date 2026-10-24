//! Named signature formats and private, immutable startup key snapshots.
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::{Arc, OnceLock},
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use super::native::{SignatureAlgorithm, StartupKey};
use crate::request_rules::keys::{ResolvedSigningKey, SigningKeySource};

#[cfg(test)]
mod tests;

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
    pub(crate) fn validate(&self) -> Result<()> {
        let key = match self {
            Self::Jwt { key, .. } | Self::Md5SortedFields { key } => key,
        };
        super::native_compile::validate_startup_key(key)
    }
}

pub(crate) fn validate(definitions: &BTreeMap<String, SignatureDefinition>) -> Result<()> {
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

fn source(key: &StartupKey) -> SigningKeySource {
    match key {
        StartupKey::TargetEnv { name } => SigningKeySource::TargetEnv { name: name.clone() },
        StartupKey::TargetFile { path, field } => SigningKeySource::TargetFile {
            path: path.into(),
            field: field.clone(),
        },
    }
}

/// Keys are initialized once by the runtime owner, never by pure compilation or
/// by a payload comparator. Serialization and equality retain definitions only.
#[derive(Clone, Default)]
pub(crate) struct SignatureRegistry {
    definitions: BTreeMap<String, SignatureDefinition>,
    keys: Arc<OnceLock<BTreeMap<String, ResolvedSigningKey>>>,
}

impl std::fmt::Debug for SignatureRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SignatureRegistry")
            .field("definitions", &self.definitions)
            .field("prepared", &self.keys.get().is_some())
            .finish()
    }
}

impl PartialEq for SignatureRegistry {
    fn eq(&self, other: &Self) -> bool {
        self.definitions == other.definitions
    }
}
impl Eq for SignatureRegistry {}

impl SignatureRegistry {
    pub(crate) fn new(
        definitions: &BTreeMap<String, SignatureDefinition>,
        required: &BTreeSet<String>,
    ) -> Result<Self> {
        let definitions = required
            .iter()
            .map(|name| {
                let definition = definitions
                    .get(name)
                    .with_context(|| format!("undefined JWT signature {name:?}"))?;
                ensure!(
                    matches!(definition, SignatureDefinition::Jwt { .. }),
                    "JSON JWT fields require a JWT signature definition"
                );
                Ok((name.clone(), definition.clone()))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        Ok(Self {
            definitions,
            keys: Arc::default(),
        })
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.definitions.is_empty()
    }

    pub(crate) fn needs_prepare(&self) -> bool {
        !self.is_empty() && self.keys.get().is_none()
    }

    pub(crate) fn prepare(&self, root: &Path) -> Result<()> {
        if self.keys.get().is_some() {
            return Ok(());
        }
        let keys = self
            .definitions
            .iter()
            .map(|(name, definition)| {
                let SignatureDefinition::Jwt { key, .. } = definition else {
                    anyhow::bail!("JWT key context contains a non-JWT definition");
                };
                Ok((
                    name.clone(),
                    ResolvedSigningKey::resolve(root, &source(key))?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        // Concurrent owners resolve the same managed startup inputs. The first
        // complete immutable snapshot wins; plans independently freeze witnesses.
        let _ = self.keys.set(keys);
        Ok(())
    }

    pub(crate) fn get(&self, name: &str) -> Result<(&SignatureAlgorithm, &[u8])> {
        let Some(SignatureDefinition::Jwt { algorithm, .. }) = self.definitions.get(name) else {
            anyhow::bail!("JWT signature definition is unavailable");
        };
        let key = self
            .keys
            .get()
            .and_then(|keys| keys.get(name))
            .context("JWT signing key context has not been prepared")?;
        Ok((algorithm, key.bytes()))
    }

    pub(crate) fn resolved_keys(&self) -> Vec<ResolvedSigningKey> {
        self.keys
            .get()
            .into_iter()
            .flat_map(BTreeMap::values)
            .cloned()
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        definitions: BTreeMap<String, SignatureDefinition>,
        keys: BTreeMap<String, Vec<u8>>,
    ) -> Self {
        Self {
            definitions,
            keys: Arc::new(OnceLock::from(
                keys.into_iter()
                    .map(|(name, value)| (name, ResolvedSigningKey::for_test(&value)))
                    .collect::<BTreeMap<_, _>>(),
            )),
        }
    }
}
