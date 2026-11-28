//! Named signature formats and private, immutable startup key snapshots.
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::{Arc, OnceLock},
};

use anyhow::{Context, Result, ensure};
use traffic_jwt::verification::{Algorithm, PreparedKey};
use traffic_policy_document::signatures::MAX_INFERRED_JWT_PROFILES;
use traffic_policy_value::auth::Matcher;

use super::native::{SignatureAlgorithm, StartupKey};
use crate::signing::{ResolvedSigningKey, SigningKeyResolver, SigningKeySource};

pub use traffic_policy_document::SignatureDefinition;
pub use traffic_policy_document::signatures::validate;

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
pub struct SignatureRegistry {
    definitions: BTreeMap<String, SignatureDefinition>,
    prepared: Arc<OnceLock<PreparedSignatures>>,
}

struct PreparedSignatures {
    keys: BTreeMap<String, ResolvedSigningKey>,
    matcher: Matcher,
}

impl std::fmt::Debug for SignatureRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SignatureRegistry")
            .field("definitions", &self.definitions)
            .field("prepared", &self.prepared.get().is_some())
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
    pub fn new(
        definitions: &BTreeMap<String, SignatureDefinition>,
        required: &BTreeSet<String>,
    ) -> Result<Self> {
        let mut selected = required
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
        let inferred = definitions
            .iter()
            .filter(|(_, definition)| definition.inferred());
        ensure!(
            inferred.clone().count() <= MAX_INFERRED_JWT_PROFILES,
            "signatures exceeds {MAX_INFERRED_JWT_PROFILES} inferred JWT profiles"
        );
        selected.extend(inferred.map(|(name, definition)| (name.clone(), definition.clone())));
        Ok(Self {
            definitions: selected,
            prepared: Arc::default(),
        })
    }

    pub fn is_empty(&self) -> bool {
        self.definitions.is_empty()
    }

    pub fn needs_prepare(&self) -> bool {
        !self.is_empty() && self.prepared.get().is_none()
    }

    pub fn prepare(&self, root: &Path, resolver: SigningKeyResolver) -> Result<()> {
        if self.prepared.get().is_some() {
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
                    ResolvedSigningKey::resolve(root, &source(key), resolver)?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        // Concurrent owners resolve the same managed startup inputs. The first
        // complete immutable snapshot wins; plans independently freeze witnesses.
        let matcher = prepare_matcher(&self.definitions, &keys)?;
        let _ = self.prepared.set(PreparedSignatures { keys, matcher });
        Ok(())
    }

    pub fn get(&self, name: &str) -> Result<(&SignatureAlgorithm, &[u8])> {
        let Some(SignatureDefinition::Jwt { algorithm, .. }) = self.definitions.get(name) else {
            anyhow::bail!("JWT signature definition is unavailable");
        };
        let key = self
            .prepared
            .get()
            .and_then(|prepared| prepared.keys.get(name))
            .context("JWT signing key context has not been prepared")?;
        Ok((algorithm, key.bytes()))
    }

    pub fn resolved_keys(&self) -> Vec<ResolvedSigningKey> {
        self.prepared
            .get()
            .into_iter()
            .flat_map(|prepared| prepared.keys.values())
            .cloned()
            .collect()
    }

    pub(crate) fn auth_matcher(&self) -> Option<Matcher> {
        if let Some(prepared) = self.prepared.get() {
            Some(prepared.matcher.clone())
        } else if self.definitions.values().any(SignatureDefinition::inferred) {
            None
        } else {
            Some(Matcher::default())
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(
        definitions: BTreeMap<String, SignatureDefinition>,
        keys: BTreeMap<String, Vec<u8>>,
    ) -> Self {
        let keys = keys
            .into_iter()
            .map(|(name, value)| (name, ResolvedSigningKey::for_test(&value)))
            .collect();
        let matcher = prepare_matcher(&definitions, &keys).expect("valid test JWT keys");
        Self {
            definitions,
            prepared: Arc::new(OnceLock::from(PreparedSignatures { keys, matcher })),
        }
    }
}

fn prepare_matcher(
    definitions: &BTreeMap<String, SignatureDefinition>,
    keys: &BTreeMap<String, ResolvedSigningKey>,
) -> Result<Matcher> {
    let mut inferred = Vec::new();
    for (name, definition) in definitions {
        let SignatureDefinition::Jwt {
            algorithm,
            infer: true,
            ..
        } = definition
        else {
            continue;
        };
        let key = keys.get(name).context("inferred JWT key is not prepared")?;
        let algorithm = match algorithm {
            SignatureAlgorithm::HS256 => Algorithm::HS256,
            SignatureAlgorithm::HS384 => Algorithm::HS384,
            SignatureAlgorithm::HS512 => Algorithm::HS512,
            SignatureAlgorithm::RS256 => Algorithm::RS256,
        };
        inferred.push(
            PreparedKey::new(algorithm, key.bytes())
                .with_context(|| format!("cannot prepare inferred JWT profile {name:?}"))?,
        );
    }
    Ok(Matcher::new(inferred))
}
