//! Frozen signing material supplied by the managed startup adapter.
use anyhow::{Result, ensure};
use std::path::{Path, PathBuf};
pub use traffic_jwt::key::SigningKeySource;
pub type SigningKeyMaterial = (Vec<u8>, Vec<(PathBuf, String)>);
pub type SigningKeyResolver = fn(&Path, &SigningKeySource) -> Result<SigningKeyMaterial>;
/// Private, immutable key snapshot. It is deliberately neither Debug nor Serialize.
#[derive(Clone)]
pub struct ResolvedSigningKey {
    root: PathBuf,
    source: SigningKeySource,
    value: Vec<u8>,
    witnesses: Vec<(PathBuf, String)>,
    resolver: SigningKeyResolver,
}

impl ResolvedSigningKey {
    pub fn resolve(
        root: &Path,
        source: &SigningKeySource,
        resolver: SigningKeyResolver,
    ) -> Result<Self> {
        let (value, witnesses) = resolver(root, source)?;
        Ok(Self {
            root: root.into(),
            source: source.clone(),
            value,
            witnesses,
            resolver,
        })
    }
    pub fn bytes(&self) -> &[u8] {
        &self.value
    }
    pub fn witnesses(&self) -> impl Iterator<Item = &(PathBuf, String)> {
        self.witnesses.iter()
    }
    pub fn ensure_current(&self) -> Result<()> {
        ensure!(
            (self.resolver)(&self.root, &self.source)?.0 == self.value,
            "JWT signing input changed after planning; obtain fresh evidence and plan again"
        );
        Ok(())
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(value: &[u8]) -> Self {
        Self {
            root: PathBuf::new(),
            source: SigningKeySource::TargetEnv {
                name: "TEST_KEY".into(),
            },
            value: value.into(),
            witnesses: vec![],
            resolver: |_, _| anyhow::bail!("test signing key has no mutable source"),
        }
    }
}
