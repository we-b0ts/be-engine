//! Case-local identity equality and injectivity, independent of payload text.
use super::*;
use crate::rule::IdentityFormat;
use sha2::{Digest, Sha256};

#[derive(Clone, Default)]
pub struct Bijection {
    forward: BTreeMap<[u8; 32], [u8; 32]>,
    reverse: BTreeMap<[u8; 32], [u8; 32]>,
    tokens: BTreeMap<[u8; 32], (String, String)>,
    bytes: usize,
}

impl std::fmt::Debug for Bijection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Bijection")
            .field("entities", &self.forward.len())
            .finish()
    }
}

#[cfg(test)]
mod tests;

impl Bijection {
    fn bind(&mut self, source: [u8; 32], target: [u8; 32]) -> Result<(), &'static str> {
        if self.forward.get(&source).is_some_and(|v| *v != target)
            || self.reverse.get(&target).is_some_and(|v| *v != source)
        {
            return Err("identity equality relationship changed");
        }
        if !self.forward.contains_key(&source) && self.forward.len() >= 4096 {
            return Err("identity relationship exceeds 4096 entities per interaction");
        }
        self.forward.insert(source, target);
        self.reverse.insert(target, source);
        Ok(())
    }

    pub fn observe(&mut self, source: &Value, target: &Value) -> Result<(), &'static str> {
        if std::mem::discriminant(source) != std::mem::discriminant(target) {
            return Err("identity scalar representation changed");
        }
        let source = key(source, "").map_err(|_| "identity scalar representation is invalid")?;
        let target = key(target, "").map_err(|_| "identity scalar representation is invalid")?;
        let source_hash = Sha256::digest(source.as_bytes()).into();
        let target_hash = Sha256::digest(target.as_bytes()).into();
        self.bind(source_hash, target_hash)?;
        self.store_tokens(source_hash, source, target)?;
        Ok(())
    }

    fn store_tokens(
        &mut self,
        hash: [u8; 32],
        source: String,
        target: String,
    ) -> Result<(), &'static str> {
        if !self.tokens.contains_key(&hash) {
            let added = source.len() + target.len();
            if self.bytes + added > 16 * 1024 * 1024 {
                return Err("identity observation byte bound exceeded");
            }
            self.bytes += added;
            self.tokens.insert(hash, (source, target));
        }
        Ok(())
    }

    pub(super) fn merge(&mut self, other: Self) -> Result<(), &'static str> {
        for (source, target) in other.forward {
            self.bind(source, target)?;
        }
        for (hash, (source, target)) in other.tokens {
            self.store_tokens(hash, source, target)?;
        }
        Ok(())
    }

    pub(super) fn pairs(&self) -> impl Iterator<Item = crate::identity::IdentityPair> {
        self.tokens
            .values()
            .map(move |(source, target)| crate::identity::IdentityPair {
                source: source.clone(),
                target: target.clone(),
            })
    }
}

pub(super) fn compare(
    source: &Value,
    target: &Value,
    prefix: &str,
    format: IdentityFormat,
    pointer: &str,
    decisions: &mut Decisions,
) -> Result<(), Difference> {
    if source == target {
        return decisions
            .identities
            .observe(source, target)
            .map_err(|reason| difference(pointer, reason));
    }
    if source.is_string() != target.is_string() || source.is_number() != target.is_number() {
        return Err(difference(
            pointer,
            "identity scalar representation changed",
        ));
    }
    token(source, prefix, format, pointer)?;
    token(target, prefix, format, pointer)?;
    decisions
        .identities
        .observe(source, target)
        .map_err(|reason| difference(pointer, reason))
}

pub(super) fn fingerprint(
    value: &Value,
    prefix: &str,
    format: IdentityFormat,
    pointer: &str,
) -> Result<[u8; 32], Difference> {
    token(value, prefix, format, pointer)?;
    Ok(Sha256::digest(key(value, pointer)?.as_bytes()).into())
}

pub use crate::identity::{key, token};
