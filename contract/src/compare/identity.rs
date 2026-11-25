//! Case-local identity equality and injectivity, independent of payload text.
use super::*;
#[cfg(test)]
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
    pub(super) fn prefetch_retained_bytes(&self) -> usize {
        if self.forward.is_empty() {
            return 0;
        }
        let nodes = btree_retained_bytes::<[u8; 32], [u8; 32]>(self.forward.len())
            .saturating_add(btree_retained_bytes::<[u8; 32], [u8; 32]>(
                self.reverse.len(),
            ))
            .saturating_add(btree_retained_bytes::<[u8; 32], (String, String)>(
                self.tokens.len(),
            ));
        self.tokens.values().fold(nodes, |bytes, (source, target)| {
            bytes
                .saturating_add(source.capacity())
                .saturating_add(target.capacity())
        })
    }

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
        let shared = std::ptr::eq(source, target);
        let source = key(source, "").map_err(|_| "identity scalar representation is invalid")?;
        let source_hash = Sha256::digest(source.as_bytes()).into();
        let (target, target_hash) = if shared {
            (source.clone(), source_hash)
        } else {
            let target =
                key(target, "").map_err(|_| "identity scalar representation is invalid")?;
            let hash = Sha256::digest(target.as_bytes()).into();
            (target, hash)
        };
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

pub use crate::identity::key;
