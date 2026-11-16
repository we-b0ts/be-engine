//! Opaque physical origins supplied by native value owners.
use sha2::{Digest, Sha256};

use super::PhysicalOrigin;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ValueOrigin([u8; 32]);

impl ValueOrigin {
    /// The native owner supplies its versioned domain and canonical components.
    pub fn from_parts(domain: &[u8], parts: &[&[u8]]) -> Self {
        let mut hash = Sha256::new();
        hash.update(domain);
        for part in parts {
            hash.update((part.len() as u64).to_be_bytes());
            hash.update(part);
        }
        Self(hash.finalize().into())
    }
}

impl PhysicalOrigin for ValueOrigin {
    fn fingerprint(self) -> [u8; 32] {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_components_retain_boundaries_and_domain_ownership() {
        let a = ValueOrigin::from_parts(b"custom/v1", &[b"ab", b"c"]);
        let b = ValueOrigin::from_parts(b"custom/v1", &[b"a", b"bc"]);
        let c = ValueOrigin::from_parts(b"another/v1", &[b"ab", b"c"]);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_eq!(a, ValueOrigin::from_parts(b"custom/v1", &[b"ab", b"c"]));
    }
}
