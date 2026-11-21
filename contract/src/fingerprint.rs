//! Domain-separated identities for immutable semantic declarations.
use anyhow::Result;
use serde::Serialize;
use sha2::{Digest, Sha256};

pub fn digest<T: Serialize + ?Sized>(domain: &str, value: &T) -> Result<String> {
    let mut hash = Sha256::new();
    hash.update(domain.as_bytes());
    hash.update([0]);
    hash.update(serde_json::to_vec(value)?);
    Ok(format!("sha256:{:x}", hash.finalize()))
}
