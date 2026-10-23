//! Case-local identity equality and injectivity, independent of payload text.
use super::*;
use crate::policy::IdentityFormat;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Default)]
pub(crate) struct Bijection {
    forward: BTreeMap<[u8; 32], [u8; 32]>,
    reverse: BTreeMap<[u8; 32], [u8; 32]>,
}

#[cfg(test)]
mod tests;

impl Bijection {
    fn bind(&mut self, source: [u8; 32], target: [u8; 32]) -> Result<(), &'static str> {
        if self.forward.get(&source).is_some_and(|v| *v != target)
            || self.reverse.get(&target).is_some_and(|v| *v != source)
        {
            return Err("identity binding bijection changed");
        }
        if !self.forward.contains_key(&source) && self.forward.len() >= 4096 {
            return Err("identity binding exceeds 4096 entities per interaction");
        }
        self.forward.insert(source, target);
        self.reverse.insert(target, source);
        Ok(())
    }

    pub(super) fn merge(&mut self, other: Self) -> Result<(), &'static str> {
        for (source, target) in other.forward {
            self.bind(source, target)?;
        }
        Ok(())
    }
}

pub(super) fn compare(
    source: &Value,
    target: &Value,
    binding: &str,
    prefix: &str,
    format: IdentityFormat,
    pointer: &str,
    decisions: &mut Decisions,
) -> Result<(), Difference> {
    let pair = (
        fingerprint(source, prefix, format, pointer)?,
        fingerprint(target, prefix, format, pointer)?,
    );
    decisions
        .identities
        .entry(binding.into())
        .or_default()
        .bind(pair.0, pair.1)
        .map_err(|reason| difference(pointer, reason))
}

pub(super) fn fingerprint(
    value: &Value,
    prefix: &str,
    format: IdentityFormat,
    pointer: &str,
) -> Result<[u8; 32], Difference> {
    let token = value
        .as_str()
        .and_then(|v| v.strip_prefix(prefix))
        .ok_or_else(|| difference(pointer, "identity type or literal prefix changed"))?;
    let valid = match format {
        IdentityFormat::Decimal => {
            !token.is_empty()
                && token.len() <= 20
                && token.bytes().all(|b| b.is_ascii_digit())
                && !token.starts_with('0')
                && token.parse::<u64>().is_ok()
        }
        IdentityFormat::Hex(length) => {
            token.len() == length
                && token
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }
        IdentityFormat::Uuid => uuid::Uuid::parse_str(token)
            .is_ok_and(|uuid| uuid.hyphenated().to_string() == token && !uuid.is_nil()),
    };
    if !valid {
        return Err(difference(pointer, "identity representation is invalid"));
    }
    Ok(Sha256::digest(token.as_bytes()).into())
}
