//! Case-local identity equality and injectivity, independent of payload text.
use super::*;
use crate::policy::IdentityFormat;
use sha2::{Digest, Sha256};

#[derive(Clone, Default)]
pub(crate) struct Bijection {
    forward: BTreeMap<[u8; 32], [u8; 32]>,
    reverse: BTreeMap<[u8; 32], [u8; 32]>,
    tokens: BTreeMap<[u8; 32], (String, String)>,
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
        self.tokens.extend(other.tokens);
        Ok(())
    }

    pub(super) fn pairs(
        &self,
        binding: &str,
    ) -> impl Iterator<Item = crate::value_contract::identities::IdentityPair> {
        self.tokens.values().map(move |(source, target)| {
            crate::value_contract::identities::IdentityPair {
                domain: binding.to_owned(),
                source: source.clone(),
                target: target.clone(),
            }
        })
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
    if source.is_string() != target.is_string() || source.is_number() != target.is_number() {
        return Err(difference(
            pointer,
            "identity scalar representation changed",
        ));
    }
    let source = token(source, prefix, format, pointer)?;
    let target = token(target, prefix, format, pointer)?;
    let source_hash = Sha256::digest(source.as_bytes()).into();
    let target_hash = Sha256::digest(target.as_bytes()).into();
    let state = decisions.identities.entry(binding.into()).or_default();
    state
        .bind(source_hash, target_hash)
        .map_err(|reason| difference(pointer, reason))?;
    state.tokens.insert(source_hash, (source, target));
    Ok(())
}

pub(super) fn fingerprint(
    value: &Value,
    prefix: &str,
    format: IdentityFormat,
    pointer: &str,
) -> Result<[u8; 32], Difference> {
    Ok(Sha256::digest(token(value, prefix, format, pointer)?.as_bytes()).into())
}

pub(crate) fn token(
    value: &Value,
    prefix: &str,
    format: IdentityFormat,
    pointer: &str,
) -> Result<String, Difference> {
    let token = if let Some(value) = value.as_str().and_then(|value| value.strip_prefix(prefix)) {
        value.to_owned()
    } else if format == IdentityFormat::Decimal && prefix.is_empty() {
        value
            .as_u64()
            .map(|value| value.to_string())
            .ok_or_else(|| difference(pointer, "identity type or literal prefix changed"))?
    } else {
        return Err(difference(
            pointer,
            "identity type or literal prefix changed",
        ));
    };
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
        IdentityFormat::Uuid => uuid::Uuid::parse_str(&token)
            .is_ok_and(|uuid| uuid.hyphenated().to_string() == token && !uuid.is_nil()),
        IdentityFormat::Base64Url(length) => {
            token.len() == length
                && token
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
        }
    };
    if !valid {
        return Err(difference(pointer, "identity representation is invalid"));
    }
    Ok(token)
}
