//! Case-local identity equality and injectivity, independent of payload text.
use super::*;
use crate::policy::IdentityFormat;
use sha2::{Digest, Sha256};

#[derive(Clone, Default)]
pub(crate) struct Bijection {
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

    pub(crate) fn observe(&mut self, source: &Value, target: &Value) -> Result<(), &'static str> {
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

    pub(super) fn pairs(
        &self,
    ) -> impl Iterator<Item = crate::value_contract::identities::IdentityPair> {
        self.tokens.values().map(move |(source, target)| {
            crate::value_contract::identities::IdentityPair {
                source: source.clone(),
                target: target.clone(),
            }
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
        IdentityFormat::String | IdentityFormat::BoundedString(_) => {
            let bound = if let IdentityFormat::BoundedString(bound) = format {
                bound
            } else {
                1024
            };
            !token.is_empty()
                && value
                    .as_str()
                    .is_some_and(|text| text.len() <= bound && !text.chars().any(char::is_control))
        }
        IdentityFormat::Jwt => {
            value.as_str().is_some_and(|value| value.len() <= 64 * 1024)
                && crate::value_contract::global_protocol::is_jwt(&Value::String(token.clone()))
        }
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

/// Complete typed scalar used by the automatic case-local correspondence.
/// Format validation never removes literal prefixes or scalar types from this key.
pub(crate) fn key(value: &Value, pointer: &str) -> Result<String, Difference> {
    let valid = match value {
        Value::String(text) => text.len() <= 64 * 1024,
        Value::Number(_) | Value::Bool(_) => true,
        _ => false,
    };
    if !valid {
        return Err(difference(
            pointer,
            "identity scalar representation is invalid",
        ));
    }
    serde_json::to_string(value)
        .map_err(|_| difference(pointer, "identity scalar cannot be represented"))
}
