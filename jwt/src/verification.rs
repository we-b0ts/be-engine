//! Verification of compact JWTs using trusted startup key material.
use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use jsonwebtoken::{
    DecodingKey,
    jwk::{AlgorithmParameters, JwkSet, KeyAlgorithm, KeyOperations, PublicKeyUse},
};
use serde_json::Value;
use sha2::{Sha256, Sha384, Sha512};

const MAX_TOKEN_BYTES: usize = 64 * 1024;
const MAX_RSA_KEY_BYTES: usize = 256 * 1024;
const MAX_JWKS_KEYS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Algorithm {
    HS256,
    HS384,
    HS512,
    RS256,
}

impl Algorithm {
    fn hmac(self) -> Option<crate::Algorithm> {
        match self {
            Self::HS256 => Some(crate::Algorithm::HS256),
            Self::HS384 => Some(crate::Algorithm::HS384),
            Self::HS512 => Some(crate::Algorithm::HS512),
            Self::RS256 => None,
        }
    }
}

pub struct Token {
    pub algorithm: Algorithm,
    pub header: Value,
    pub claims: Value,
    compact: Box<str>,
    input_end: usize,
    signature: Vec<u8>,
}

impl Token {
    pub fn parse(raw: &str) -> Option<Self> {
        if raw.len() > MAX_TOKEN_BYTES {
            return None;
        }
        let (input, signature) = raw.rsplit_once('.')?;
        let (header, payload) = input.split_once('.')?;
        let json =
            |encoded: &str| traffic_codec_json::parse(&URL_SAFE_NO_PAD.decode(encoded).ok()?);
        let header = json(header)?;
        let claims = json(payload)?;
        if !header.is_object()
            || !claims.is_object()
            || header.get("crit").is_some()
            || header.get("b64").is_some()
            || header.get("kid").is_some_and(|kid| !kid.is_string())
        {
            return None;
        }

        let algorithm = match header["alg"].as_str()? {
            "HS256" => Algorithm::HS256,
            "HS384" => Algorithm::HS384,
            "HS512" => Algorithm::HS512,
            "RS256" => Algorithm::RS256,
            _ => return None,
        };
        let signature = URL_SAFE_NO_PAD.decode(signature).ok()?;
        let valid_signature_len = match algorithm {
            Algorithm::HS256 => signature.len() == 32,
            Algorithm::HS384 => signature.len() == 48,
            Algorithm::HS512 => signature.len() == 64,
            Algorithm::RS256 => !signature.is_empty(),
        };
        valid_signature_len.then(|| Self {
            algorithm,
            header,
            claims,
            compact: raw.into(),
            input_end: input.len(),
            signature,
        })
    }

    fn input(&self) -> &[u8] {
        &self.compact.as_bytes()[..self.input_end]
    }

    fn verify_rsa(&self, key: &DecodingKey) -> bool {
        crate::rsa::verify(key, self.input(), &self.compact[self.input_end + 1..])
    }
}

/// A key prepared once from a trusted startup source. Secret material stays private.
pub struct PreparedKey {
    algorithm: Algorithm,
    material: Material,
}

enum Material {
    Hmac(Box<PreparedHmac>),
    RsaKey(DecodingKey),
    RsaSet(RsaSet),
}

impl PreparedKey {
    pub fn new(algorithm: Algorithm, key: &[u8]) -> Result<Self> {
        ensure!(!key.is_empty(), "JWT verification key is empty");
        let material = if let Some(hmac) = algorithm.hmac() {
            Material::Hmac(Box::new(PreparedHmac::new(hmac, key)))
        } else {
            ensure!(
                key.len() <= MAX_RSA_KEY_BYTES,
                "RSA verification input is too large"
            );
            if key.iter().find(|byte| !byte.is_ascii_whitespace()) == Some(&b'{') {
                Material::RsaSet(RsaSet::prepare(key)?)
            } else {
                Material::RsaKey(
                    crate::rsa::prepare_spki(key)
                        .ok()
                        .context("invalid RSA SPKI public key")?,
                )
            }
        };
        Ok(Self {
            algorithm,
            material,
        })
    }

    pub fn verify(&self, token: &Token) -> bool {
        if token.algorithm != self.algorithm {
            return false;
        }
        match &self.material {
            Material::Hmac(key) => key.as_ref().clone().verify(token.input(), &token.signature),
            Material::RsaKey(key) => token.verify_rsa(key),
            Material::RsaSet(keys) => keys.verify(token),
        }
    }
}

struct RsaSet {
    keyed: BTreeMap<String, DecodingKey>,
    anonymous: Vec<DecodingKey>,
}

impl RsaSet {
    fn prepare(raw: &[u8]) -> Result<Self> {
        let value = traffic_codec_json::parse(raw).context("invalid JWKS JSON")?;
        let entries = value
            .get("keys")
            .and_then(Value::as_array)
            .context("JWKS keys must be an array")?;
        ensure!(
            entries.len() <= MAX_JWKS_KEYS,
            "JWKS contains too many keys"
        );
        let set: JwkSet =
            serde_json::from_value(value).map_err(|_| anyhow::anyhow!("invalid JWKS key entry"))?;
        let mut keyed = BTreeMap::new();
        let mut anonymous = Vec::new();
        for entry in set.keys {
            if !matches!(&entry.algorithm, AlgorithmParameters::RSA(_))
                || entry
                    .common
                    .key_algorithm
                    .is_some_and(|alg| alg != KeyAlgorithm::RS256)
                || entry
                    .common
                    .public_key_use
                    .as_ref()
                    .is_some_and(|usage| *usage != PublicKeyUse::Signature)
                || entry
                    .common
                    .key_operations
                    .as_ref()
                    .is_some_and(|operations| !operations.contains(&KeyOperations::Verify))
            {
                continue;
            }
            let key = DecodingKey::from_jwk(&entry)
                .ok()
                .context("invalid RSA JWK")?;
            if let Some(id) = entry.common.key_id {
                ensure!(keyed.insert(id, key).is_none(), "duplicate RSA JWKS key id");
            } else {
                anonymous.push(key);
            }
        }
        ensure!(
            !keyed.is_empty() || !anonymous.is_empty(),
            "JWKS has no RS256 verification keys"
        );
        Ok(Self { keyed, anonymous })
    }

    fn verify(&self, token: &Token) -> bool {
        if let Some(id) = token.header["kid"].as_str() {
            self.keyed.get(id).is_some_and(|key| token.verify_rsa(key))
        } else {
            self.keyed
                .values()
                .chain(&self.anonymous)
                .any(|key| token.verify_rsa(key))
        }
    }
}

#[derive(Clone)]
pub(crate) enum PreparedHmac {
    HS256(Hmac<Sha256>),
    HS384(Hmac<Sha384>),
    HS512(Hmac<Sha512>),
}

impl PreparedHmac {
    pub(crate) fn new(algorithm: crate::Algorithm, key: &[u8]) -> Self {
        match algorithm {
            crate::Algorithm::HS256 => {
                Self::HS256(Hmac::new_from_slice(key).expect("HMAC accepts any key size"))
            }
            crate::Algorithm::HS384 => {
                Self::HS384(Hmac::new_from_slice(key).expect("HMAC accepts any key size"))
            }
            crate::Algorithm::HS512 => {
                Self::HS512(Hmac::new_from_slice(key).expect("HMAC accepts any key size"))
            }
        }
    }

    pub(crate) fn verify(self, input: &[u8], signature: &[u8]) -> bool {
        macro_rules! verify {
            ($mac:expr) => {{
                let mut mac = $mac;
                mac.update(input);
                mac.verify_slice(signature).is_ok()
            }};
        }
        match self {
            Self::HS256(mac) => verify!(mac),
            Self::HS384(mac) => verify!(mac),
            Self::HS512(mac) => verify!(mac),
        }
    }
}

#[cfg(test)]
mod tests;
