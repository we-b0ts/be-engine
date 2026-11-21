//! Compact JWS/HMAC authentication, NumericDate relationships and typed nonces.
use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Sha256, Sha384, Sha512};

pub mod contract;
pub mod key;
pub mod nonce;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Algorithm {
    HS256,
    HS384,
    HS512,
}

pub struct Token {
    pub algorithm: Algorithm,
    header: String,
    payload: String,
    signature: Vec<u8>,
    pub claims: Value,
}

impl Token {
    pub fn parse(raw: &str) -> Result<Option<Self>> {
        // Other Bearer credentials and malformed tokens retain their original behavior.
        if raw.len() > 64 * 1024 {
            return Ok(None);
        }
        let parts = raw.split('.').collect::<Vec<_>>();
        if parts.len() != 3 {
            return Ok(None);
        }
        let decode = |part| URL_SAFE_NO_PAD.decode(part).ok();
        let Some(header) = decode(parts[0]).and_then(|b| traffic_codec_json::parse(&b)) else {
            return Ok(None);
        };
        let Some(claims) = decode(parts[1]).and_then(|b| traffic_codec_json::parse(&b)) else {
            return Ok(None);
        };
        let Some(signature) = decode(parts[2]) else {
            return Ok(None);
        };
        if !claims.is_object() || header.get("crit").is_some() || header.get("b64").is_some() {
            return Ok(None);
        }
        let algorithm = match header["alg"].as_str() {
            Some("HS256") => Algorithm::HS256,
            Some("HS384") => Algorithm::HS384,
            Some("HS512") => Algorithm::HS512,
            _ => return Ok(None),
        };
        Ok(Some(Self {
            algorithm,
            header: parts[0].into(),
            payload: parts[1].into(),
            signature,
            claims,
        }))
    }

    pub fn header_value(&self) -> Result<Value> {
        Ok(serde_json::from_slice(
            &URL_SAFE_NO_PAD.decode(&self.header)?,
        )?)
    }

    pub fn verify(&self, key: &[u8]) -> bool {
        let input = format!("{}.{}", self.header, self.payload);
        macro_rules! verify {
            ($digest:ty) => {{
                let Ok(mut mac) = Hmac::<$digest>::new_from_slice(key) else {
                    return false;
                };
                mac.update(input.as_bytes());
                mac.verify_slice(&self.signature).is_ok()
            }};
        }
        match self.algorithm {
            Algorithm::HS256 => verify!(Sha256),
            Algorithm::HS384 => verify!(Sha384),
            Algorithm::HS512 => verify!(Sha512),
        }
    }

    pub fn has_time_claims(&self) -> bool {
        ["exp", "nbf", "iat"]
            .iter()
            .any(|name| self.claims.get(name).is_some())
    }

    pub fn integer_claim(&self, name: &str) -> Result<Option<i64>> {
        self.claims
            .get(name)
            .map(|v| {
                v.as_i64()
                    .context("JWT rule requires integer NumericDate claims")
            })
            .transpose()
    }

    pub fn shift(mut self, offset: i64, key: &[u8]) -> Result<String> {
        for name in ["exp", "nbf", "iat"] {
            if let Some(value) = self.integer_claim(name)? {
                self.claims[name] = Value::from(
                    value
                        .checked_add(offset)
                        .context("JWT NumericDate overflow")?,
                );
            }
        }
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&self.claims)?);
        let input = format!("{}.{}", self.header, payload);
        let signature = sign(self.algorithm, key, input.as_bytes());
        Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)))
    }
}

pub fn sign(algorithm: Algorithm, key: &[u8], input: &[u8]) -> Vec<u8> {
    macro_rules! sign {
        ($digest:ty) => {{
            let mut mac =
                Hmac::<$digest>::new_from_slice(key).expect("HMAC accepts arbitrary key lengths");
            mac.update(input);
            mac.finalize().into_bytes().to_vec()
        }};
    }
    match algorithm {
        Algorithm::HS256 => sign!(Sha256),
        Algorithm::HS384 => sign!(Sha384),
        Algorithm::HS512 => sign!(Sha512),
    }
}

pub fn is_jwt(value: &serde_json::Value) -> bool {
    let Some(token) = value.as_str().filter(|token| token.len() <= 64 * 1024) else {
        return false;
    };
    let parts = token.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return false;
    }
    let decode = |part: &str| {
        URL_SAFE_NO_PAD
            .decode(part)
            .ok()
            .filter(|bytes| URL_SAFE_NO_PAD.encode(bytes) == part)
    };
    let Some(header) = decode(parts[0]).and_then(|bytes| traffic_codec_json::parse(&bytes)) else {
        return false;
    };
    let Some(claims) = decode(parts[1]).and_then(|bytes| traffic_codec_json::parse(&bytes)) else {
        return false;
    };
    header.is_object()
        && header
            .get("alg")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|algorithm| !algorithm.is_empty())
        && claims.is_object()
        && decode(parts[2])
            .is_some_and(|signature| !signature.is_empty() || header["alg"] == "none")
}

pub mod rsa;
