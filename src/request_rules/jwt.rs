//! Compact JWS/HMAC verification and NumericDate translation, without IO.
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Sha256, Sha384, Sha512};

pub(crate) mod contract;
pub(crate) mod nonce;
pub(crate) mod url_query;

use super::JwtTokenLocation;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Algorithm {
    HS256,
    HS384,
    HS512,
}

pub(crate) struct Token {
    pub(crate) algorithm: Algorithm,
    header: String,
    payload: String,
    signature: Vec<u8>,
    pub(crate) claims: Value,
}

impl Token {
    pub(crate) fn parse(raw: &str) -> Result<Option<Self>> {
        // Other Bearer credentials and malformed tokens retain their original behavior.
        if raw.len() > 64 * 1024 {
            return Ok(None);
        }
        let parts = raw.split('.').collect::<Vec<_>>();
        if parts.len() != 3 {
            return Ok(None);
        }
        let decode = |part| URL_SAFE_NO_PAD.decode(part).ok();
        let Some(header) = decode(parts[0]).and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        else {
            return Ok(None);
        };
        let Some(claims) = decode(parts[1]).and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        else {
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

    pub(crate) fn header_value(&self) -> Result<Value> {
        Ok(serde_json::from_slice(
            &URL_SAFE_NO_PAD.decode(&self.header)?,
        )?)
    }

    pub(crate) fn verify(&self, key: &[u8]) -> bool {
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

    pub(crate) fn has_time_claims(&self) -> bool {
        ["exp", "nbf", "iat"]
            .iter()
            .any(|name| self.claims.get(name).is_some())
    }

    pub(crate) fn integer_claim(&self, name: &str) -> Result<Option<i64>> {
        self.claims
            .get(name)
            .map(|v| {
                v.as_i64()
                    .context("JWT rule requires integer NumericDate claims")
            })
            .transpose()
    }

    pub(crate) fn shift(mut self, offset: i64, key: &[u8]) -> Result<String> {
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

pub(crate) fn sign(algorithm: Algorithm, key: &[u8], input: &[u8]) -> Vec<u8> {
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

pub(crate) fn request_timestamp(request: &Value) -> Result<DateTime<Utc>> {
    request["timestamp"]
        .as_str()
        .context("JWT request rule requires the original recording timestamp")?
        .parse()
        .context("invalid JWT request recording timestamp")
}

pub(crate) fn request_token(
    request: &Value,
    location: &JwtTokenLocation,
) -> Result<Option<String>> {
    match location {
        JwtTokenLocation::BearerHeader { header } => header_token(request, header),
        JwtTokenLocation::QueryParameter { query_param } => {
            let Some(uri) = request["uri"].as_str() else {
                return Ok(None);
            };
            Ok(query_token_range(uri, query_param)?.map(|(_, token)| token))
        }
    }
}

pub(crate) fn replace_request_token(
    request: &mut Value,
    location: &JwtTokenLocation,
    token: String,
) -> Result<()> {
    match location {
        JwtTokenLocation::BearerHeader { header } => {
            if let Some(headers) = request["headers"].as_object_mut() {
                for (key, values) in headers {
                    if key.eq_ignore_ascii_case(header) {
                        let scheme = values[0]
                            .as_str()
                            .and_then(|v| v.split_once(' '))
                            .map(|v| v.0)
                            .context("JWT header changed during transformation")?
                            .to_string();
                        values[0] = Value::String(format!("{scheme} {token}"));
                        return Ok(());
                    }
                }
            }
            bail!("JWT header disappeared during transformation")
        }
        JwtTokenLocation::QueryParameter { query_param } => {
            let uri = request["uri"]
                .as_str()
                .context("JWT request URI disappeared during transformation")?;
            let (range, original) = query_token_range(uri, query_param)?
                .context("JWT query parameter disappeared during transformation")?;
            ensure!(
                !original.is_empty(),
                "JWT query parameter changed during transformation"
            );
            let mut rewritten = String::with_capacity(uri.len() - range.len() + token.len());
            rewritten.push_str(&uri[..range.start]);
            rewritten.push_str(&token);
            rewritten.push_str(&uri[range.end..]);
            request["uri"] = Value::String(rewritten);
            Ok(())
        }
    }
}

fn header_token(request: &Value, name: &str) -> Result<Option<String>> {
    let Some(headers) = request["headers"].as_object() else {
        return Ok(None);
    };
    let values = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(name))
        .collect::<Vec<_>>();
    if values.is_empty() {
        return Ok(None);
    }
    ensure!(values.len() == 1, "ambiguous JWT request header");
    let values = values[0]
        .1
        .as_array()
        .context("JWT request header must be an array")?;
    ensure!(values.len() == 1, "ambiguous JWT request header values");
    let value = values[0]
        .as_str()
        .context("JWT request header must be text")?;
    let Some((scheme, token)) = value.split_once(' ') else {
        return Ok(None);
    };
    Ok(scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| token.trim().to_string()))
}

fn query_token_range(uri: &str, wanted: &str) -> Result<Option<(std::ops::Range<usize>, String)>> {
    let Some(question) = uri.find('?') else {
        return Ok(None);
    };
    let query_start = question + 1;
    let query_end = uri[query_start..]
        .find('#')
        .map(|offset| query_start + offset)
        .unwrap_or(uri.len());
    let query = &uri[query_start..query_end];
    let mut selected = None;
    let mut offset = query_start;
    for component in query.split('&') {
        let (raw_name, raw_value) = component.split_once('=').unwrap_or((component, ""));
        let decoded_name = url::form_urlencoded::parse(component.as_bytes())
            .next()
            .map(|(name, _)| name.into_owned())
            .unwrap_or_default();
        if decoded_name == wanted {
            ensure!(selected.is_none(), "ambiguous JWT query parameter values");
            let value_start = offset + raw_name.len() + usize::from(component.contains('='));
            let value_end = value_start + raw_value.len();
            let decoded_value = url::form_urlencoded::parse(component.as_bytes())
                .next()
                .map(|(_, value)| value.into_owned())
                .unwrap_or_default();
            selected = Some((value_start..value_end, decoded_value));
        }
        offset += component.len() + 1;
    }
    Ok(selected)
}
