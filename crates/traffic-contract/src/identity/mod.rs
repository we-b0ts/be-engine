//! Typed identity formats and shared candidate-local correspondence state.
use crate::{comparison::Difference, rule::IdentityFormat};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
mod store;
pub use store::*;

fn difference(pointer: &str, reason: &str) -> Difference {
    Difference {
        pointer: pointer.into(),
        reason: reason.into(),
    }
}

pub fn token(
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
                && is_jwt(&Value::String(token.clone()))
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
pub fn key(value: &Value, pointer: &str) -> Result<String, Difference> {
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
    let Some(header) = decode(parts[0]).and_then(|bytes| crate::json::parse(&bytes)) else {
        return false;
    };
    let Some(claims) = decode(parts[1]).and_then(|bytes| crate::json::parse(&bytes)) else {
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
