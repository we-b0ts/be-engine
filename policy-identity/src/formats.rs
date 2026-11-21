//! Identity representation validation owned by the installed identity policy.
use serde_json::Value;
use traffic_contract::{comparison::Difference, rule::IdentityFormat};
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
                && traffic_jwt::is_jwt(&Value::String(token.clone()))
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
