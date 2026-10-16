//! Exact derivation checks for fields accompanying a signed response token.
use super::*;
use crate::replay::policy::ResponseTimestampFormat;

pub(super) fn compare(
    rule: &ResponseJwtRule,
    pointer: &str,
    documents: [&Value; 2],
    validated: &contract::Validated,
) -> Result<(), ResponseDifferenceKind> {
    let invalid = ResponseDifferenceKind::JwtExpiryMismatch;
    for (index, document) in documents.into_iter().enumerate() {
        let read =
            |pattern: &str| document.pointer(&ResponseJwtRule::concrete_pointer(pattern, pointer));
        let exp = if let Some(pattern) = &rule.expires_at {
            let expiry = read(pattern)
                .and_then(|value| match rule.expires_at_format {
                    ResponseTimestampFormat::UnixSeconds => value.as_i64(),
                    ResponseTimestampFormat::Rfc3339 => value
                        .as_str()
                        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                        .map(|v| v.timestamp()),
                    _ => None,
                })
                .ok_or(invalid)?;
            if expiry != validated.exp[index] {
                return Err(invalid);
            }
            Some(expiry)
        } else {
            None
        };
        let iat = if let Some(pattern) = &rule.issued_at {
            let issued = read(pattern).and_then(Value::as_i64).ok_or(invalid)?;
            if Some(issued) != validated.iat[index] {
                return Err(invalid);
            }
            Some(issued)
        } else {
            None
        };
        if let Some(pattern) = &rule.ttl {
            let ttl = read(pattern)
                .and_then(Value::as_i64)
                .filter(|ttl| *ttl > 0)
                .ok_or(invalid)?;
            if iat.and_then(|iat| iat.checked_add(ttl)) != exp {
                return Err(invalid);
            }
        }
    }
    Ok(())
}
