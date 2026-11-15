//! Exact derivation checks for fields accompanying a signed response token.
use super::*;
use crate::policy::runtime::ResponseTimestampFormat;

pub(super) fn compare(
    rule: &ResponseJwtRule,
    pointer: &str,
    documents: [&Value; 2],
    validated: &contract::Validated,
) -> Result<(), ResponseDifferenceKind> {
    compare_pair(rule, [pointer, pointer], documents, validated)
}

pub(crate) fn compare_pair(
    rule: &ResponseJwtRule,
    pointers: [&str; 2],
    documents: [&Value; 2],
    validated: &contract::Validated,
) -> Result<(), ResponseDifferenceKind> {
    let invalid = ResponseDifferenceKind::JwtExpiryMismatch;
    if let Some(pattern) = &rule.expires_at {
        let read = |index: usize| {
            documents[index]
                .pointer(&ResponseJwtRule::concrete_pointer(pattern, pointers[index]))
                .ok_or(invalid)
        };
        let format = match rule.expires_at_format {
            ResponseTimestampFormat::UnixSeconds => {
                crate::value_contract::time::TimestampFormat::UnixSeconds
            }
            ResponseTimestampFormat::Rfc3339 => {
                crate::value_contract::time::TimestampFormat::Rfc3339
            }
            _ => return Err(invalid),
        };
        crate::value_contract::time::validate_representation(read(0)?, read(1)?, format)
            .map_err(|_| invalid)?;
    }
    for (index, document) in documents.into_iter().enumerate() {
        let read = |pattern: &str| {
            document.pointer(&ResponseJwtRule::concrete_pointer(pattern, pointers[index]))
        };
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
