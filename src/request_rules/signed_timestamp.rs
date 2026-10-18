//! Source-verified translation of a bounded signed JSON timestamp. This module
//! never reads response or dependency values and never repairs invalid signatures.
use std::collections::BTreeSet;

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use md5::{Digest, Md5};
use serde_json::Value;
use subtle::ConstantTimeEq as _;

use super::{RequestRuleObservation, jwt, keys::SigningKeySource};
use crate::policy::native::{InputSignedTimestampEffect, StartupKey};

pub(crate) fn validate(effect: &InputSignedTimestampEffect) -> Result<()> {
    ensure!(
        (1..=8).contains(&effect.fields.len()),
        "signed timestamp requires 1..8 fields"
    );
    let mut pointers = BTreeSet::new();
    for (name, pointer) in &effect.fields {
        parameter(name)?;
        crate::policy::validate_pointer(pointer, false)?;
        ensure!(
            !pointer.is_empty() && pointers.insert(pointer),
            "signed fields require distinct non-root JSON pointers"
        );
    }
    ensure!(
        pointers.contains(&effect.timestamp_pointer),
        "signed fields must include the timestamp pointer"
    );
    parameter(&effect.secret_parameter)?;
    ensure!(
        !effect.fields.contains_key(&effect.secret_parameter),
        "secret parameter duplicates a signed field"
    );
    crate::policy::validate_pointer(&effect.signature_pointer, false)?;
    ensure!(
        !effect.signature_pointer.is_empty(),
        "signature pointer must not select the root"
    );
    let mut all = pointers.into_iter().collect::<Vec<_>>();
    all.push(&effect.signature_pointer);
    for (index, pointer) in all.iter().enumerate() {
        for other in &all[index + 1..] {
            ensure!(
                *pointer != *other
                    && !pointer.starts_with(&format!("{other}/"))
                    && !other.starts_with(&format!("{pointer}/")),
                "signed timestamp fields overlap"
            );
        }
    }
    Ok(())
}

fn parameter(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 64
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'),
        "signature parameter must be 1..64 ASCII letters, digits or underscores"
    );
    Ok(())
}

pub(crate) fn key_source(effect: &InputSignedTimestampEffect) -> SigningKeySource {
    match &effect.signing_key {
        StartupKey::TargetEnv { name } => SigningKeySource::TargetEnv { name: name.clone() },
        StartupKey::TargetFile { path, field } => SigningKeySource::TargetFile {
            path: path.into(),
            field: field.clone(),
        },
    }
}

pub(crate) fn body(request: &Value) -> Result<Option<Value>> {
    let envelope = &request["body"];
    ensure!(
        envelope["truncated"] == false,
        "signed input requires a complete body"
    );
    let data = envelope["data"]
        .as_str()
        .context("signed input body data is absent")?;
    ensure!(
        data.len() <= 2 * 1024 * 1024,
        "signed input body exceeds its bound"
    );
    let bytes = match envelope["encoding"].as_str() {
        Some("utf8") => data.as_bytes().to_vec(),
        Some("base64") => STANDARD
            .decode(data)
            .context("invalid signed input body encoding")?,
        _ => anyhow::bail!("unsupported signed input body encoding"),
    };
    Ok(crate::json_value::parse(&bytes))
}

fn signature(body: &Value, effect: &InputSignedTimestampEffect, key: &[u8]) -> Option<String> {
    let mut hash = Md5::new();
    for (name, pointer) in &effect.fields {
        hash.update(name.as_bytes());
        hash.update(b"=");
        hash.update(body.pointer(pointer)?.as_str()?.trim().as_bytes());
        hash.update(b"&");
    }
    hash.update(effect.secret_parameter.as_bytes());
    hash.update(b"=");
    hash.update(key);
    Some(format!("{:x}", hash.finalize()))
}

pub(crate) fn verifies(body: &Value, effect: &InputSignedTimestampEffect, key: &[u8]) -> bool {
    let Some(actual) = body
        .pointer(&effect.signature_pointer)
        .and_then(Value::as_str)
    else {
        return false;
    };
    let Some(expected) = signature(body, effect, key) else {
        return false;
    };
    actual.len() == 32
        && bool::from(
            actual
                .to_ascii_lowercase()
                .as_bytes()
                .ct_eq(expected.as_bytes()),
        )
}

pub(crate) fn apply(
    request: &mut Value,
    effect: &InputSignedTimestampEffect,
    key: &[u8],
    now: DateTime<Utc>,
) -> Result<Option<RequestRuleObservation>> {
    let Some(mut body) = body(request)? else {
        return Ok(None);
    };
    let Some(timestamp) = body
        .pointer(&effect.timestamp_pointer)
        .and_then(Value::as_str)
        .and_then(|value| value.trim().parse::<i64>().ok())
    else {
        return Ok(None);
    };
    if !verifies(&body, effect, key) {
        return Ok(Some(RequestRuleObservation {
            rule_id: String::new(),
            outcome: "original_signature_invalid_unchanged".into(),
            offset_seconds: None,
        }));
    }
    let recorded = jwt::request_timestamp(request)?;
    let offset = now
        .timestamp()
        .checked_sub(recorded.timestamp())
        .context("signed input time offset overflow")?;
    let shifted = timestamp
        .checked_add(offset)
        .context("signed input timestamp overflow")?;
    if offset != 0 {
        *body
            .pointer_mut(&effect.timestamp_pointer)
            .context("signed timestamp disappeared")? = shifted.to_string().into();
        let signature = signature(&body, effect, key).context("signed fields disappeared")?;
        *body
            .pointer_mut(&effect.signature_pointer)
            .context("signed input signature disappeared")? = signature.into();
        let bytes = serde_json::to_vec(&body)?;
        request["body"]["data"] = match request["body"]["encoding"].as_str() {
            Some("base64") => STANDARD.encode(bytes),
            _ => String::from_utf8(bytes)?,
        }
        .into();
    }
    Ok(Some(RequestRuleObservation {
        rule_id: String::new(),
        outcome: "time_shifted_signature_verified".into(),
        offset_seconds: Some(offset),
    }))
}

#[cfg(test)]
mod tests;
