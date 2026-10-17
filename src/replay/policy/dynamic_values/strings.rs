//! Bounded string/JSON adaptation without matching opaque binary payloads.
use super::IdentityPair;
use anyhow::{Result, ensure};
use serde_json::Value;

pub(in crate::replay) fn capture(bytes: &[u8], pointer: Option<&str>) -> Result<String> {
    match pointer {
        None => {
            ensure!(!std::str::from_utf8(bytes)?.trim_start().starts_with(['{','[']),"structured JSON captures require an explicit JSON pointer");
            Ok(std::str::from_utf8(bytes)?.into())
        }
        Some(pointer) => crate::replay::json_order::parse(bytes).and_then(|value|value.pointer(pointer).and_then(Value::as_str).map(str::to_owned)).ok_or_else(||anyhow::anyhow!("dynamic JSON capture requires complete JSON with unique members and a string at the selected pointer")),
    }
}

pub(super) fn contains_identity(bytes: &[u8], pairs: &[IdentityPair]) -> bool {
    if bytes.len() > 1024 * 1024 || pairs.is_empty() {
        return false;
    }
    if std::str::from_utf8(bytes)
        .is_ok_and(|value| pairs.iter().any(|pair| value.contains(&pair.source)))
    {
        return true;
    }
    crate::replay::json_order::parse(bytes)
        .is_some_and(|mut value| normalize_json(&mut value, pairs, false, 0).unwrap_or(false))
}

pub(super) fn normalize(bytes: &[u8], pairs: &[IdentityPair], actual: bool) -> Result<Vec<u8>> {
    if pairs.is_empty() || bytes.len() > 1024 * 1024 {
        return Ok(bytes.to_vec());
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Ok(bytes.to_vec());
    };
    if pairs
        .iter()
        .any(|pair| text == if actual { &pair.target } else { &pair.source })
    {
        return if actual {
            Ok(translate(text, pairs)?.into_bytes())
        } else {
            Ok(bytes.to_vec())
        };
    }
    if let Some(mut json) = crate::replay::json_order::parse(bytes)
        && matches!(json, Value::Object(_) | Value::Array(_))
    {
        let changed = normalize_json(&mut json, pairs, actual, 0)?;
        if changed {
            return Ok(serde_json::to_vec(&json)?);
        }
        return Ok(bytes.to_vec());
    }
    ensure!(
        !text.trim_start().starts_with(['{', '['])
            || !pairs
                .iter()
                .any(|pair| text.contains(&pair.source) || text.contains(&pair.target)),
        "dynamic JSON must be complete and have unique object members"
    );
    if actual {
        Ok(translate(text, pairs)?.into_bytes())
    } else {
        Ok(bytes.to_vec())
    }
}

fn normalize_json(
    value: &mut Value,
    pairs: &[IdentityPair],
    actual: bool,
    depth: usize,
) -> Result<bool> {
    ensure!(depth <= 64, "dynamic JSON nesting exceeds 64");
    let mut found = false;
    match value {
        Value::String(text) => {
            found = pairs
                .iter()
                .any(|pair| text.contains(if actual { &pair.target } else { &pair.source }));
            if actual {
                *text = translate(text, pairs)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                found |= normalize_json(value, pairs, actual, depth + 1)?;
            }
        }
        Value::Object(values) => {
            let mut normalized = serde_json::Map::new();
            for (key, mut value) in std::mem::take(values) {
                found |= pairs
                    .iter()
                    .any(|pair| key.contains(if actual { &pair.target } else { &pair.source }));
                let key = if actual { translate(&key, pairs)? } else { key };
                found |= normalize_json(&mut value, pairs, actual, depth + 1)?;
                ensure!(
                    normalized.insert(key, value).is_none(),
                    "dynamic JSON object keys collapsed"
                );
            }
            *values = normalized;
        }
        _ => {}
    }
    Ok(found)
}

fn translate(text: &str, pairs: &[IdentityPair]) -> Result<String> {
    if !pairs
        .iter()
        .any(|pair| text.contains(&pair.target) || text.contains(&pair.source))
    {
        return Ok(text.to_owned());
    }
    let mut out = String::new();
    let mut offset = 0;
    while offset < text.len() {
        let tail = &text[offset..];
        let matches = pairs
            .iter()
            .filter(|pair| tail.starts_with(&pair.target))
            .collect::<Vec<_>>();
        let longest = matches.iter().map(|pair| pair.target.len()).max();
        if let Some(length) = longest {
            let selected = matches
                .into_iter()
                .filter(|pair| pair.target.len() == length)
                .collect::<Vec<_>>();
            ensure!(
                selected
                    .iter()
                    .all(|pair| pair.source == selected[0].source),
                "ambiguous dynamic identity mapping"
            );
            out.push_str(&selected[0].source);
            offset += length;
        } else {
            ensure!(
                !pairs
                    .iter()
                    .any(|pair| pair.source != pair.target && tail.starts_with(&pair.source)),
                "target used a recorded identity instead of its bound identity"
            );
            let character = tail.chars().next().expect("nonempty UTF-8 tail");
            out.push(character);
            offset += character.len_utf8();
        }
    }
    Ok(out)
}
