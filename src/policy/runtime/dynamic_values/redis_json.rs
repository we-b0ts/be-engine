//! Declared JSON references in a first Redis capture, without broad string substitution.
use super::{DynamicValueCapture, IdentityPair};
use crate::RedisValueKeySelector;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedisCaptureReference {
    pub json_pointer: String,
    pub template: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedisDerivedIdentity {
    pub json_pointer: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub prefix: String,
}

pub(super) fn validate(
    pointer: Option<&str>,
    references: Option<&[RedisCaptureReference]>,
    derived: Option<&RedisDerivedIdentity>,
    key: &RedisValueKeySelector,
) -> Result<()> {
    let Some(references) = references else {
        ensure!(
            derived.is_none(),
            "derived Redis identity requires explicit JSON references"
        );
        return Ok(());
    };
    let pointer = pointer.context("explicit Redis JSON references require a capture pointer")?;
    ensure!(
        !pointer.is_empty(),
        "explicit Redis identity pointer must not be root"
    );
    ensure!(
        references.len() <= 16,
        "at most 16 Redis JSON references are supported"
    );
    let mut locations = vec![pointer];
    for reference in references {
        super::config::validate_pointer(&reference.json_pointer)?;
        ensure!(
            !reference.json_pointer.is_empty(),
            "Redis reference pointer must not be root"
        );
        ensure!(
            !locations
                .iter()
                .any(|p| crate::policy::runtime::response_locations_overlap(
                    p,
                    &reference.json_pointer
                )),
            "overlapping Redis identity/reference pointers"
        );
        locations.push(&reference.json_pointer);
        let template = &reference.template;
        let remainder = template.replace("{value}", "").replace("{key_middle}", "");
        ensure!(
            template.len() <= 1024
                && template.matches("{value}").count() == 1
                && template.matches("{key_middle}").count() <= 1
                && !remainder.contains(['{', '}']),
            "Redis reference template requires one {{value}} and at most one {{key_middle}}"
        );
        ensure!(
            !template.contains("{key_middle}")
                || matches!(key, RedisValueKeySelector::Numeric { .. }),
            "Redis key_middle reference requires inherited numeric key affixes"
        );
    }
    if let Some(derived) = derived {
        super::config::validate_pointer(&derived.json_pointer)?;
        ensure!(
            !derived.json_pointer.is_empty() && derived.prefix.len() <= 64,
            "derived Redis identity requires a non-root integer pointer and bounded prefix"
        );
        ensure!(
            !locations
                .iter()
                .any(|p| crate::policy::runtime::response_locations_overlap(
                    p,
                    &derived.json_pointer
                )),
            "derived Redis identity overlaps a capture/reference pointer"
        );
    }
    Ok(())
}

pub(super) fn project(
    capture: &DynamicValueCapture,
    key_bytes: &[u8],
    source: &[u8],
    actual: &[u8],
    pair: &IdentityPair,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let DynamicValueCapture::Redis {
        key,
        json_pointer: Some(pointer),
        references,
        derived_from,
        ..
    } = capture
    else {
        anyhow::bail!("explicit Redis JSON projection requires a declared capture");
    };
    let source = crate::json_value::parse(source)
        .context("source capture requires complete unique-member JSON")?;
    let mut actual = crate::json_value::parse(actual)
        .context("target capture requires complete unique-member JSON")?;
    if let Some(derived) = derived_from {
        for (json, value) in [(&source, &pair.source), (&actual, &pair.target)] {
            let integer = json
                .pointer(&derived.json_pointer)
                .context("derived Redis integer field is missing")?;
            ensure!(
                integer.is_i64() || integer.is_u64(),
                "derived Redis identity requires a JSON integer"
            );
            ensure!(
                *value == format!("{}{}", derived.prefix, integer),
                "Redis identity differs from its derived integer"
            );
        }
    }
    let middle = match key {
        RedisValueKeySelector::Numeric { prefix, suffix } if key.matches(key_bytes) => {
            std::str::from_utf8(&key_bytes[prefix.len()..key_bytes.len() - suffix.len()])?
        }
        _ => "",
    };
    for reference in references.iter().flatten() {
        let render = |value: &str| {
            reference
                .template
                .replace("{key_middle}", middle)
                .replace("{value}", value)
        };
        let left = source
            .pointer(&reference.json_pointer)
            .and_then(Value::as_str)
            .context("source Redis reference is not a string")?;
        let right = actual
            .pointer(&reference.json_pointer)
            .and_then(Value::as_str)
            .context("target Redis reference is not a string")?;
        ensure!(
            left == render(&pair.source) && right == render(&pair.target),
            "Redis reference does not match its own bound identity/key"
        );
        *actual.pointer_mut(&reference.json_pointer).unwrap() = Value::String(left.into());
    }
    *actual
        .pointer_mut(pointer)
        .context("target Redis identity pointer is missing")? = Value::String(pair.source.clone());
    Ok((serde_json::to_vec(&source)?, serde_json::to_vec(&actual)?))
}
