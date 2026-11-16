//! Declared JSON references in a first Redis capture, without broad string substitution.
use crate::RedisValueKeySelector;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

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
