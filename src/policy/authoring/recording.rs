//! Recording scope declarations reuse the native Source acquisition owner.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_yaml::{Mapping, Value};

use crate::policy::native::CaptureHttpEffect;
use crate::policy::{NativeEffect, NativeMatch, NativeRule, PolicyRule, Proof};

const DEFAULT_NAME: &str = "source-capture-http";

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Declaration {
    pub case_paths: Vec<String>,
    #[serde(default = "default_name", skip_serializing_if = "is_default_name")]
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
}

fn default_name() -> String {
    DEFAULT_NAME.into()
}

fn is_default_name(name: &str) -> bool {
    name == DEFAULT_NAME
}

fn lower(declaration: &Declaration, revision: Option<&str>) -> Result<NativeRule> {
    let revision = revision.context("recording requires root source_revision")?;
    super::proof::revision(revision)?;
    let mut value = serde_yaml::to_value(NativeRule {
        id: declaration.name.clone(),
        selector: NativeMatch::default(),
        effect: NativeEffect::CaptureHttp(CaptureHttpEffect {
            source_revision: revision.into(),
            case_paths: declaration.case_paths.clone(),
        }),
        proof: declaration.proof.clone(),
        when: None,
    })?;
    super::walk::expand_rule(&mut value, Some(revision))?;
    let rule = serde_yaml::from_value(value)?;
    crate::policy::compile_native(&rule)?;
    Ok(rule)
}

pub(super) fn expand(
    declaration: Option<Declaration>,
    revision: Option<&str>,
) -> Result<Vec<Value>> {
    let Some(declaration) = declaration else {
        return Ok(vec![]);
    };
    Ok(vec![serde_yaml::to_value(lower(&declaration, revision)?)?])
}

pub(super) fn selected(rules: &[PolicyRule], revision: Option<&str>) -> Result<Option<String>> {
    let mut names = Vec::new();
    for rule in rules {
        if compact(rule, revision, &mut Mapping::new())? {
            names.push(rule.id().to_owned());
        }
    }
    names.sort_by_key(|name| (name.as_str() != DEFAULT_NAME, name.clone()));
    Ok(names.into_iter().next())
}

pub(super) fn compact(
    rule: &PolicyRule,
    revision: Option<&str>,
    root: &mut Mapping,
) -> Result<bool> {
    let Some(native) = rule.as_native() else {
        return Ok(false);
    };
    let NativeEffect::CaptureHttp(effect) = &native.effect else {
        return Ok(false);
    };
    if revision != Some(effect.source_revision.as_str()) || root.contains_key("recording") {
        return Ok(false);
    }
    let declaration = Declaration {
        case_paths: effect.case_paths.clone(),
        name: native.id.clone(),
        proof: None,
    };
    let Ok(canonical) = lower(&declaration, revision) else {
        return Ok(false);
    };
    let mut runtime = native.clone();
    runtime.proof = None;
    if runtime != canonical {
        return Ok(false);
    }
    root.insert("recording".into(), serde_yaml::to_value(declaration)?);
    Ok(true)
}

#[cfg(test)]
mod tests;
