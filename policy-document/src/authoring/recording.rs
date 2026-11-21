//! Recording authoring groups async lifecycles and optional HTTP acquisition.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Deserializer, Serialize};
use serde_yaml::{Mapping, Value};

use crate::native::CaptureHttpEffect;
use crate::{NativeEffect, NativeMatch, NativeRule, PolicyRule, Proof};

pub const DEFAULT_NAME: &str = "source-capture-http";

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Declaration {
    #[serde(
        default,
        deserialize_with = "optional_async_api",
        skip_serializing_if = "Option::is_none"
    )]
    pub async_api: Option<std::collections::BTreeMap<String, crate::AsyncApiRules>>,
    #[serde(
        default,
        deserialize_with = "optional_case_paths",
        skip_serializing_if = "Option::is_none"
    )]
    pub case_paths: Option<Vec<String>>,
    #[serde(default = "default_name", skip_serializing_if = "is_default_name")]
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
}

pub fn optional_async_api<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<std::collections::BTreeMap<String, crate::AsyncApiRules>>, D::Error> {
    crate::strict_map::unique_map(deserializer).map(Some)
}

pub fn optional_case_paths<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<String>>, D::Error> {
    Vec::deserialize(deserializer).map(Some)
}

pub fn default_name() -> String {
    DEFAULT_NAME.into()
}

pub fn is_default_name(name: &str) -> bool {
    name == DEFAULT_NAME
}

pub fn lower(
    declaration: &Declaration,
    revision: Option<&str>,
    context: &crate::AuthoringContext<'_>,
) -> Result<NativeRule> {
    let revision = revision.context("recording requires root source_revision")?;
    super::proof::revision(revision)?;
    let mut value = serde_yaml::to_value(NativeRule {
        id: declaration.name.clone(),
        selector: NativeMatch::default(),
        effect: NativeEffect::CaptureHttp(CaptureHttpEffect {
            source_revision: revision.into(),
            case_paths: declaration
                .case_paths
                .clone()
                .context("recording HTTP acquisition requires case_paths")?,
        }),
        proof: declaration.proof.clone(),
        when: None,
    })?;
    super::walk::expand_rule(&mut value, Some(revision))?;
    let rule = serde_yaml::from_value(value)?;
    context.compile_native(&rule)?;
    Ok(rule)
}

pub fn expand(
    declaration: Option<Declaration>,
    revision: Option<&str>,
    context: &crate::AuthoringContext<'_>,
) -> Result<Vec<Value>> {
    let Some(declaration) = declaration else {
        return Ok(vec![]);
    };
    if declaration.case_paths.is_none() {
        ensure!(
            declaration.async_api.is_some(),
            "recording requires async_api or case_paths"
        );
        ensure!(
            is_default_name(&declaration.name) && declaration.proof.is_none(),
            "recording name and proof describe HTTP acquisition and require case_paths"
        );
        return Ok(vec![]);
    }
    Ok(vec![serde_yaml::to_value(lower(
        &declaration,
        revision,
        context,
    )?)?])
}

pub fn selected(
    rules: &[PolicyRule],
    revision: Option<&str>,
    context: &crate::AuthoringContext<'_>,
) -> Result<Option<String>> {
    let mut names = Vec::new();
    for rule in rules {
        if compact(rule, revision, &mut Mapping::new(), context)? {
            names.push(rule.id().to_owned());
        }
    }
    names.sort_by_key(|name| (name.as_str() != DEFAULT_NAME, name.clone()));
    Ok(names.into_iter().next())
}

pub fn compact(
    rule: &PolicyRule,
    revision: Option<&str>,
    root: &mut Mapping,
    context: &crate::AuthoringContext<'_>,
) -> Result<bool> {
    let Some(native) = rule.as_native() else {
        return Ok(false);
    };
    let NativeEffect::CaptureHttp(effect) = &native.effect else {
        return Ok(false);
    };
    if revision != Some(effect.source_revision.as_str())
        || root
            .get("recording")
            .and_then(Value::as_mapping)
            .is_some_and(|recording| recording.contains_key("case_paths"))
    {
        return Ok(false);
    }
    let declaration = Declaration {
        async_api: None,
        case_paths: Some(effect.case_paths.clone()),
        name: native.id.clone(),
        proof: None,
    };
    let Ok(canonical) = lower(&declaration, revision, context) else {
        return Ok(false);
    };
    let mut runtime = native.clone();
    runtime.proof = None;
    if runtime != canonical {
        return Ok(false);
    }
    let value = serde_yaml::to_value(declaration)?;
    root.entry(Value::String("recording".into()))
        .or_insert_with(|| Value::Mapping(Mapping::new()))
        .as_mapping_mut()
        .context("recording authoring must be a mapping")?
        .extend(
            value
                .as_mapping()
                .expect("typed recording declaration")
                .clone(),
        );
    Ok(true)
}
