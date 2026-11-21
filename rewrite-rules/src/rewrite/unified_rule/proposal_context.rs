//! Partial proposals resolve trusted names without inheriting existing permissions.
use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};
use serde::{Serialize, de::DeserializeOwned};
use serde_yaml::{Mapping, Value};

use crate::policy::{NativeEffect, TrafficPolicy, native::BodyCodec};

pub struct Resolved {
    pub input: String,
    pub explicit_resources: bool,
}

pub fn resolve(input: &str, current: &TrafficPolicy) -> Result<Resolved> {
    let mut raw: Value = serde_yaml::from_str(input)?;
    let policy = if raw.get("format").and_then(Value::as_str) == Some("traffic-policy-change/v1") {
        raw.get_mut("policy")
            .context("policy change is missing runtime declarations")?
    } else {
        &mut raw
    };
    if policy.get("format").and_then(Value::as_str) != Some(crate::policy::POLICY_FORMAT) {
        return Ok(Resolved {
            input: input.into(),
            explicit_resources: false,
        });
    }
    let policy = policy
        .as_mapping_mut()
        .context("policy proposal requires a mapping")?;
    let explicit_resources = policy
        .get("resources")
        .and_then(Value::as_mapping)
        .is_some_and(|resources| !resources.is_empty());
    definitions(policy, "signatures", &current.signatures)?;
    definitions(policy, "resources", &current.resources)?;
    if !policy.contains_key("source_revision")
        && let Some(revision) = &current.source_revision
    {
        policy.insert("source_revision".into(), revision.clone().into());
    }
    if !policy.contains_key("docx") && uses_docx(policy) {
        let mut definition = None;
        for rule in current.rules.iter().filter_map(|rule| rule.as_native()) {
            let NativeEffect::ResponseBody(body) = &rule.effect else {
                continue;
            };
            if body.codec != BodyCodec::Docx {
                continue;
            }
            let fields = body
                .fields
                .iter()
                .map(|field| serde_yaml::to_value(&field.contract))
                .collect::<Result<Vec<_>, _>>()?;
            ensure!(
                definition
                    .as_ref()
                    .is_none_or(|previous| previous == &fields),
                "existing DOCX field declarations disagree; provide the intended docx.fields explicitly"
            );
            definition = Some(fields);
        }
        if let Some(fields) = definition {
            let mut docx = Mapping::new();
            docx.insert("fields".into(), Value::Sequence(fields));
            policy.insert("docx".into(), docx.into());
        }
    }
    Ok(Resolved {
        input: serde_yaml::to_string(&raw)?,
        explicit_resources,
    })
}

fn uses_docx(policy: &Mapping) -> bool {
    policy
        .get("api")
        .and_then(Value::as_mapping)
        .is_some_and(|apis| {
            apis.values().any(|api| {
                api.get("response")
                    .and_then(|response| response.get("body"))
                    .and_then(|body| body.get("codec"))
                    .and_then(Value::as_str)
                    == Some("docx")
            })
        })
}

fn definitions<T: Serialize + DeserializeOwned + PartialEq>(
    policy: &mut Mapping,
    name: &str,
    current: &BTreeMap<String, T>,
) -> Result<()> {
    if current.is_empty() {
        return Ok(());
    }
    let declared = policy
        .entry(name.into())
        .or_insert_with(|| Value::Mapping(Mapping::new()))
        .as_mapping_mut()
        .with_context(|| format!("{name} requires a mapping"))?;
    for (key, definition) in current {
        if let Some(value) = declared.get(key.as_str()) {
            let value: T = serde_yaml::from_value(value.clone())?;
            ensure!(
                value == *definition,
                "existing {name} definition {key:?} conflicts with the active policy"
            );
        } else {
            declared.insert(key.clone().into(), serde_yaml::to_value(definition)?);
        }
    }
    Ok(())
}

#[cfg(test)]
pub mod tests;
