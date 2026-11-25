//! Source-selected literal templates share complete typed identity observations.
use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Map, Value};

use super::FormatHost;
use crate::fields::{GlobalField, GlobalIdentityFormat, GlobalTemplateFormat, MatchedFormatField};
use traffic_contract::{
    compare::{LeafContext, LeafObservations},
    identity::IdentityPair,
    template::extract,
};
use traffic_policy::PolicyRegistry;

pub struct Document<'a> {
    format: &'a GlobalTemplateFormat,
    policies: &'a PolicyRegistry,
    pub logical: Value,
}

impl<'a> Document<'a> {
    pub fn select(
        value: &Value,
        formats: &'a [GlobalTemplateFormat],
        policies: &'a PolicyRegistry,
    ) -> Result<Option<Self>> {
        let Some(value) = value.as_str() else {
            return Ok(None);
        };
        let mut selected = None;
        let mut recognized = false;
        for format in formats {
            // A known fixed prefix cannot become an opaque value merely because
            // its remaining layout or token encoding is malformed.
            let prefix = format.template.split('{').next().unwrap_or_default();
            recognized |= value.starts_with(prefix);
            if let Ok(values) = extract(value, &format.template) {
                ensure!(
                    selected.is_none(),
                    "Source string matches multiple template layouts"
                );
                selected = Some((format, values));
            }
        }
        let Some((format, values)) = selected else {
            ensure!(!recognized, "Source string has malformed template layout");
            return Ok(None);
        };
        Ok(Some(Self {
            format,
            policies,
            logical: checked_values(format, values, policies)?,
        }))
    }

    pub fn fields(&self) -> &BTreeMap<String, GlobalIdentityFormat> {
        &self.format.fields
    }

    pub fn rebuild(&self, logical: &Value) -> Result<String> {
        let values = logical
            .as_object()
            .context("template tokens require an object")?;
        ensure!(
            values.len() == self.format.fields.len(),
            "template token set changed"
        );
        let mut rebuilt = self.format.template.clone();
        for name in self.format.fields.keys() {
            let value = values
                .get(name)
                .and_then(Value::as_str)
                .context("template identity must remain a string")?;
            rebuilt = rebuilt.replace(&format!("{{{name}}}"), value);
        }
        let checked = checked_values(
            self.format,
            extract(&rebuilt, &self.format.template)
                .map_err(|_| anyhow::anyhow!("derived template layout changed"))?,
            self.policies,
        )?;
        ensure!(
            checked == *logical,
            "derived template token representation changed"
        );
        Ok(rebuilt)
    }
}

fn checked_values(
    format: &GlobalTemplateFormat,
    values: BTreeMap<String, &str>,
    policies: &PolicyRegistry,
) -> Result<Value> {
    let mut logical = Map::new();
    for (name, field) in &format.fields {
        let text = values.get(name).context("template token disappeared")?;
        let value = Value::String((*text).into());
        let token = crate::identity::token(&value, &field.prefix, field.format, "", policies)
            .map_err(|_| anyhow::anyhow!("template identity format is invalid"))?;
        if matches!(
            field.format,
            traffic_contract::rule::IdentityFormat::Base64Url(_)
        ) {
            ensure!(
                URL_SAFE_NO_PAD
                    .decode(&token)
                    .is_ok_and(|bytes| URL_SAFE_NO_PAD.encode(bytes) == token),
                "template base64url token is not canonical"
            );
        }
        logical.insert(name.clone(), value);
    }
    Ok(Value::Object(logical))
}

pub fn selected<'a>(
    plan: &'a dyn FormatHost,
    source: &Value,
) -> Result<Vec<(String, Document<'a>)>> {
    let mut selected = Vec::new();
    for (pattern, field) in plan.fields() {
        let GlobalField::Template { formats } = field else {
            continue;
        };
        for pointer in plan.select_paths(pattern, source)? {
            let value = source
                .pointer(&pointer)
                .context("template field disappeared")?;
            if let Some(document) = Document::select(value, formats, plan.policies())? {
                selected.push((pointer, document));
            }
        }
    }
    Ok(selected)
}

pub fn selected_at_matches<'a>(
    plan: &'a dyn FormatHost,
    source: &Value,
    matched: &[MatchedFormatField],
) -> Result<Vec<(String, Document<'a>)>> {
    let mut selected = Vec::new();
    for field in matched {
        let GlobalField::Template { formats } = &plan.fields()[&field.pattern] else {
            continue;
        };
        let value = source
            .pointer(&field.pointer)
            .context("template field disappeared")?;
        if let Some(document) = Document::select(value, formats, plan.policies())? {
            selected.push((field.pointer.clone(), document));
        }
    }
    Ok(selected)
}

pub fn compare(
    context: LeafContext<'_>,
    formats: &[GlobalTemplateFormat],
    policies: &PolicyRegistry,
) -> Result<LeafObservations, String> {
    let compare = || -> Result<LeafObservations> {
        let Some(source) = Document::select(context.source, formats, policies)? else {
            ensure!(
                context.source == context.target,
                "unselected template value differs"
            );
            return Ok(LeafObservations::default());
        };
        let target = context
            .target
            .as_str()
            .context("Target template must remain a string")?;
        let values = extract(target, &source.format.template)
            .map_err(|_| anyhow::anyhow!("Target template literals or layout changed"))?;
        let target = checked_values(source.format, values, policies)?;
        let identities = source
            .format
            .fields
            .keys()
            .map(|name| {
                Ok(IdentityPair {
                    source: serde_json::to_string(&source.logical[name])?,
                    target: serde_json::to_string(&target[name])?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(LeafObservations {
            identities,
            ..Default::default()
        })
    };
    compare().map_err(|error| format!("string template rejected value: {error:#}"))
}
