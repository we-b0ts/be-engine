//! URL query values are one JSON view; static URL bytes stay Source-owned.
use anyhow::{Context, Result, ensure};
use serde_json::{Map, Value};

use crate::policy::{CompiledJsonPolicy, GlobalField, GlobalUrlFormat};
use crate::value_contract::json::{LeafContext, LeafObservations};

pub(crate) struct Document {
    prefix: String,
    fragment: Option<String>,
    query: bool,
    parts: Vec<Part>,
    pub(crate) logical: Value,
}

struct Part {
    raw: String,
    raw_name: String,
    name: String,
    equals: bool,
}

fn decode(raw: &str) -> Result<String> {
    let bytes = raw.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => decoded.push(b' '),
            b'%' => {
                let digits = bytes
                    .get(index + 1..index + 3)
                    .context("incomplete URL escape")?;
                let hex = std::str::from_utf8(digits)?;
                decoded.push(u8::from_str_radix(hex, 16).context("invalid URL escape")?);
                index += 2;
            }
            byte => decoded.push(byte),
        }
        index += 1;
    }
    String::from_utf8(decoded).context("URL query is not UTF-8")
}

impl Document {
    pub(crate) fn parse(value: &Value) -> Result<Self> {
        let value = value.as_str().context("URL requires a string")?;
        ensure!(
            value.len() <= 16_384
                && !value
                    .chars()
                    .any(|character| character.is_control() || character == ' '),
            "URL exceeds bounds"
        );
        let parsed = ::url::Url::parse(value).context("URL requires an absolute URL")?;
        ensure!(
            matches!(parsed.scheme(), "http" | "https") && parsed.host_str().is_some(),
            "URL requires HTTP(S) and a host"
        );
        let (body, fragment) = value
            .split_once('#')
            .map_or((value, None), |(body, fragment)| {
                (body, Some(fragment.to_owned()))
            });
        let (prefix, query) = body
            .split_once('?')
            .map_or((body, None), |(prefix, query)| (prefix, Some(query)));
        let mut parts = Vec::new();
        let mut logical = Map::new();
        for raw in query
            .filter(|query| !query.is_empty())
            .into_iter()
            .flat_map(|query| query.split('&'))
        {
            ensure!(
                parts.len() < 64 && !raw.is_empty(),
                "URL query exceeds bounds or has an empty member"
            );
            let (raw_name, raw_value, equals) = raw
                .split_once('=')
                .map_or((raw, "", false), |(name, value)| (name, value, true));
            let name = decode(raw_name)?;
            let value = Value::String(decode(raw_value)?);
            ensure!(
                logical.insert(name.clone(), value).is_none(),
                "URL query has a duplicate decoded name"
            );
            parts.push(Part {
                raw: raw.into(),
                raw_name: raw_name.into(),
                name,
                equals,
            });
        }
        Ok(Self {
            prefix: prefix.into(),
            fragment,
            query: query.is_some(),
            parts,
            logical: Value::Object(logical),
        })
    }

    pub(crate) fn rebuild(&self, logical: &Value) -> Result<String> {
        let values = logical
            .as_object()
            .context("URL query must remain an object")?;
        ensure!(values.len() == self.parts.len(), "URL query names changed");
        let mut parts = Vec::with_capacity(self.parts.len());
        for part in &self.parts {
            let value = values
                .get(&part.name)
                .context("URL query name disappeared")?;
            if self.logical.get(&part.name) == Some(value) {
                parts.push(part.raw.clone());
            } else {
                let value = value.as_str().context("URL query value must remain text")?;
                ensure!(part.equals, "URL query value had no equals separator");
                let encoded =
                    ::url::form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>();
                parts.push(format!("{}={encoded}", part.raw_name));
            }
        }
        let query = if self.query {
            format!("?{}", parts.join("&"))
        } else {
            String::new()
        };
        Ok(format!(
            "{}{query}{}",
            self.prefix,
            self.fragment
                .as_ref()
                .map_or(String::new(), |fragment| format!("#{fragment}"))
        ))
    }

    fn same_structure(&self, target: &Self) -> bool {
        self.prefix == target.prefix
            && self.fragment == target.fragment
            && self.query == target.query
            && self.parts.len() == target.parts.len()
            && self
                .parts
                .iter()
                .zip(&target.parts)
                .all(|(source, target)| {
                    source.raw_name == target.raw_name
                        && source.name == target.name
                        && source.equals == target.equals
                })
    }
}

pub(crate) fn query_plan(plan: &CompiledJsonPolicy) -> CompiledJsonPolicy {
    CompiledJsonPolicy {
        time: plan.time.clone(),
        fields: plan
            .fields
            .iter()
            .filter(|(_, field)| !matches!(field, GlobalField::Url { .. }))
            .map(|(pointer, field)| (pointer.clone(), field.clone()))
            .collect(),
        fingerprint: plan.fingerprint.clone(),
        signatures: plan.signatures.clone(),
    }
}

pub(crate) fn selected(plan: &CompiledJsonPolicy, source: &Value) -> Result<Vec<String>> {
    let mut selected = Vec::new();
    for (pattern, field) in &plan.fields {
        if matches!(field,GlobalField::Url {formats} if formats == &[GlobalUrlFormat::Url]) {
            selected.extend(crate::value_contract::delivery::select(pattern, source)?);
        }
    }
    Ok(selected)
}

pub(super) fn compare(
    context: LeafContext<'_>,
    plan: &CompiledJsonPolicy,
) -> Result<LeafObservations, String> {
    let compare = || -> Result<LeafObservations> {
        let source = match Document::parse(context.source) {
            Ok(source) => source,
            Err(_) if context.source == context.target => return Ok(LeafObservations::default()),
            Err(error) => return Err(error),
        };
        let target = Document::parse(context.target)?;
        ensure!(
            source.same_structure(&target),
            "static URL structure differs"
        );
        let plan = query_plan(plan);
        let selected = plan.comparison_fields(&source.logical, &target.logical, context.clocks)?;
        let protocols = super::checks(&plan, &source.logical)?;
        let protocol_fields = protocols.fields();
        for (before, after) in source.parts.iter().zip(&target.parts) {
            let pointer = format!("/{}", before.name.replace('~', "~0").replace('/', "~1"));
            if !selected.iter().any(|(selected, _)| selected == &pointer)
                && !protocol_fields
                    .iter()
                    .any(|selected| selected.pointer == pointer)
            {
                ensure!(before.raw == after.raw, "unselected URL query bytes differ");
            }
        }
        let comparison = crate::value_contract::global::compare_logical_with_time_copies(
            &source.logical,
            &target.logical,
            &plan,
            &[],
            context.clocks,
            &[],
        )?;
        ensure!(
            comparison.passed(),
            "URL query content differs: {:?}",
            comparison.differences
        );
        Ok(LeafObservations {
            identities: comparison.identity_pairs(),
            time_validations: comparison.time_validations.values().sum(),
            ..Default::default()
        })
    };
    compare().map_err(|error| format!("URL query format rejected value: {error:#}"))
}

#[cfg(test)]
mod tests;
