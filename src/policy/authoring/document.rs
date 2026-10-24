//! Authoring documents resolve to fully explicit typed rules before compilation.
use anyhow::{Result, ensure};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_yaml::{Mapping, Value};

use super::{field_refs, proof, resources, walk};
use crate::policy::{PolicyRule, TrafficPolicy};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    format: String,
    #[serde(default, deserialize_with = "declared_revision")]
    source_revision: Option<String>,
    #[serde(default, deserialize_with = "crate::policy::strict_map::unique_map")]
    resources: std::collections::BTreeMap<String, crate::policy::ResourceDeclaration>,
    #[serde(default, deserialize_with = "crate::policy::strict_map::unique_map")]
    responses: std::collections::BTreeMap<String, crate::policy::ResponseDeclaration>,
    #[serde(default)]
    rules: Vec<Value>,
}

fn declared_revision<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    String::deserialize(deserializer).map(Some)
}

impl<'de> Deserialize<'de> for TrafficPolicy {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let document = Document::deserialize(deserializer)?;
        let result = (|| -> anyhow::Result<Self> {
            if let Some(revision) = &document.source_revision {
                proof::revision(revision)?;
            }
            resources::validate(&document.resources)?;
            let mut rules = Vec::with_capacity(document.rules.len());
            let mut field_references = std::collections::BTreeMap::new();
            for mut rule in document.rules {
                let id = rule
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or("<missing-id>")
                    .to_owned();
                resources::expand(&mut rule, &document.resources)?;
                let references = field_refs::expand(&mut rule, &document.resources)?;
                if !references.is_empty() {
                    field_references.insert(id.clone(), references);
                }
                walk::expand_rule(&mut rule, document.source_revision.as_deref())
                    .map_err(|error| anyhow::anyhow!("rule {id:?}: {error:#}"))?;
                rules.push(serde_yaml::from_value(rule)?);
            }
            Ok(Self {
                format: document.format,
                source_revision: document.source_revision,
                resources: document.resources,
                responses: document.responses,
                field_references,
                rules,
            })
        })();
        result.map_err(serde::de::Error::custom)
    }
}

/// Typed callers can insert rules without a document context; normalize them
/// here too so compile, rendering and plan evidence bind the same Source.
pub(crate) fn expanded(document: &TrafficPolicy) -> Result<TrafficPolicy> {
    resources::validate(&document.resources)?;
    if let Some(revision) = &document.source_revision {
        proof::revision(revision)?;
    }
    let rules = document
        .rules
        .iter()
        .map(|rule| {
            let mut value = serde_yaml::to_value(rule)?;
            if let Some(references) = document.field_references.get(rule.id()) {
                field_refs::refresh(&mut value, references, &document.resources)?;
            }
            walk::expand_rule(&mut value, document.source_revision.as_deref())?;
            serde_yaml::from_value(value).map_err(Into::into)
        })
        .collect::<Result<Vec<PolicyRule>>>()?;
    Ok(TrafficPolicy {
        format: document.format.clone(),
        source_revision: document.source_revision.clone(),
        resources: document.resources.clone(),
        responses: document.responses.clone(),
        field_references: document.field_references.clone(),
        rules,
    })
}

impl Serialize for TrafficPolicy {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        compact_value(self)
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }
}

pub(super) fn compact_value(document: &TrafficPolicy) -> Result<Value> {
    let document = expanded(document)?;
    ensure!(
        document.format == crate::policy::POLICY_FORMAT,
        "policy format must be traffic-policy/v2"
    );
    let mut root = Mapping::new();
    root.insert("format".into(), document.format.into());
    if let Some(revision) = &document.source_revision {
        root.insert("source_revision".into(), revision.clone().into());
    }
    if !document.resources.is_empty() {
        root.insert(
            "resources".into(),
            serde_yaml::to_value(&document.resources)?,
        );
    }
    if !document.responses.is_empty() {
        root.insert(
            "responses".into(),
            serde_yaml::to_value(&document.responses)?,
        );
    }
    let mut rules = vec![];
    let resource_names = resources::names(&document.resources)?;
    let capture_first = document.rules.iter().filter(|rule| matches!(rule,
        PolicyRule::Native(rule) if matches!(rule.effect, crate::policy::NativeEffect::CaptureHttp(_))));
    let remaining = document.rules.iter().filter(|rule| !matches!(rule,
        PolicyRule::Native(rule) if matches!(rule.effect, crate::policy::NativeEffect::CaptureHttp(_))));
    for rule in capture_first.chain(remaining) {
        let references = document.field_references.get(rule.id());
        let mut rule = serde_yaml::to_value(rule)?;
        walk::compact_rule(&mut rule, document.source_revision.as_deref())?;
        if let Some(references) = references {
            field_refs::restore(&mut rule, references)?;
        }
        resources::compact(&mut rule, &resource_names)?;
        rules.push(rule);
    }
    root.insert("rules".into(), Value::Sequence(rules));
    Ok(root.into())
}
