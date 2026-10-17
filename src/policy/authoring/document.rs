//! Authoring documents resolve to fully explicit typed rules before compilation.
use anyhow::{Result, ensure};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_yaml::{Mapping, Value};

use super::{proof, walk};
use crate::policy::{PolicyRule, TrafficPolicy};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    format: String,
    #[serde(default, deserialize_with = "declared_revision")]
    source_revision: Option<String>,
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
            let mut rules = Vec::with_capacity(document.rules.len());
            for mut rule in document.rules {
                let id = rule
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or("<missing-id>")
                    .to_owned();
                walk::expand_rule(&mut rule, document.source_revision.as_deref())
                    .map_err(|error| anyhow::anyhow!("rule {id:?}: {error:#}"))?;
                rules.push(serde_yaml::from_value(rule)?);
            }
            Ok(Self {
                format: document.format,
                source_revision: document.source_revision,
                rules,
            })
        })();
        result.map_err(serde::de::Error::custom)
    }
}

/// Typed callers can insert rules without a document context; normalize them
/// here too so compile, rendering and plan evidence bind the same Source.
pub(crate) fn expanded(document: &TrafficPolicy) -> Result<TrafficPolicy> {
    if document.source_revision.is_none() {
        return Ok(document.clone());
    }
    if let Some(revision) = &document.source_revision {
        proof::revision(revision)?;
    }
    let rules = document
        .rules
        .iter()
        .map(|rule| {
            let mut value = serde_yaml::to_value(rule)?;
            walk::expand_rule(&mut value, document.source_revision.as_deref())?;
            serde_yaml::from_value(value).map_err(Into::into)
        })
        .collect::<Result<Vec<PolicyRule>>>()?;
    Ok(TrafficPolicy {
        format: document.format.clone(),
        source_revision: document.source_revision.clone(),
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
        "policy format must be traffic-policy/v1"
    );
    let mut root = Mapping::new();
    root.insert("format".into(), document.format.into());
    if let Some(revision) = &document.source_revision {
        root.insert("source_revision".into(), revision.clone().into());
    }
    let mut rules = vec![];
    for rule in &document.rules {
        let mut rule = serde_yaml::to_value(rule)?;
        walk::compact_rule(&mut rule, document.source_revision.as_deref())?;
        rules.push(rule);
    }
    root.insert("rules".into(), Value::Sequence(rules));
    Ok(root.into())
}
