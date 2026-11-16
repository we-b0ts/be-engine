//! Legacy joined-value declarations execute the supplied comparison/analysis providers.
use anyhow::Result;
use serde_json::json;
use std::collections::BTreeMap;
use traffic_policy::{AnalysisInput, EvidenceAccess, PolicyRegistry, ValuePair};
use traffic_value::Value;

pub fn canonicalize(policies: &PolicyRegistry, value: &str, separator: &str) -> String {
    let canonical = || -> Result<String> {
        let options = serde_json::from_value(json!({"separator":separator}))?;
        let transform = policies.prepare_transform("unordered-joined-string", &options)?;
        let context = Value::Null;
        let plan = transform
            .inspect(&traffic_policy::TransformInput {
                bytes: value.as_bytes(),
                context: &context,
            })?
            .ok_or_else(|| anyhow::anyhow!("joined collection has no transformation"))?;
        Ok(String::from_utf8(
            plan.materialize(&BTreeMap::new())?.bytes,
        )?)
    };
    canonical().unwrap_or_else(|_| value.into())
}

pub fn matching_discovery_separators(
    policies: &PolicyRegistry,
    source: &str,
    target: &str,
) -> Vec<String> {
    let source = Value::String(source.into());
    let target = Value::String(target.into());
    let facts = Value::Object(BTreeMap::new());
    let evidence = PairEvidence {
        source: &source,
        target: &target,
        facts: &facts,
    };
    policies
        .analyze(
            &AnalysisInput {
                values: Some(ValuePair {
                    source: &source,
                    target: &target,
                    source_path: "",
                    target_path: "",
                }),
                facts: &facts,
            },
            &evidence,
        )
        .unwrap_or_default()
        .into_iter()
        .filter(|finding| finding.policy == "unordered-joined-string")
        .filter_map(|finding| match finding.proposal? {
            traffic_policy::Proposal::Field(value) => value
                .pointer("/options/separator")?
                .as_str()
                .map(str::to_owned),
            traffic_policy::Proposal::Document(_) => None,
        })
        .collect()
}

struct PairEvidence<'a> {
    source: &'a Value,
    target: &'a Value,
    facts: &'a Value,
}
impl EvidenceAccess for PairEvidence<'_> {
    fn query(&self, kind: &str, selection: &Value) -> Result<Vec<Value>> {
        let value = match kind {
            "source" => self.source,
            "target" => self.target,
            "context" => self.facts,
            _ => anyhow::bail!("value analysis evidence {kind:?} is unavailable"),
        };
        let pointer = match selection {
            Value::Null => "",
            Value::String(pointer) => pointer,
            _ => anyhow::bail!("evidence selection requires a logical pointer"),
        };
        traffic_value::path::validate(pointer, false)?;
        Ok(value.pointer(pointer).cloned().into_iter().collect())
    }
}

pub fn equal(policies: &PolicyRegistry, source: &str, target: &str, separator: &str) -> bool {
    let compare = || -> Result<bool> {
        let policy = policies.prepare(
            "unordered-joined-string",
            &serde_json::from_value(json!({"separator":separator}))?,
        )?;
        Ok(policy
            .evaluate(
                &ValuePair {
                    source: &Value::String(source.into()),
                    target: &Value::String(target.into()),
                    source_path: "",
                    target_path: "",
                },
                &mut (),
            )?
            .passed())
    };
    compare().unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_requires_a_present_separator() {
        let policies = traffic_extensions::policies();
        assert!(matching_discovery_separators(policies, "alice", "alice").is_empty());
        assert_eq!(
            matching_discovery_separators(policies, "alice,bob", "bob,alice"),
            vec![",".to_string()]
        );
    }

    #[test]
    fn comparison_preserves_duplicates_and_empty_elements() {
        let policies = traffic_extensions::policies();
        assert!(equal(policies, "alice,,bob,alice", "alice,bob,alice,", ","));
        assert!(!equal(policies, "alice,,bob", "alice,bob", ","));
    }
}
