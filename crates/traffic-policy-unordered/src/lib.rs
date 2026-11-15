//! Multiset comparison and order-difference discovery over logical values.
use anyhow::{Result, ensure};
use std::{collections::BTreeMap, sync::Arc};
use traffic_policy::{
    AnalysisInput, ComparisonPolicy, Evaluation, EvaluationHost, EvidenceAccess, Finding,
    PolicyAction, PolicyDescriptor, PolicyProvider, Proposal, ValuePair,
};
use traffic_value::Value;

mod canonical;
mod joined;
pub use joined::JoinedStringPolicy;

pub struct UnorderedPolicy;

impl PolicyProvider for UnorderedPolicy {
    fn descriptor(&self) -> PolicyDescriptor {
        PolicyDescriptor {
            id: "unordered",
            version: 1,
            description: "Compare complete collection elements as a multiset while preserving multiplicity and nested contracts",
            actions: &[PolicyAction::Compare, PolicyAction::Analyze],
        }
    }
    fn prepare(&self, configuration: &Value) -> Result<Arc<dyn ComparisonPolicy>> {
        ensure!(
            configuration == &Value::Null,
            "unordered has no configuration fields"
        );
        Ok(Arc::new(Self))
    }
    fn analyze(
        &self,
        input: &AnalysisInput<'_>,
        _evidence: &dyn EvidenceAccess,
    ) -> Result<Vec<Finding>> {
        let Some(pair) = &input.values else {
            return Ok(context_hint(input));
        };
        let (Some(source), Some(target)) = (pair.source.as_array(), pair.target.as_array()) else {
            return Ok(Vec::new());
        };
        if source == target || counts(source)? != counts(target)? {
            return Ok(Vec::new());
        }
        Ok(vec![Finding {
            policy: self.descriptor().id.into(), source_path: pair.source_path.into(),
            summary: "Collection values differ only in element order".into(),
            hint: "Trace Source collection construction and downstream use before proposing unordered semantics. Preserve complete elements, duplicate counts and all unselected fields.".into(),
            proposal: Some(Proposal::Field(Value::Object(BTreeMap::from([("kind".into(), Value::String("unordered".into()))])))),
            requirements: vec!["source_semantics".into(), "fresh_verification".into()],
        }])
    }
}

fn context_hint(input: &AnalysisInput<'_>) -> Vec<Finding> {
    let unmatched = input
        .facts
        .pointer("/clusters")
        .and_then(Value::as_array)
        .is_some_and(|clusters| {
            clusters.iter().any(|cluster| {
                cluster.pointer("/reason").and_then(Value::as_str) == Some("unmatched_target")
            })
        });
    if input.facts.pointer("/query").and_then(Value::as_str) != Some("dirty_clusters") || !unmatched
    {
        return Vec::new();
    }
    vec![Finding {
        policy: "unordered".into(), source_path: String::new(),
        summary: "Unmatched values can be inspected for Source-proven collection ordering".into(),
        hint: "Inspect protected Source/Target differences and trace Source collection construction. A proven order-only difference can use a shared field declaration. Preserve complete elements, duplicate counts and unselected values, then review and verify the applied rule through genuine Replay.".into(),
        proposal: None,
        requirements: vec!["source_semantics".into(), "paired_values".into(), "fresh_verification".into()],
    }]
}

impl ComparisonPolicy for UnorderedPolicy {
    fn applies(&self, source: &Value, _: &Value) -> Result<bool> {
        Ok(source.as_array().is_some())
    }
    fn supports_child_rules(&self) -> bool {
        true
    }
    fn evaluate(&self, pair: &ValuePair<'_>, host: &mut dyn EvaluationHost) -> Result<Evaluation> {
        let (Some(source), Some(target)) = (pair.source.as_array(), pair.target.as_array()) else {
            return Ok(Evaluation::mismatch(
                pair,
                "collection_type",
                "unordered requires two arrays",
            ));
        };
        if source.len() != target.len() {
            return Ok(Evaluation::mismatch(
                pair,
                "collection_cardinality",
                "array cardinality changed",
            ));
        }
        if !host.has_descendant_rules() {
            return Ok(if counts(source)? == counts(target)? {
                Evaluation::matched()
            } else {
                Evaluation::mismatch(pair, "collection_contents", "unordered multiset changed")
            });
        }
        if source.len() > 128 {
            return Ok(Evaluation::mismatch(
                pair,
                "collection_limit",
                "unordered collection exceeds 128 elements",
            ));
        }
        if pair_elements(pair, source.len(), 0, &mut vec![false; target.len()], host)? {
            Ok(Evaluation::matched())
        } else {
            Ok(Evaluation::mismatch(
                pair,
                "collection_pairing",
                "no bounded multiset pairing preserves all contracts",
            ))
        }
    }
}

fn pair_elements(
    pair: &ValuePair<'_>,
    length: usize,
    index: usize,
    used: &mut [bool],
    host: &mut dyn EvaluationHost,
) -> Result<bool> {
    if index == length {
        return Ok(true);
    }
    for candidate in 0..used.len() {
        if used[candidate] {
            continue;
        }
        let checkpoint = host.checkpoint()?;
        let comparison = host.compare(
            &format!("{}/{index}", pair.source_path),
            &format!("{}/{candidate}", pair.target_path),
        );
        let accepted = match comparison {
            Ok(comparison) if comparison.passed() => {
                used[candidate] = true;
                pair_elements(pair, length, index + 1, used, host)
            }
            Ok(_) => Ok(false),
            Err(error) => {
                host.rollback(checkpoint)?;
                return Err(error);
            }
        };
        if matches!(accepted, Ok(true)) {
            host.accept(checkpoint)?;
            return Ok(true);
        }
        host.rollback(checkpoint)?;
        used[candidate] = false;
        accepted?;
        if !host.budget_remaining() {
            break;
        }
    }
    Ok(false)
}

fn counts(values: &[Value]) -> Result<BTreeMap<Vec<u8>, usize>> {
    let mut counts = BTreeMap::new();
    for value in values {
        *counts.entry(canonical::key(value)?).or_default() += 1;
    }
    Ok(counts)
}
