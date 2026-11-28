//! Specialized leaves participate inside the shared whole-element pairing.
use super::{AnchorClocks, Comparison, Decisions, Difference, difference};
/// An extension validates its own leaf while the kernel retains whole-element pairing.
#[derive(Clone, Copy)]
pub struct NativeField<'a> {
    pub rule_id: &'a str,
    pub pointer: &'a str,
    pub verifier: &'a dyn Fn(NativeContext<'_>) -> Result<Comparison, String>,
}

#[derive(Clone, Copy)]
pub struct NativeContext<'a> {
    pub source: &'a serde_json::Value,
    pub target: &'a serde_json::Value,
    pub pointer: &'a str,
    pub clocks: AnchorClocks,
}

/// A domain owner authenticates a leaf without mutating shared candidate state.
/// The shared comparator owns the staged nonce bijection and chosen pairing.
pub struct VerifiedField<'a> {
    pub rule_id: &'a str,
    pub pointer: &'a str,
    pub verifier: &'a dyn Fn(LeafContext<'_>) -> Result<LeafObservations, String>,
}

#[derive(Clone, Copy)]
pub struct LeafContext<'a> {
    pub source: &'a serde_json::Value,
    pub target: &'a serde_json::Value,
    pub source_pointer: &'a str,
    pub target_pointer: &'a str,
    pub source_root: &'a serde_json::Value,
    pub target_root: &'a serde_json::Value,
    pub clocks: AnchorClocks,
}

#[derive(Default)]
pub struct LeafObservations {
    pub time_validations: usize,
    pub nonces: Vec<NonceIdentity>,
    pub identities: Vec<crate::identity::IdentityPair>,
}

pub struct NonceIdentity {
    pub claim: String,
    source: [u8; 32],
    target: [u8; 32],
}

impl NonceIdentity {
    pub fn new(claim: String, source: &str, target: &str) -> Self {
        use sha2::{Digest, Sha256};
        Self {
            claim,
            source: Sha256::digest(source.as_bytes()).into(),
            target: Sha256::digest(target.as_bytes()).into(),
        }
    }
}

pub(super) fn verify(
    field: &VerifiedField<'_>,
    context: LeafContext<'_>,
    decisions: &mut Decisions,
) -> Result<(), Difference> {
    let observed =
        (field.verifier)(context).map_err(|error| difference(context.source_pointer, &error))?;
    observe(field.rule_id, context.source_pointer, observed, decisions)
}

pub(super) fn observe(
    rule_id: &str,
    pointer: &str,
    observed: LeafObservations,
    decisions: &mut Decisions,
) -> Result<(), Difference> {
    for pair in &observed.identities {
        let source = serde_json::from_str(&pair.source)
            .map_err(|_| difference(pointer, "invalid authenticated identity scalar"))?;
        let target = serde_json::from_str(&pair.target)
            .map_err(|_| difference(pointer, "invalid authenticated identity scalar"))?;
        decisions
            .identities
            .observe(&source, &target)
            .map_err(|_| difference(pointer, "authenticated nonce bijection changed"))?;
    }
    for nonce in &observed.nonces {
        let values = decisions
            .nonces
            .entry((rule_id.into(), nonce.claim.clone()))
            .or_default();
        if values.iter().any(|(source, target)| {
            (*source == nonce.source && *target != nonce.target)
                || (*target == nonce.target && *source != nonce.source)
        }) {
            return Err(difference(pointer, "authenticated nonce bijection changed"));
        }
        if !values.contains(&(nonce.source, nonce.target)) {
            values.push((nonce.source, nonce.target));
        }
    }
    *decisions
        .time_validations
        .entry(rule_id.into())
        .or_default() += observed.time_validations;
    Ok(())
}

pub(super) fn compare(
    source: &serde_json::Value,
    target: &serde_json::Value,
    field: &NativeField<'_>,
    pointer: &str,
    clocks: AnchorClocks,
    decisions: &mut Decisions,
) -> Result<(), Difference> {
    let comparison = (field.verifier)(NativeContext {
        source,
        target,
        pointer,
        clocks,
    })
    .map_err(|error| difference(pointer, &error))?;
    if let Some(error) = comparison.differences.first() {
        return Err(error.clone());
    }
    merge(decisions, comparison).map_err(|error| difference(pointer, &error))
}

fn merge(decisions: &mut Decisions, comparison: Comparison) -> Result<(), String> {
    decisions
        .identities
        .merge(comparison.identities)
        .map_err(str::to_owned)?;
    decisions.evaluated.extend(comparison.evaluated);
    for (rule_id, count) in comparison.time_validations {
        *decisions.time_validations.entry(rule_id).or_default() += count;
    }
    decisions
        .observations
        .merge(comparison.observations)
        .map_err(|error| error.to_string())?;
    for (metric, values) in comparison.policy_counts {
        let counts = decisions.counts.entry(metric).or_default();
        for (rule, count) in values {
            *counts.entry(rule).or_default() += count;
        }
    }
    for (scope, pairs) in comparison.nonce_relationships {
        let values = decisions.nonces.entry(scope).or_default();
        for (source, target) in pairs {
            if values
                .iter()
                .any(|(a, b)| (*a == source && *b != target) || (*b == target && *a != source))
            {
                return Err("generated binding bijection changed".into());
            }
            if !values.contains(&(source, target)) {
                values.push((source, target));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::FieldContract;
    use serde_json::json;

    #[test]
    fn failed_unordered_candidate_does_not_commit_nonce_or_target_index() {
        let metadata = super::super::RegisteredRules(traffic_extensions::policies());
        let contract = FieldContract::Unordered;
        let fields = [super::super::Field {
            rule_id: "order",
            pointer: "/items",
            contract: &contract,
        }];
        let source = json!({"items":[{"auth":"s1","name":"A"},{"auth":"s2","name":"B"}]});
        let target = json!({"items":[{"auth":"t2","name":"B"},{"auth":"t1","name":"A"}]});
        let verify = |context: LeafContext<'_>| {
            assert_eq!(
                context.source_root.pointer(context.source_pointer),
                Some(context.source)
            );
            assert_eq!(
                context.target_root.pointer(context.target_pointer),
                Some(context.target)
            );
            Ok(LeafObservations {
                time_validations: 0,
                identities: vec![],
                nonces: vec![NonceIdentity::new(
                    "/nonce".into(),
                    context.source.as_str().unwrap(),
                    context.target.as_str().unwrap(),
                )],
            })
        };
        let verified = [VerifiedField {
            rule_id: "token",
            pointer: "/items/*/auth",
            verifier: &verify,
        }];
        assert!(
            super::super::compare_all(
                &source,
                &target,
                &fields,
                &[],
                &verified,
                AnchorClocks::default(),
                &[],
                &metadata,
            )
            .passed()
        );
        let collapsed = json!({"items":[{"auth":"t1","name":"B"},{"auth":"t1","name":"A"}]});
        assert!(
            !super::super::compare_all(
                &source,
                &collapsed,
                &fields,
                &[],
                &verified,
                AnchorClocks::default(),
                &[],
                &metadata,
            )
            .passed()
        );
        let changed = json!({"items":[{"auth":"t2","name":"C"},{"auth":"t1","name":"A"}]});
        assert!(
            !super::super::compare_all(
                &source,
                &changed,
                &fields,
                &[],
                &verified,
                AnchorClocks::default(),
                &[],
                &metadata,
            )
            .passed()
        );
    }
}
