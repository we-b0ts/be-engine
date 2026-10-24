//! Specialized leaves participate inside the shared whole-element pairing.
use super::{
    AnchorClocks, Comparison, Decisions, Difference, MAX_TIME_OBSERVATIONS, difference,
    validate_relationships,
};
use crate::policy::native::GeneratedResponse;

/// This intentionally has no Debug or Serialize implementation: the key is a
/// borrowed immutable startup snapshot and must never enter an artifact.
#[derive(Clone, Copy)]
pub(crate) struct NativeField<'a> {
    pub(crate) rule_id: &'a str,
    pub(crate) pointer: &'a str,
    pub(crate) contract: &'a GeneratedResponse,
    pub(crate) key: Option<&'a [u8]>,
}

/// A domain owner authenticates a leaf without mutating shared candidate state.
/// The shared comparator owns the staged nonce bijection and chosen pairing.
pub(crate) struct VerifiedField<'a> {
    pub(crate) rule_id: &'a str,
    pub(crate) pointer: &'a str,
    pub(crate) verifier: &'a dyn Fn(LeafContext<'_>) -> Result<LeafObservations, String>,
}

#[derive(Clone, Copy)]
pub(crate) struct LeafContext<'a> {
    pub(crate) source: &'a serde_json::Value,
    pub(crate) target: &'a serde_json::Value,
    pub(crate) source_pointer: &'a str,
    pub(crate) target_pointer: &'a str,
    pub(crate) source_root: &'a serde_json::Value,
    pub(crate) target_root: &'a serde_json::Value,
    pub(crate) clocks: AnchorClocks,
}

#[derive(Default)]
pub(crate) struct LeafObservations {
    pub(crate) time_validations: usize,
    pub(crate) nonces: Vec<NonceIdentity>,
    pub(crate) identities: Vec<crate::value_contract::identities::IdentityPair>,
}

pub(crate) struct NonceIdentity {
    pub(crate) claim: String,
    source: [u8; 32],
    target: [u8; 32],
}

impl NonceIdentity {
    pub(crate) fn new(claim: String, source: &str, target: &str) -> Self {
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
    for pair in &observed.identities {
        let source = serde_json::from_str(&pair.source).map_err(|_| {
            difference(
                context.source_pointer,
                "invalid authenticated identity scalar",
            )
        })?;
        let target = serde_json::from_str(&pair.target).map_err(|_| {
            difference(
                context.source_pointer,
                "invalid authenticated identity scalar",
            )
        })?;
        decisions
            .identities
            .observe(&source, &target)
            .map_err(|_| {
                difference(
                    context.source_pointer,
                    "authenticated nonce bijection changed",
                )
            })?;
    }
    for nonce in &observed.nonces {
        let values = decisions
            .nonces
            .entry((field.rule_id.into(), nonce.claim.clone()))
            .or_default();
        if values.iter().any(|(source, target)| {
            (*source == nonce.source && *target != nonce.target)
                || (*target == nonce.target && *source != nonce.source)
        }) {
            return Err(difference(
                context.source_pointer,
                "authenticated nonce bijection changed",
            ));
        }
        if !values.contains(&(nonce.source, nonce.target)) {
            values.push((nonce.source, nonce.target));
        }
    }
    *decisions
        .time_validations
        .entry(field.rule_id.into())
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
    let comparison = crate::value_contract::generated::compare_value(
        source,
        target,
        field.contract,
        field.key,
        field.rule_id,
        clocks,
    )
    .map_err(|error| {
        difference(
            pointer,
            &format!("generated contract rejected value: {error:?}"),
        )
    })?;
    merge(decisions, comparison).map_err(|error| difference(pointer, error))?;
    validate_relationships(decisions).map_err(|error| difference(pointer, &error.to_string()))
}

fn merge(decisions: &mut Decisions, comparison: Comparison) -> Result<(), &'static str> {
    decisions.identities.merge(comparison.identities)?;
    decisions.evaluated.extend(comparison.evaluated);
    for (rule_id, count) in comparison.time_validations {
        *decisions.time_validations.entry(rule_id).or_default() += count;
    }
    for (scope, values) in comparison.relationships {
        if !scope.2.is_shared() {
            decisions.scoped_time_observations += values.len();
            if decisions.scoped_time_observations > MAX_TIME_OBSERVATIONS {
                return Err("scoped time relationship exceeds 4096 distinct observations");
            }
        }
        decisions.times.entry(scope).or_default().extend(values);
    }
    for (scope, pairs) in comparison.nonce_relationships {
        let values = decisions.nonces.entry(scope).or_default();
        for (source, target) in pairs {
            if values
                .iter()
                .any(|(a, b)| (*a == source && *b != target) || (*b == target && *a != source))
            {
                return Err("generated binding bijection changed");
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
    use crate::policy::FieldContract;
    use serde_json::json;

    #[test]
    fn failed_unordered_candidate_does_not_commit_nonce_or_target_index() {
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
            super::super::compare_with_verified(
                &source,
                &target,
                &fields,
                &[],
                &verified,
                AnchorClocks::default()
            )
            .passed()
        );
        let collapsed = json!({"items":[{"auth":"t1","name":"B"},{"auth":"t1","name":"A"}]});
        assert!(
            !super::super::compare_with_verified(
                &source,
                &collapsed,
                &fields,
                &[],
                &verified,
                AnchorClocks::default()
            )
            .passed()
        );
        let changed = json!({"items":[{"auth":"t2","name":"C"},{"auth":"t1","name":"A"}]});
        assert!(
            !super::super::compare_with_verified(
                &source,
                &changed,
                &fields,
                &[],
                &verified,
                AnchorClocks::default()
            )
            .passed()
        );
    }
}
