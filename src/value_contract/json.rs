//! Application policy bindings for the protocol-independent comparison kernel.
#[cfg(test)]
use super::time;
#[cfg(test)]
use super::time::ClockPair;
#[cfg(test)]
use crate::policy::{FieldContract, TimeAnchor, TimeRelation, TimestampFormat};
use serde_json::Value;
use traffic_contract::compare as kernel;
mod native;
pub(crate) use super::time_copies::VerifiedTimeCopy;
pub(crate) use kernel::diagnosis;
pub(crate) use kernel::{
    AnchorClocks, Comparison, Field, LeafContext, LeafObservations, NonceIdentity, VerifiedField,
    parse_time_pair, parse_time_value, pointer_observed,
};
pub(crate) use native::NativeField;
pub(crate) use traffic_contract::comparison::Difference;
pub(crate) use traffic_contract::identity::{key as identity_key, token as identity_token};

pub(crate) struct PolicyMetadata;
impl kernel::RuleMetadata for PolicyMetadata {
    fn policies(&self) -> &traffic_policy::PolicyRegistry {
        traffic_extensions::policies()
    }
    fn permits_scalar_composition(&self, rule: &str) -> bool {
        rule == crate::policy::GLOBAL_JSON_ID
    }
    fn accepts_exact_time(&self, rule: &str) -> bool {
        matches!(
            rule,
            crate::policy::GLOBAL_JSON_ID
                | crate::policy::GLOBAL_HTTP_ID
                | crate::policy::GLOBAL_REDIS_ID
                | "global.mysql"
                | super::time::automatic::RULE_ID
        )
    }
}

pub(crate) fn compare(
    source: &Value,
    target: &Value,
    fields: &[Field<'_>],
    clocks: AnchorClocks,
) -> Comparison {
    compare_with_native(source, target, fields, &[], clocks)
}

pub(crate) fn compare_with_native(
    source: &Value,
    target: &Value,
    fields: &[Field<'_>],
    native: &[NativeField<'_>],
    clocks: AnchorClocks,
) -> Comparison {
    compare_all(source, target, fields, native, &[], clocks, &[])
}

pub(crate) fn compare_with_verified(
    source: &Value,
    target: &Value,
    fields: &[Field<'_>],
    native: &[NativeField<'_>],
    verified: &[VerifiedField<'_>],
    clocks: AnchorClocks,
) -> Comparison {
    compare_all(source, target, fields, native, verified, clocks, &[])
}

pub(crate) fn compare_with_verified_time_copies(
    source: &Value,
    target: &Value,
    fields: &[Field<'_>],
    verified: &[VerifiedField<'_>],
    clocks: AnchorClocks,
    copies: &[VerifiedTimeCopy],
) -> Comparison {
    compare_all(source, target, fields, &[], verified, clocks, copies)
}

pub(crate) fn compare_with_time_copies(
    source: &Value,
    target: &Value,
    fields: &[Field<'_>],
    clocks: AnchorClocks,
    copies: &[VerifiedTimeCopy],
) -> Comparison {
    compare_all(source, target, fields, &[], &[], clocks, copies)
}

pub(crate) fn compare_values(
    source: &traffic_value::Value,
    target: &traffic_value::Value,
    fields: &[Field<'_>],
    verified: &[VerifiedField<'_>],
    clocks: AnchorClocks,
    copies: &[VerifiedTimeCopy],
) -> Comparison {
    let copies = copies
        .iter()
        .map(|proof| proof as &dyn kernel::ValueCopyProof)
        .collect::<Vec<_>>();
    kernel::compare_logical_all(
        source,
        target,
        fields,
        &[],
        verified,
        clocks,
        &copies,
        &PolicyMetadata,
    )
}

fn compare_all(
    source: &Value,
    target: &Value,
    fields: &[Field<'_>],
    native: &[NativeField<'_>],
    verified: &[VerifiedField<'_>],
    clocks: AnchorClocks,
    copies: &[VerifiedTimeCopy],
) -> Comparison {
    let verifiers = native.iter().map(native::verifier).collect::<Vec<_>>();
    let native = native
        .iter()
        .zip(&verifiers)
        .map(|(field, verifier)| kernel::NativeField {
            rule_id: field.rule_id,
            pointer: field.pointer,
            verifier,
        })
        .collect::<Vec<_>>();
    let copies = copies
        .iter()
        .map(|proof| proof as &dyn kernel::TimeCopyProof)
        .collect::<Vec<_>>();
    kernel::compare_all(
        source,
        target,
        fields,
        &native,
        verified,
        clocks,
        &copies,
        &PolicyMetadata,
    )
}

impl kernel::TimeCopyProof for VerifiedTimeCopy {
    fn scope(&self) -> (&str, &str) {
        self.scope()
    }
    fn permits_value(
        &self,
        rule: &str,
        source_pointer: &str,
        target_pointer: &str,
        source: &Value,
        target: &Value,
        requirement: &traffic_value::Value,
    ) -> bool {
        serde_json::to_value(requirement)
            .ok()
            .and_then(|value| serde_json::from_value::<crate::policy::TimeContract>(value).ok())
            .is_some_and(|time| {
                self.permits_value(rule, source_pointer, target_pointer, source, target, &time)
            })
    }
}

#[cfg(test)]
mod composition;
#[cfg(test)]
mod tests;
