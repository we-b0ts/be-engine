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
pub use super::time_copies::VerifiedTimeCopy;
pub use kernel::{
    AnchorClocks, Comparison, Field, LeafContext, LeafObservations, NonceIdentity, VerifiedField,
    parse_time_pair, pointer_observed,
};
pub use native::NativeField;
pub use traffic_contract::comparison::Difference;
pub use traffic_contract::identity::key as identity_key;
pub fn identity_token(
    value: &Value,
    prefix: &str,
    format: traffic_contract::rule::IdentityFormat,
    pointer: &str,
) -> Result<String, Difference> {
    traffic_policy_value::identity::token(
        value,
        prefix,
        format,
        pointer,
        traffic_extensions::policies(),
    )
}

pub use traffic_engine_policy::formats::PolicyMetadata;

pub fn compare(
    source: &Value,
    target: &Value,
    fields: &[Field<'_>],
    clocks: AnchorClocks,
) -> Comparison {
    compare_with_native(source, target, fields, &[], clocks)
}

pub fn compare_with_native(
    source: &Value,
    target: &Value,
    fields: &[Field<'_>],
    native: &[NativeField<'_>],
    clocks: AnchorClocks,
) -> Comparison {
    compare_all(
        [source, target],
        fields,
        native,
        &[],
        clocks,
        &[],
        &PolicyMetadata,
    )
}

pub fn compare_with_verified(
    source: &Value,
    target: &Value,
    fields: &[Field<'_>],
    native: &[NativeField<'_>],
    verified: &[VerifiedField<'_>],
    clocks: AnchorClocks,
) -> Comparison {
    compare_with_verified_metadata(
        source,
        target,
        fields,
        native,
        verified,
        clocks,
        &PolicyMetadata,
    )
}

pub(crate) fn compare_with_verified_metadata(
    source: &Value,
    target: &Value,
    fields: &[Field<'_>],
    native: &[NativeField<'_>],
    verified: &[VerifiedField<'_>],
    clocks: AnchorClocks,
    metadata: &dyn kernel::RuleMetadata,
) -> Comparison {
    compare_all(
        [source, target],
        fields,
        native,
        verified,
        clocks,
        &[],
        metadata,
    )
}

#[allow(dead_code)]
pub fn compare_with_verified_time_copies(
    source: &Value,
    target: &Value,
    fields: &[Field<'_>],
    verified: &[VerifiedField<'_>],
    clocks: AnchorClocks,
    copies: &[VerifiedTimeCopy],
) -> Comparison {
    compare_all(
        [source, target],
        fields,
        &[],
        verified,
        clocks,
        copies,
        &PolicyMetadata,
    )
}

#[cfg(test)]
pub fn compare_with_time_copies(
    source: &Value,
    target: &Value,
    fields: &[Field<'_>],
    clocks: AnchorClocks,
    copies: &[VerifiedTimeCopy],
) -> Comparison {
    compare_all(
        [source, target],
        fields,
        &[],
        &[],
        clocks,
        copies,
        &PolicyMetadata,
    )
}

fn compare_all(
    [source, target]: [&Value; 2],
    fields: &[Field<'_>],
    native: &[NativeField<'_>],
    verified: &[VerifiedField<'_>],
    clocks: AnchorClocks,
    copies: &[VerifiedTimeCopy],
    metadata: &dyn kernel::RuleMetadata,
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
        source, target, fields, &native, verified, clocks, &copies, metadata,
    )
}

#[cfg(test)]
mod composition;
#[cfg(test)]
mod tests;
