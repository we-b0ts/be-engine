//! Strict comparison consumes the caller's rule metadata and authenticated copy proofs.
use crate::ExecutionContext;
use serde_json::Value;
pub use traffic_contract::compare::{
    AnchorClocks, Comparison, Field, ValueCopyProof, VerifiedField,
};
pub use traffic_contract::comparison::Difference;

pub(crate) fn compare_values(
    context: &ExecutionContext<'_>,
    source: &traffic_value::Value,
    target: &traffic_value::Value,
    fields: &[Field<'_>],
    verified: &[VerifiedField<'_>],
    clocks: AnchorClocks,
    copies: &[&dyn ValueCopyProof],
) -> Comparison {
    traffic_contract::compare::compare_logical_all(
        source,
        target,
        fields,
        &[],
        verified,
        clocks,
        copies,
        context.metadata,
    )
}

pub(crate) fn compare_with_verified_time_copies(
    context: &ExecutionContext<'_>,
    source: &Value,
    target: &Value,
    fields: &[Field<'_>],
    verified: &[VerifiedField<'_>],
    clocks: AnchorClocks,
    copies: &[&dyn ValueCopyProof],
) -> Comparison {
    traffic_contract::compare::compare_all(
        source,
        target,
        fields,
        &[],
        verified,
        clocks,
        copies,
        context.metadata,
    )
}
