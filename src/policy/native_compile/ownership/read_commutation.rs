//! Finite nil ordering can compose with read-back, whose wire adapter preserves nil.
use super::*;
use crate::policy::CompiledNativeRule;

pub(super) fn compatible_read_back(
    native: &[CompiledNativeRule],
    left: &NativeFieldClaim,
    right: &NativeFieldClaim,
) -> bool {
    if left.surface != ClaimSurface::DependencyResponse
        || left.slot != NativeOwnedSlot::Value
        || right.slot != NativeOwnedSlot::Value
        || left.selector.operation.as_deref() != Some("GET")
        || right.selector.operation.as_deref() != Some("GET")
    {
        return false;
    }
    let effect = |claim: &NativeFieldClaim| {
        native
            .iter()
            .find(|rule| rule.rule.id == claim.rule_id)
            .map(|rule| &rule.rule.effect)
    };
    let (Some(left), Some(right)) = (effect(left), effect(right)) else {
        return false;
    };
    let read_back = match (left, right) {
        (NativeEffect::RedisReadCommutation(_), read_back)
        | (read_back, NativeEffect::RedisReadCommutation(_)) => read_back,
        _ => return false,
    };
    // Source preparation still requires every selected GET to be nil and
    // rejects all writers. GET read-back only transforms bulk payloads, never
    // RESP nil, so it cannot change the observation authorizing commutation.
    read_back
        .redis_read_back()
        .iter()
        .any(|read| read.contract.operation == "GET")
}
