//! Observation count/order permissions compose with independent read-back rendering.
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
        (NativeEffect::RedisReadObservation(effect), read_back)
        | (read_back, NativeEffect::RedisReadObservation(effect))
            if effect.state_values =>
        {
            read_back
        }
        _ => return false,
    };
    // Native observation proof owns state and counts. Read-back renders only
    // authenticated current SET values and preserves RESP nil.
    read_back
        .redis_read_back()
        .iter()
        .any(|read| read.contract.operation == "GET")
}
