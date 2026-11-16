//! Application SSE policy and delivered-value provenance integration tests.
use super::*;
use crate::interaction::stream::SseEvent;
fn compare_message(
    source: &WireMessage,
    target: &WireMessage,
    global: Option<&crate::policy::CompiledJsonPolicy>,
    clocks: crate::value_contract::json::AnchorClocks,
    pointer: &str,
    copies: &crate::value_contract::time_copies::DeliveredTimeCopies,
    _observed: super::super::RequestTimes,
) -> Comparison {
    let adapter = global.map(|plan| ValueAdapter { plan, copies });
    verification::sse::compare_message(
        source,
        target,
        adapter
            .as_ref()
            .map(|adapter| adapter as &dyn verification::ValueComparator),
        clocks,
        pointer,
    )
}
mod global_tests;
