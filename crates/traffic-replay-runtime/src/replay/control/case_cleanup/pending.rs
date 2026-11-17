//! Capture actual cleanup blockers while the Case ownership lock is still held.
use super::*;
use serde_json::Value;

pub(super) fn snapshot<P: ReplayProtocolSet>(state: &RuntimeState<P>) -> Value {
    let mut pending = state.protocols.pending_diagnostic();
    pending.insert(
        "dependency_protocols".into(),
        state.native.in_flight_diagnostic(),
    );
    pending.insert(
        "connect_failures".into(),
        state.connect_failures.has_in_flight().into(),
    );
    serde_json::to_value(pending).expect("pending diagnostics serialize")
}
