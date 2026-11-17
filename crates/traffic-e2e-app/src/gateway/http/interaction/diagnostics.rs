//! Bounded interaction phases, without application messages or request headers.
use super::SessionRef;
use crate::interaction::model::Protocol;
use uuid::Uuid;

pub(super) fn phase(case_id: Uuid, protocol: Protocol, phase: &'static str) {
    tracing::info!(case_id = %case_id, ?protocol, phase, "recording interaction phase");
}

pub(super) fn waiting(session: &SessionRef) {
    let observation = session
        .observation
        .lock()
        .expect("interaction observation poisoned");
    let pending = observation.pending();
    tracing::info!(
        case_id = %session.case.id,
        protocol = ?observation.protocol(),
        elapsed_ms = session.now(),
        pending_requests = pending.len(),
        initial_response_pending = pending.contains(&0),
        next_deadline_ms = observation.next_deadline_ms(),
        "recording interaction progress"
    );
}
