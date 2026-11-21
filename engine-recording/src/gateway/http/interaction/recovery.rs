//! Reuse Source only after protocol-owned teardown and complete dependency drain.

use super::SessionRef;
use crate::recorder::CaseInvalidation;
use std::sync::atomic::Ordering;

pub(super) fn client_disconnect_closed(
    session: &SessionRef,
    failure: Option<&CaseInvalidation>,
) -> bool {
    failure.is_some_and(|failure| {
        failure.reason == "interaction_client_transport_lost" && failure.can_recover_after_drain()
    }) && session.client_disconnect_confirmed.load(Ordering::SeqCst)
        && session.active_io.load(Ordering::SeqCst) == 0
        && !*session.state.inner.interactions.source_stop.borrow()
}

pub(super) fn can_continue(session: &SessionRef, failure: Option<&CaseInvalidation>) -> bool {
    if client_disconnect_closed(session, failure) {
        return session
            .state
            .inner
            .active_cases
            .failed_case_dependencies_drained(session.case.id);
    }
    failure.is_some_and(|failure| {
        failure.reason == "http_stream_capture_incomplete" && failure.can_recover_after_drain()
    }) && session
        .state
        .inner
        .active_cases
        .failed_stream_is_drained(session.case.id)
        && !*session.state.inner.interactions.source_stop.borrow()
}
