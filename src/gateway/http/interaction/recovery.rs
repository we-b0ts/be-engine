//! Only a completely drained, case-local HTTP stream capture failure can resume.

use super::SessionRef;
use crate::recorder::CaseInvalidation;

pub(super) fn can_continue(session: &SessionRef, failure: Option<&CaseInvalidation>) -> bool {
    failure.is_some_and(|failure| {
        failure.reason == "http_stream_capture_incomplete" && failure.can_recover_after_drain()
    }) && session
        .state
        .inner
        .active_cases
        .failed_stream_is_drained(session.case.id)
        && !*session.state.inner.interactions.source_stop.borrow()
}
