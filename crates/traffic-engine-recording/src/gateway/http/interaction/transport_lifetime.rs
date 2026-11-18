//! Task cancellation still releases the recorded transport reservation.
use super::SessionRef;
use std::sync::atomic::Ordering;

pub(super) struct TransportLifetime(SessionRef);
impl TransportLifetime {
    pub(super) fn new(session: SessionRef) -> Self {
        session.active_io.fetch_add(1, Ordering::SeqCst);
        Self(session)
    }
}
impl Drop for TransportLifetime {
    fn drop(&mut self) {
        self.0.active_io.fetch_sub(1, Ordering::SeqCst);
        self.0.changed.notify_one();
    }
}
