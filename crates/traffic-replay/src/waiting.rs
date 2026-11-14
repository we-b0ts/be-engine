//! Completion notifications registered before releasing the ownership lock.
use std::{pin::Pin, sync::Arc, time::Duration};
use tokio::{
    sync::{Notify, futures::OwnedNotified},
    time::Instant,
};

pub struct WaitRegistration {
    changed: Pin<Box<OwnedNotified>>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitOutcome {
    Changed,
    Poll,
    Deadline,
}
impl WaitRegistration {
    pub fn new(changed: Arc<Notify>) -> Self {
        let mut changed = Box::pin(changed.notified_owned());
        changed.as_mut().enable();
        Self { changed }
    }
    pub async fn wait(mut self, deadline: Instant) -> WaitOutcome {
        tokio::select! {
            biased;
            _=tokio::time::sleep_until(deadline)=>WaitOutcome::Deadline,
            _=&mut self.changed=>WaitOutcome::Changed,
            _=tokio::time::sleep(Duration::from_millis(100))=>WaitOutcome::Poll,
        }
    }

    pub async fn changed(mut self) {
        (&mut self.changed).await;
    }
}
