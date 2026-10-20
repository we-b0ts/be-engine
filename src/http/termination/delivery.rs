//! Confirm that a body prefix crossed Hyper's output buffer before closing IO.
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::watch;

#[derive(Clone)]
pub(crate) struct DeliveryProgress(watch::Sender<u64>);
impl Default for DeliveryProgress {
    fn default() -> Self {
        Self(watch::channel(0).0)
    }
}
impl DeliveryProgress {
    fn generation(&self) -> u64 {
        *self.0.borrow()
    }
    pub(crate) fn flushed(&self) {
        self.0.send_modify(|value| *value = value.saturating_add(1));
    }
}

pub(crate) struct PrefixDelivery {
    progress: DeliveryProgress,
    required: AtomicU64,
}
impl PrefixDelivery {
    pub(crate) fn new(progress: DeliveryProgress) -> Self {
        Self {
            progress,
            required: AtomicU64::new(u64::MAX),
        }
    }
    pub(crate) fn queued(&self) {
        self.required.store(
            self.progress.generation().saturating_add(1),
            Ordering::Release,
        );
    }
    pub(crate) fn is_complete(&self) -> bool {
        self.progress.generation() >= self.required.load(Ordering::Acquire)
    }
    pub(crate) async fn wait(&self) {
        let mut progress = self.progress.0.subscribe();
        while !self.is_complete() {
            if progress.changed().await.is_err() {
                return;
            }
        }
    }
}
