//! Confirm that a body prefix crossed Hyper's output buffer before closing IO.
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::watch;

#[derive(Clone, Debug)]
pub(crate) struct DeliveryProgress {
    changed: watch::Sender<u64>,
    pending: std::sync::Arc<std::sync::Mutex<Vec<FlushReceipt>>>,
}

pub(crate) struct FlushReceipt {
    delivered: Option<Box<dyn FnOnce() + Send>>,
    failed: Option<Box<dyn FnOnce() + Send>>,
}

impl std::fmt::Debug for FlushReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("FlushReceipt")
    }
}

impl FlushReceipt {
    pub(crate) fn new(
        delivered: impl FnOnce() + Send + 'static,
        failed: impl FnOnce() + Send + 'static,
    ) -> Self {
        Self {
            delivered: Some(Box::new(delivered)),
            failed: Some(Box::new(failed)),
        }
    }
    fn commit(mut self) {
        self.failed = None;
        if let Some(delivered) = self.delivered.take() {
            delivered();
        }
    }
}

impl Drop for FlushReceipt {
    fn drop(&mut self) {
        if let Some(failed) = self.failed.take() {
            failed();
        }
    }
}
impl Default for DeliveryProgress {
    fn default() -> Self {
        Self {
            changed: watch::channel(0).0,
            pending: Default::default(),
        }
    }
}
impl DeliveryProgress {
    fn generation(&self) -> u64 {
        *self.changed.borrow()
    }
    pub(crate) fn flushed(&self) {
        let pending = std::mem::take(&mut *self.pending.lock().expect("flush receipts poisoned"));
        for receipt in pending {
            receipt.commit();
        }
        self.changed
            .send_modify(|value| *value = value.saturating_add(1));
    }
    pub(crate) fn observe_flush(&self, receipt: FlushReceipt) {
        self.pending
            .lock()
            .expect("flush receipts poisoned")
            .push(receipt);
    }
}

#[derive(Debug)]
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
        let mut progress = self.progress.changed.subscribe();
        while !self.is_complete() {
            if progress.changed().await.is_err() {
                return;
            }
        }
    }
}
