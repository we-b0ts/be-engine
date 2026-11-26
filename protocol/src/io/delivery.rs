//! Commit queued output callbacks after their transport buffer flushes.
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::watch;

#[derive(Clone, Debug)]
pub struct DeliveryProgress {
    changed: watch::Sender<u64>,
    pending: Arc<Mutex<Vec<FlushReceipt>>>,
}

pub struct FlushReceipt {
    delivered: Option<Box<dyn FnOnce() + Send>>,
    failed: Option<Box<dyn FnOnce() + Send>>,
    timestamp: Option<FlushTimestamp>,
}

#[derive(Debug, Clone, Default)]
pub struct FlushTimestamp(Arc<Mutex<Option<Instant>>>);

impl FlushTimestamp {
    pub fn last(&self) -> Option<Instant> {
        *self.0.lock().expect("flush timestamp poisoned")
    }
}

impl std::fmt::Debug for FlushReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("FlushReceipt")
    }
}

impl FlushReceipt {
    pub fn new(
        delivered: impl FnOnce() + Send + 'static,
        failed: impl FnOnce() + Send + 'static,
    ) -> Self {
        Self {
            delivered: Some(Box::new(delivered)),
            failed: Some(Box::new(failed)),
            timestamp: None,
        }
    }

    /// Track when this receipt committed to compare it with a lifecycle boundary.
    pub fn with_timestamp(mut self, timestamp: FlushTimestamp) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    fn commit(mut self) {
        self.failed = None;
        if let Some(delivered) = self.delivered.take() {
            delivered();
        }
        if let Some(timestamp) = &self.timestamp {
            *timestamp.0.lock().expect("flush timestamp poisoned") = Some(Instant::now());
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
    pub fn flushed(&self) {
        let pending = std::mem::take(&mut *self.pending.lock().expect("flush receipts poisoned"));
        for receipt in pending {
            receipt.commit();
        }
        self.changed
            .send_modify(|value| *value = value.saturating_add(1));
    }
    pub fn observe_flush(&self, receipt: FlushReceipt) {
        self.pending
            .lock()
            .expect("flush receipts poisoned")
            .push(receipt);
    }
}

#[derive(Debug)]
pub struct PrefixDelivery {
    progress: DeliveryProgress,
    required: AtomicU64,
}
impl PrefixDelivery {
    pub fn new(progress: DeliveryProgress) -> Self {
        Self {
            progress,
            required: AtomicU64::new(u64::MAX),
        }
    }
    pub fn queued(&self) {
        self.required.store(
            self.progress.generation().saturating_add(1),
            Ordering::Release,
        );
    }
    pub fn is_complete(&self) -> bool {
        self.progress.generation() >= self.required.load(Ordering::Acquire)
    }
    pub async fn wait(&self) {
        let mut progress = self.progress.changed.subscribe();
        while !self.is_complete() {
            if progress.changed().await.is_err() {
                return;
            }
        }
    }
}
