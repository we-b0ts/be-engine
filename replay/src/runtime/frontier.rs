//! Wake tasks whose recorded sequence has reached the replay frontier.
use std::{collections::BTreeMap, sync::Arc};

use tokio::sync::Notify;

use super::SequenceRuntime;

type Key = (u64, u64);

#[derive(Debug, Default)]
pub(super) struct FrontierWaiters {
    next_id: u64,
    pending: BTreeMap<Key, Arc<Notify>>,
}

impl FrontierWaiters {
    pub(super) fn register<'a>(
        &mut self,
        runtime: &'a SequenceRuntime,
        sequence: u64,
    ) -> FrontierWait<'a> {
        let key = (sequence, self.next_id);
        self.next_id = self
            .next_id
            .checked_add(1)
            .expect("frontier waiter ID overflow");
        let changed = Arc::new(Notify::new());
        self.pending.insert(key, changed.clone());
        FrontierWait {
            runtime,
            key: Some(key),
            changed,
        }
    }

    pub(super) fn take_ready(&mut self, sequence: u64) -> Vec<Arc<Notify>> {
        let mut ready = Vec::new();
        while let Some(entry) = self
            .pending
            .first_entry()
            .filter(|entry| entry.key().0 <= sequence)
        {
            ready.push(entry.remove());
        }
        ready
    }
}

/// A cancellable registration for one sequence. Each registration owns its
/// notification, so it can retain a permit until the waiting future is polled.
pub struct FrontierWait<'a> {
    runtime: &'a SequenceRuntime,
    key: Option<Key>,
    changed: Arc<Notify>,
}

impl FrontierWait<'_> {
    pub async fn changed(mut self) {
        self.changed.notified().await;
        self.key = None;
    }
}

impl Drop for FrontierWait<'_> {
    fn drop(&mut self) {
        if let Some(key) = self.key {
            self.runtime
                .state
                .lock()
                .expect("sequence runtime poisoned")
                .frontier_waiters
                .pending
                .remove(&key);
        }
    }
}
