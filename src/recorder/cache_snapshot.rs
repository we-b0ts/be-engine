use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use bytes::Bytes;
use tokio::sync::{Mutex, oneshot};

use crate::config::RecordingConfig;

#[derive(Debug)]
pub(crate) struct CacheSnapshotStore {
    state: Mutex<SnapshotState>,
    max_entries: usize,
    max_bytes: usize,
    max_waiters_per_entry: usize,
    fill_timeout: Duration,
}

#[derive(Debug, Default)]
struct SnapshotState {
    entries: HashMap<Vec<u8>, SnapshotEntry>,
    ready_bytes: usize,
}

#[derive(Debug)]
enum SnapshotEntry {
    Filling {
        waiters: Vec<oneshot::Sender<std::result::Result<Bytes, String>>>,
    },
    Ready(Bytes),
}

#[derive(Debug)]
pub(crate) enum CacheSnapshotReservation {
    Leader,
    Hit(Bytes),
    Wait(CacheSnapshotWaiter),
}

#[derive(Debug)]
pub(crate) struct CacheSnapshotWaiter {
    receiver: oneshot::Receiver<std::result::Result<Bytes, String>>,
    timeout: Duration,
}

impl CacheSnapshotStore {
    pub(crate) fn new(config: &RecordingConfig) -> Self {
        Self {
            state: Mutex::new(SnapshotState::default()),
            max_entries: config.cache_snapshot_max_entries,
            max_bytes: config.cache_snapshot_max_bytes,
            max_waiters_per_entry: config.cache_snapshot_max_waiters_per_entry,
            fill_timeout: Duration::from_millis(config.cache_snapshot_fill_timeout_ms),
        }
    }

    pub(crate) async fn reserve(&self, key: Vec<u8>) -> Result<CacheSnapshotReservation> {
        let mut state = self.state.lock().await;
        match state.entries.get_mut(&key) {
            Some(SnapshotEntry::Ready(response)) => {
                Ok(CacheSnapshotReservation::Hit(response.clone()))
            }
            Some(SnapshotEntry::Filling { waiters }) => {
                if waiters.len() >= self.max_waiters_per_entry {
                    bail!(
                        "cache snapshot entry reached its bounded waiter limit of {}",
                        self.max_waiters_per_entry
                    );
                }
                let (sender, receiver) = oneshot::channel();
                waiters.push(sender);
                Ok(CacheSnapshotReservation::Wait(CacheSnapshotWaiter {
                    receiver,
                    timeout: self.fill_timeout,
                }))
            }
            None => {
                if state.entries.len() >= self.max_entries {
                    bail!(
                        "cache snapshot reached its bounded entry limit of {}",
                        self.max_entries
                    );
                }
                state.entries.insert(
                    key,
                    SnapshotEntry::Filling {
                        waiters: Vec::new(),
                    },
                );
                Ok(CacheSnapshotReservation::Leader)
            }
        }
    }

    pub(crate) async fn complete(&self, key: &[u8], response: Bytes, reusable: bool) -> Result<()> {
        let mut state = self.state.lock().await;
        let Some(SnapshotEntry::Filling { waiters }) = state.entries.remove(key) else {
            bail!("cache snapshot completion has no matching fill reservation");
        };
        if reusable {
            let next_bytes = state
                .ready_bytes
                .checked_add(response.len())
                .ok_or_else(|| anyhow!("cache snapshot byte accounting overflowed"))?;
            if next_bytes > self.max_bytes {
                let message = format!(
                    "cache snapshot reached its bounded byte limit of {}",
                    self.max_bytes
                );
                notify(waiters, Err(message.clone()));
                return Err(anyhow!(message));
            }
            state.ready_bytes = next_bytes;
            state
                .entries
                .insert(key.to_vec(), SnapshotEntry::Ready(response.clone()));
        }
        notify(waiters, Ok(response));
        Ok(())
    }

    pub(crate) async fn abort(&self, key: &[u8], reason: &str) {
        let waiters = {
            let mut state = self.state.lock().await;
            match state.entries.remove(key) {
                Some(SnapshotEntry::Filling { waiters }) => waiters,
                Some(SnapshotEntry::Ready(response)) => {
                    state.ready_bytes = state.ready_bytes.saturating_sub(response.len());
                    Vec::new()
                }
                None => Vec::new(),
            }
        };
        notify(waiters, Err(reason.to_string()));
    }
}

impl CacheSnapshotWaiter {
    pub(crate) async fn response(self) -> Result<Bytes> {
        tokio::time::timeout(self.timeout, self.receiver)
            .await
            .map_err(|_| anyhow!("cache snapshot fill timed out"))?
            .map_err(|_| anyhow!("cache snapshot fill owner ended without a result"))?
            .map_err(anyhow::Error::msg)
    }
}

fn notify(
    waiters: Vec<oneshot::Sender<std::result::Result<Bytes, String>>>,
    result: std::result::Result<Bytes, String>,
) {
    for waiter in waiters {
        let _ = waiter.send(result.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn shares_one_completed_value_with_hits_and_waiters() {
        let store = CacheSnapshotStore::new(&RecordingConfig::default());
        let key = b"redis-key".to_vec();
        assert!(matches!(
            store.reserve(key.clone()).await.unwrap(),
            CacheSnapshotReservation::Leader
        ));
        let CacheSnapshotReservation::Wait(waiter) = store.reserve(key.clone()).await.unwrap()
        else {
            panic!("expected waiter");
        };

        store
            .complete(&key, Bytes::from_static(b"v1"), true)
            .await
            .unwrap();

        assert_eq!(waiter.response().await.unwrap(), Bytes::from_static(b"v1"));
        let CacheSnapshotReservation::Hit(hit) = store.reserve(key).await.unwrap() else {
            panic!("expected hit");
        };
        assert_eq!(hit, Bytes::from_static(b"v1"));
    }

    #[tokio::test]
    async fn transient_completion_wakes_waiters_without_becoming_sticky() {
        let store = CacheSnapshotStore::new(&RecordingConfig::default());
        let key = b"redis-key".to_vec();
        assert!(matches!(
            store.reserve(key.clone()).await.unwrap(),
            CacheSnapshotReservation::Leader
        ));
        let CacheSnapshotReservation::Wait(waiter) = store.reserve(key.clone()).await.unwrap()
        else {
            panic!("expected waiter");
        };

        store
            .complete(&key, Bytes::from_static(b"-ERR transient\r\n"), false)
            .await
            .unwrap();

        assert_eq!(
            waiter.response().await.unwrap(),
            Bytes::from_static(b"-ERR transient\r\n")
        );
        assert!(matches!(
            store.reserve(key).await.unwrap(),
            CacheSnapshotReservation::Leader
        ));
    }
}
