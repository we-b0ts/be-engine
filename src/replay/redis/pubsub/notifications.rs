//! A subscription owns one ordered timer and at most one materialized notification.
use super::*;
use crate::dependency_index::{Paged, RecordRef, RecordSource};
use inventory::NotificationEntry;
use std::sync::Weak;
use tokio::sync::watch;
use tokio::time::{Duration, Instant, sleep_until};

type IndexedJob = (usize, Paged<NotificationEntry>, Arc<RecordSource>);

pub(in crate::replay::redis) struct NotificationJob {
    pub(super) indices: Arc<Vec<usize>>,
    pub(super) indexed: Option<IndexedJob>,
    pub(super) sender: mpsc::Sender<Delivery>,
    pub(super) cancelled: watch::Receiver<()>,
    pub(super) client: Uuid,
}

impl Push {
    pub(super) fn bytes(&self) -> Result<Vec<u8>> {
        match &self.evidence {
            Some(reference) => reference.load::<RecordedPush>()?.response.decode(),
            None => Ok(self.raw.clone()),
        }
    }
}

pub(in crate::replay::redis) fn schedule_notifications(
    state: Arc<Mutex<ReplayState>>,
    mut job: NotificationJob,
) {
    let weak = Arc::downgrade(&state);
    tokio::spawn(async move {
        let started = Instant::now();
        if let Some((lane, pages, source)) = job.indexed.take() {
            let mut index = 0;
            for page in 0..pages.pages() {
                let inventory = pages.clone();
                let entries = tokio::task::spawn_blocking(move || inventory.read_page(page)).await;
                let entries = match entries {
                    Ok(Ok(entries)) => entries,
                    error => {
                        if let Some(state) = weak.upgrade() {
                            let mut replay = state.lock().await;
                            fail(
                                &mut replay,
                                PushId::Indexed { lane, index },
                                format!("notification index unavailable: {error:?}"),
                            );
                        }
                        return;
                    }
                };
                for entry in entries {
                    let id = PushId::Indexed { lane, index };
                    index += 1;
                    if !deliver(
                        &weak,
                        &mut job,
                        id,
                        entry.duration_ms,
                        Some(source.reference(entry.location)),
                        started,
                    )
                    .await
                    {
                        return;
                    }
                }
            }
        } else {
            let indices = job.indices.clone();
            for &index in indices.iter() {
                let Some(state) = weak.upgrade() else {
                    return;
                };
                let delay = state.lock().await.redis.pubsub.pushes[index]
                    .record
                    .duration_ms;
                if !deliver(&weak, &mut job, PushId::Inline(index), delay, None, started).await {
                    return;
                }
            }
        }
    });
}

async fn deliver(
    weak: &Weak<Mutex<ReplayState>>,
    job: &mut NotificationJob,
    id: PushId,
    delay: u64,
    reference: Option<RecordRef>,
    started: Instant,
) -> bool {
    tokio::select! {
        _ = sleep_until(started + Duration::from_millis(delay)) => {}
        _ = job.cancelled.changed() => { return false; }
        _ = job.sender.closed() => { return false; }
    }
    let Some(state) = weak.upgrade() else {
        return false;
    };
    let (reference, inline) = {
        let mut replay = state.lock().await;
        if replay.finalized_at.is_some() || !replay.redis.pubsub.is_subscribed(job.client, id) {
            return false;
        }
        match id {
            PushId::Inline(index) => {
                let push = &mut replay.redis.pubsub.pushes[index];
                if !push.status.is_available() {
                    return true;
                }
                push.status = ReplayExchangeStatus::Responding;
                (push.evidence.clone(), push.raw.clone())
            }
            PushId::Indexed { lane, index } => {
                if !replay.redis.pubsub.indexed.available(lane, index) {
                    return true;
                }
                replay.redis.pubsub.indexed.responding(lane, index);
                (reference, Vec::new())
            }
        }
    };
    let bytes = tokio::task::spawn_blocking(move || match reference {
        Some(reference) => reference.load::<RecordedPush>()?.response.decode(),
        None => Ok(inline),
    })
    .await;
    let bytes = match bytes {
        Ok(Ok(bytes)) => bytes,
        error => {
            let mut replay = state.lock().await;
            fail(
                &mut replay,
                id,
                format!("notification evidence unavailable: {error:?}"),
            );
            return false;
        }
    };
    let mut replay = state.lock().await;
    if replay.finalized_at.is_some() || !replay.redis.pubsub.is_subscribed(job.client, id) {
        return false;
    }
    if job
        .sender
        .try_send(Delivery {
            push: id,
            bytes,
            matched: None,
        })
        .is_err()
    {
        fail(&mut replay, id, "notification delivery queue full".into());
    }
    true
}

fn fail(replay: &mut ReplayState, id: PushId, reason: String) {
    replay.redis.pubsub.fail(id);
    let record = match id {
        PushId::Inline(index) => &replay.redis.pubsub.pushes[index].record,
        PushId::Indexed { lane, .. } => &replay.redis.pubsub.indexed.lanes[lane].record,
    };
    let target = TargetKey {
        host: record.target_host.clone(),
        port: record.target_port,
    };
    replay
        .redis
        .events
        .unsafe_events
        .push(CommandRequestReport {
            case_id: None,
            target,
            command: "PUBSUB_PUSH".into(),
            request_fingerprint: None,
            reason,
            diagnostic: None,
        });
}
