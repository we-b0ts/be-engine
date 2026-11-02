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
                        entry.adapter_echo,
                        entry.adapter_namespace,
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
                let digest = {
                    let replay = state.lock().await;
                    replay.redis.pubsub.pushes[index]
                        .bytes()
                        .ok()
                        .and_then(|raw| parse_pubsub_push(&raw).ok().flatten())
                        .and_then(|push| rpc::echo_digest(&push.channel, &push.payload))
                };
                let namespace = {
                    let replay = state.lock().await;
                    replay.redis.pubsub.pushes[index]
                        .bytes()
                        .ok()
                        .and_then(|raw| parse_pubsub_push(&raw).ok().flatten())
                        .and_then(|push| rpc::notification_namespace(&push.channel, &push.payload))
                };
                if !deliver(
                    &weak,
                    &mut job,
                    PushId::Inline(index),
                    delay,
                    digest,
                    namespace,
                    None,
                    started,
                )
                .await
                {
                    return;
                }
            }
        }
    });
}

#[allow(clippy::too_many_arguments)]
async fn deliver(
    weak: &Weak<Mutex<ReplayState>>,
    job: &mut NotificationJob,
    id: PushId,
    delay: u64,
    adapter_echo: Option<[u8; 32]>,
    adapter_namespace: Option<String>,
    reference: Option<RecordRef>,
    started: Instant,
) -> bool {
    if let Some(state) = weak.upgrade()
        && state.lock().await.redis.pubsub.timer_is_correlated(
            id,
            adapter_echo,
            adapter_namespace.as_deref(),
        )
    {
        return true;
    }
    tokio::select! {
        _ = sleep_until(started + Duration::from_millis(delay)) => {}
        _ = job.cancelled.changed() => { return false; }
        _ = job.sender.closed() => { return false; }
    }
    let Some(state) = weak.upgrade() else {
        return false;
    };
    let (reference, inline, case_id, request_epoch) = {
        let mut replay = state.lock().await;
        if replay.finalized_at.is_some() || !replay.redis.pubsub.is_subscribed(job.client, id) {
            return false;
        }
        if replay
            .redis
            .pubsub
            .timer_is_correlated(id, adapter_echo, adapter_namespace.as_deref())
        {
            return true;
        }
        match id {
            PushId::Inline(index) => {
                let push = &replay.redis.pubsub.pushes[index];
                if !push.status.is_available() {
                    return true;
                }
                let case = push.case_id.clone();
                let reference = push.evidence.clone();
                let raw = push.raw.clone();
                let epoch = if let Some(case) = &case {
                    if replay.active_case_id.as_ref() != Some(case) || replay.target_session_stopped
                    {
                        return true;
                    }
                    let epoch = replay.redis.request_contracts.request_times(case).target;
                    replay.redis.pubsub.reserve_case_push(id, case, job.client);
                    epoch
                } else {
                    replay.redis.pubsub.reserve_push(id);
                    None
                };
                (reference, raw, case, epoch)
            }
            PushId::Indexed { lane, index } => {
                if !replay.redis.pubsub.indexed.available(lane, index) {
                    return true;
                }
                replay.redis.pubsub.indexed.responding(lane, index);
                (reference, Vec::new(), None, None)
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
    let delivery = Delivery {
        case_id,
        push: id,
        bytes,
        matched: None,
        request_epoch,
    };
    if replay.finalized_at.is_some()
        || !replay.redis.pubsub.is_subscribed(job.client, id)
        || !delivery.case_is_current(&replay)
    {
        fail(
            &mut replay,
            id,
            "notification Case or subscription ended before queueing".into(),
        );
        return false;
    }
    if job.sender.try_send(delivery).is_err() {
        fail(&mut replay, id, "notification delivery queue full".into());
    }
    true
}

fn fail(replay: &mut ReplayState, id: PushId, reason: String) {
    let case = match id {
        PushId::Inline(index) => replay.redis.pubsub.pushes[index].case_id.clone(),
        PushId::Indexed { .. } => None,
    };
    if case.is_some() {
        replay.redis.fail_pubsub_input(id, case.as_deref(), &reason);
        return;
    }
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
            target_observation_id: None,
            case_id: None,
            target,
            command: "PUBSUB_PUSH".into(),
            target_event_index: None,
            request_fingerprint: None,
            reason,
            diagnostic: None,
        });
}
