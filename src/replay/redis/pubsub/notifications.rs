//! A subscription owns one ordered timer and at most one materialized notification.
use super::*;
use crate::dependency_index::{Paged, RecordRef, RecordSource};
use inventory::NotificationEntry;
use std::sync::Weak;
use tokio::sync::watch;
use tokio::time::{Duration, Instant, sleep_until};

type IndexedJob = (usize, Paged<NotificationEntry>, Arc<RecordSource>);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Progress {
    Skipped,
    Queued,
    Ended,
}

pub(super) fn fast_gap_ms(previous: u64, current: u64, cap_ms: u64) -> u64 {
    current.saturating_sub(previous).min(cap_ms)
}

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
                    if deliver(
                        &weak,
                        &mut job,
                        id,
                        entry.duration_ms,
                        entry.adapter_echo,
                        entry.adapter_namespace,
                        Some(source.reference(entry.location)),
                        started,
                        false,
                    )
                    .await
                        == Progress::Ended
                    {
                        return;
                    }
                }
            }
        } else {
            let indices = job.indices.clone();
            let mut previous_offset = 0;
            for &index in indices.iter() {
                let Some(state) = weak.upgrade() else {
                    return;
                };
                let (offset, fast, cap_ms) = {
                    let replay = state.lock().await;
                    let push = &replay.redis.pubsub.pushes[index];
                    (
                        push.record.duration_ms,
                        replay.stream_timing == Some(crate::replay::ReplayStreamTiming::Fast)
                            && push.source == ReplaySource::Case
                            && push.record.rpc_request.is_none(),
                        replay.stream_interval_cap_ms,
                    )
                };
                let (delay, anchor) = if fast {
                    (fast_gap_ms(previous_offset, offset, cap_ms), Instant::now())
                } else {
                    (offset, started)
                };
                previous_offset = offset;
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
                let id = PushId::Inline(index);
                let progress = deliver(
                    &weak, &mut job, id, delay, digest, namespace, None, anchor, fast,
                )
                .await;
                if progress == Progress::Ended
                    || fast
                        && progress == Progress::Queued
                        && !wait_delivered(&state, &mut job, id).await
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
    fast: bool,
) -> Progress {
    if let Some(state) = weak.upgrade()
        && state.lock().await.redis.pubsub.timer_is_correlated(
            id,
            adapter_echo,
            adapter_namespace.as_deref(),
        )
    {
        return Progress::Skipped;
    }
    tokio::select! {
        _ = sleep_until(started + Duration::from_millis(delay)) => {}
        _ = job.cancelled.changed() => { return Progress::Ended; }
        _ = job.sender.closed() => { return Progress::Ended; }
    }
    let Some(state) = weak.upgrade() else {
        return Progress::Ended;
    };
    let (reference, inline, case_id, request_epoch) = {
        let replay = state.lock().await;
        if replay.finalized_at.is_some() || !replay.redis.pubsub.is_subscribed(job.client, id) {
            return Progress::Ended;
        }
        if replay
            .redis
            .pubsub
            .timer_is_correlated(id, adapter_echo, adapter_namespace.as_deref())
        {
            return Progress::Skipped;
        }
        match id {
            PushId::Inline(index) => {
                let push = &replay.redis.pubsub.pushes[index];
                if !push.status.is_available() {
                    return Progress::Skipped;
                }
                let case = push.case_id.clone();
                let reference = push.evidence.clone();
                let raw = push.raw.clone();
                let epoch = if let Some(case) = &case {
                    if replay.active_case_id.as_ref() != Some(case) || replay.target_session_stopped
                    {
                        return Progress::Skipped;
                    }
                    replay.redis.request_contracts.request_times(case).target
                } else {
                    None
                };
                (reference, raw, case, epoch)
            }
            PushId::Indexed { lane, index } => {
                if !replay.redis.pubsub.indexed.available(lane, index) {
                    return Progress::Skipped;
                }
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
            return Progress::Ended;
        }
    };
    let mut delivery = Delivery {
        case_id,
        push: id,
        bytes,
        matched: None,
        request_epoch,
        value: None,
    };
    {
        let mut replay = state.lock().await;
        match super::value_delivery::prepare(&mut replay, &delivery) {
            Ok(value) => delivery.value = value,
            Err(_) => {
                fail(
                    &mut replay,
                    id,
                    "notification value preparation failed".into(),
                );
                return Progress::Ended;
            }
        }
    }
    if !wait_predecessors(&state, job, &delivery).await {
        return Progress::Ended;
    }
    // Queue pressure is transport progress, not a dependency mismatch. Never
    // hold ReplayState while awaiting space, and keep cancellation runnable.
    let permit = if fast {
        let sender = job.sender.clone();
        let permit = tokio::select! {
            result = sender.reserve_owned() => result.ok(),
            _ = job.cancelled.changed() => None,
        };
        let Some(permit) = permit else {
            let mut replay = state.lock().await;
            fail(
                &mut replay,
                id,
                "notification delivery ended before queueing".into(),
            );
            return Progress::Ended;
        };
        Some(permit)
    } else {
        None
    };
    let mut replay = state.lock().await;
    if replay.finalized_at.is_some()
        || !replay.redis.pubsub.is_subscribed(job.client, id)
        || !delivery.case_is_current(&replay)
    {
        fail(
            &mut replay,
            id,
            "notification Case or subscription ended before queueing".into(),
        );
        return Progress::Ended;
    }
    if !replay.redis.pubsub.push_available(id) {
        return Progress::Skipped;
    }
    if let Some(case) = &delivery.case_id {
        replay.redis.pubsub.reserve_case_push(id, case, job.client);
    } else {
        replay.redis.pubsub.reserve_push(id);
    }
    if let Some(permit) = permit {
        permit.send(delivery);
    } else if job.sender.try_send(delivery).is_err() {
        fail(&mut replay, id, "notification delivery queue full".into());
        return Progress::Ended;
    }
    Progress::Queued
}

async fn wait_predecessors(
    state: &Arc<Mutex<ReplayState>>,
    job: &mut NotificationJob,
    delivery: &Delivery,
) -> bool {
    loop {
        let wait = {
            let mut replay = state.lock().await;
            if replay.finalized_at.is_some()
                || !delivery.case_is_current(&replay)
                || !replay.redis.pubsub.is_subscribed(job.client, delivery.push)
                || !replay.redis.pubsub.push_available(delivery.push)
            {
                return false;
            }
            match super::value_delivery::ready(&replay, delivery) {
                Ok(true) => return true,
                Ok(false) => replay.redis.lifecycle.subscribe(),
                Err(_) => {
                    fail(
                        &mut replay,
                        delivery.push,
                        "notification identity predecessor failed".into(),
                    );
                    return false;
                }
            }
        };
        // Pending causal inputs are not started I/O. The subscriber remains
        // free to receive commands/EOF, and cancellation owns the unclaimed tail.
        tokio::select! {
            _ = wait.changed() => {},
            _ = job.cancelled.changed() => return false,
            _ = job.sender.closed() => return false,
        }
    }
}

async fn wait_delivered(
    state: &Arc<Mutex<ReplayState>>,
    job: &mut NotificationJob,
    id: PushId,
) -> bool {
    loop {
        let wait = {
            let replay = state.lock().await;
            let status = match id {
                PushId::Inline(index) => replay.redis.pubsub.pushes[index].status,
                PushId::Indexed { .. } => return false,
            };
            if status == ReplayExchangeStatus::Consumed {
                return true;
            }
            if status != ReplayExchangeStatus::Responding
                || replay.finalized_at.is_some()
                || !replay.redis.pubsub.is_subscribed(job.client, id)
            {
                return false;
            }
            // Register under the ownership mutex before releasing it. A very
            // fast actual write cannot complete between this check and wait.
            replay.redis.lifecycle.subscribe()
        };
        tokio::select! {
            _ = wait.changed() => {}
            _ = job.cancelled.changed() => return false,
            _ = job.sender.closed() => return false,
        }
    }
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
