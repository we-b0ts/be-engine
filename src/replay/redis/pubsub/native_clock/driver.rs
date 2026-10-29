//! The live accepted namespace and current request epoch fence original input delivery.
use super::*;
use std::sync::Weak;
use tokio::time::{Duration, MissedTickBehavior};

struct Job {
    entry: usize,
    case: String,
    epoch: DateTime<Utc>,
    client: Uuid,
    sender: mpsc::Sender<Delivery>,
    source: Entry,
}

pub(in crate::replay) fn start(state: Arc<Mutex<ReplayState>>) {
    let weak = Arc::downgrade(&state);
    tokio::spawn(run(weak));
}

async fn run(weak: Weak<Mutex<ReplayState>>) {
    let mut interval = tokio::time::interval(Duration::from_millis(5));
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let Some(state) = weak.upgrade() else { return };
        let job = {
            let replay = state.lock().await;
            if replay.finalized_at.is_some()
                || replay.target_session_stopped
                || replay.redis.pubsub.native_clock.entries.is_empty()
            {
                return;
            }
            ready(&replay)
        };
        let Some(job) = job else { continue };
        let source = job.source.clone();
        let loaded = tokio::task::spawn_blocking(move || source.bytes()).await;
        let mut replay = state.lock().await;
        let slot = replay.redis.pubsub.native_clock.entries[job.entry].slot;
        if replay.finalized_at.is_some()
            || replay.target_session_stopped
            || replay.active_case_id.as_deref() != Some(&job.case)
            || replay.redis.pubsub.native_clock.epoch(&job.case) != Some(job.epoch)
            || replay
                .redis
                .pubsub
                .native_clock
                .live
                .get(&job.case)
                .is_none_or(|live| !live.observer || live.closed)
            || job
                .epoch
                .checked_add_signed(job.source.lifetime)
                .is_none_or(|end| Utc::now() >= end)
            || !replay.redis.pubsub.is_subscribed(job.client, slot)
            || !replay.redis.pubsub.push_available(slot)
        {
            continue;
        }
        let bytes = match loaded {
            Ok(Ok(bytes)) => bytes,
            _ => {
                fail(
                    &mut replay,
                    &job,
                    slot,
                    "native notification evidence unavailable",
                );
                continue;
            }
        };
        let entry = &replay.redis.pubsub.native_clock.entries[job.entry];
        let valid = parse_pubsub_push(&bytes)
            .ok()
            .flatten()
            .is_some_and(|frame| {
                rpc::notification_namespace(&frame.channel, &frame.payload).as_deref()
                    == Some(&entry.namespace)
                    && rpc::echo_digest(&frame.channel, &frame.payload) == Some(entry.digest)
            });
        if !valid {
            fail(
                &mut replay,
                &job,
                slot,
                "native notification identity changed",
            );
            continue;
        }
        replay
            .redis
            .pubsub
            .reserve_case_push(slot, &job.case, job.client);
        replay.redis.pubsub.native_clock.entries[job.entry].reserved = true;
        if job
            .sender
            .try_send(Delivery {
                push: slot,
                bytes,
                matched: None,
                case_id: Some(job.case.clone()),
                request_epoch: Some(job.epoch),
            })
            .is_err()
        {
            fail(
                &mut replay,
                &job,
                slot,
                "native notification delivery queue unavailable",
            );
        }
    }
}

fn ready(replay: &ReplayState) -> Option<Job> {
    let case = replay.active_case_id.as_deref()?;
    let native = &replay.redis.pubsub.native_clock;
    let live = native
        .live
        .get(case)
        .filter(|live| live.observer && !live.closed)?;
    let (index, entry) = native
        .entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.case == case && !entry.reserved)
        .min_by_key(|(_, entry)| (entry.offset, entry.ordinal))?;
    let now = Utc::now();
    if now < live.epoch.checked_add_signed(entry.offset)?
        || now >= live.epoch.checked_add_signed(entry.lifetime)?
        || !live.namespaces.contains(&entry.namespace)
    {
        return None;
    }
    let mut subscribers = replay.redis.pubsub.subscriptions.iter().filter(|sub| {
        !sub.sender.is_closed()
            && sub.target == entry.endpoint
            && sub.database == entry.database
            && sub.username == entry.username
            && (sub.source_connection, sub.sequence) == entry.anchor
            && replay.redis.pubsub.is_subscribed(sub.client, entry.slot)
    });
    let sub = subscribers.next()?;
    if subscribers.next().is_some() {
        return None;
    }
    Some(Job {
        entry: index,
        case: case.into(),
        epoch: live.epoch,
        client: sub.client,
        sender: sub.sender.clone(),
        source: entry.clone(),
    })
}

fn fail(replay: &mut ReplayState, job: &Job, slot: PushId, reason: &str) {
    replay.redis.pubsub.native_clock.entries[job.entry].reserved = true;
    replay
        .redis
        .fail_pubsub_input(slot, Some(&job.case), reason);
}
