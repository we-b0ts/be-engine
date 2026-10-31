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
    permit: mpsc::OwnedPermit<Delivery>,
    source: Entry,
}

pub(in crate::replay) fn start(state: Arc<Mutex<ReplayState>>) {
    let weak = Arc::downgrade(&state);
    tokio::spawn(run(weak));
}

async fn run(weak: Weak<Mutex<ReplayState>>) {
    let mut interval = tokio::time::interval(Duration::from_millis(5));
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut blocked = true;
    loop {
        // Poll only while the next original input is not yet admissible. Ready
        // inputs drain at actual I/O speed rather than a 200-message/s ceiling.
        if blocked {
            interval.tick().await;
        }
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
        let Some(job) = job else {
            blocked = true;
            continue;
        };
        blocked = false;
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
            || reached(&replay, &job.case, job.epoch, job.source.lifetime)
            || job.sender.is_closed()
            || !replay.redis.pubsub.is_subscribed(job.client, slot)
            || !replay.redis.pubsub.push_available(slot)
        {
            blocked = true;
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
        replay.redis.pubsub.native_clock.retire(job.entry);
        job.permit.send(Delivery {
            push: slot,
            bytes,
            matched: None,
            case_id: Some(job.case),
            request_epoch: Some(job.epoch),
        });
    }
}

fn ready(replay: &ReplayState) -> Option<Job> {
    let case = replay.active_case_id.as_deref()?;
    let native = &replay.redis.pubsub.native_clock;
    let live = native
        .live
        .get(case)
        .filter(|live| live.observer && !live.closed)?;
    let index = *native.pending.get(case)?.front()?;
    let entry = &native.entries[index];
    if !reached(replay, case, live.epoch, entry.offset)
        || reached(replay, case, live.epoch, entry.lifetime)
        || !live.namespaces.contains(&entry.namespace)
        || !entry
            .inputs_before
            .iter()
            .all(|sequence| live.acknowledged.contains(sequence))
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
    // Reserve bounded queue capacity before materializing Source bytes. Full
    // queues apply backpressure; they are not failed delivery observations.
    let permit = sub.sender.clone().try_reserve_owned().ok()?;
    Some(Job {
        entry: index,
        case: case.into(),
        epoch: live.epoch,
        client: sub.client,
        sender: sub.sender.clone(),
        permit,
        source: entry.clone(),
    })
}

fn reached(
    replay: &ReplayState,
    case: &str,
    epoch: DateTime<Utc>,
    offset: chrono::TimeDelta,
) -> bool {
    replay
        .input_timing
        .as_ref()
        .and_then(|timeline| timeline.reached(case, epoch, offset))
        .unwrap_or_else(|| {
            epoch
                .checked_add_signed(offset)
                .is_none_or(|due| Utc::now() >= due)
        })
}

fn fail(replay: &mut ReplayState, job: &Job, slot: PushId, reason: &str) {
    replay.redis.pubsub.native_clock.retire(job.entry);
    replay
        .redis
        .fail_pubsub_input(slot, Some(&job.case), reason);
}
