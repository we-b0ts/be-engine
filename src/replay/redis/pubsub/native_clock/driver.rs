//! The live accepted namespace and current request epoch fence original input delivery.
use super::*;
use std::sync::Weak;
use tokio::time::{Duration, Instant, sleep_until};

struct Job {
    entry: usize,
    case: String,
    epoch: DateTime<Utc>,
    client: Uuid,
    sender: mpsc::Sender<Delivery>,
    permit: mpsc::OwnedPermit<Delivery>,
    source: Entry,
    paced_dispatch: bool,
}

pub(in crate::replay) fn start(state: Arc<Mutex<ReplayState>>) {
    let weak = Arc::downgrade(&state);
    tokio::spawn(run(weak));
}

async fn run(weak: Weak<Mutex<ReplayState>>) {
    loop {
        let Some(state) = weak.upgrade() else { return };
        let (job, progress, retry) = {
            let replay = state.lock().await;
            if replay.finalized_at.is_some()
                || replay.target_session_stopped
                || replay.redis.pubsub.native_clock.entries.is_empty()
            {
                return;
            }
            let now = Instant::now();
            let dispatch_due = dispatch_deadline(&replay, now);
            let retry = replay
                .active_case_id
                .as_deref()
                .and_then(|case| replay.redis.pubsub.native_clock.fast_deadline(case))
                .or(dispatch_due)
                .filter(|due| *due > now)
                .unwrap_or(now + Duration::from_millis(5));
            (
                ready(&replay, dispatch_due, now),
                replay.redis.lifecycle.subscribe(),
                retry,
            )
        };
        let Some(job) = job else {
            drop(state);
            tokio::select! {
                _ = progress.changed() => {}
                _ = sleep_until(retry) => {}
            }
            continue;
        };
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
            || expired(&replay, &job.case, job.epoch, job.source.lifetime)
            || job.sender.is_closed()
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
        let native = &mut replay.redis.pubsub.native_clock;
        if let Some(live) = native.live.get_mut(&job.case) {
            if let Some(pace) = &mut live.fast {
                pace.queued(job.entry);
            } else if job.paced_dispatch {
                live.dispatch_pace.inflight = Some(job.entry);
            }
        }
        native.retire(job.entry);
        job.permit.send(Delivery {
            push: slot,
            bytes,
            matched: None,
            case_id: Some(job.case),
            request_epoch: Some(job.epoch),
            value: None,
        });
    }
}

fn dispatch_deadline(replay: &ReplayState, now: Instant) -> Option<Instant> {
    let case = replay.active_case_id.as_deref()?;
    let native = &replay.redis.pubsub.native_clock;
    let live = native.live.get(case)?;
    if live.fast.is_some() || live.dispatch_pace.inflight.is_some() {
        return None;
    }
    let entry = &native.entries[*native.pending.get(case)?.front()?];
    let cap = replay.input_timing.as_ref()?.native_dispatch_cap(
        replay,
        case,
        live.epoch,
        entry.offset,
    )?;
    Some(
        live.dispatch_pace
            .deadline(entry, &native.entries, cap, now),
    )
}

fn ready(replay: &ReplayState, dispatch_due: Option<Instant>, now: Instant) -> Option<Job> {
    let case = replay.active_case_id.as_deref()?;
    let native = &replay.redis.pubsub.native_clock;
    let live = native
        .live
        .get(case)
        .filter(|live| live.observer && !live.closed)?;
    let index = *native.pending.get(case)?.front()?;
    let entry = &native.entries[index];
    let recorded_due = || reached(replay, case, live.epoch, entry.offset);
    let due = live.fast.as_ref().map_or_else(
        || dispatch_due.is_some_and(|due| now >= due) || recorded_due(),
        |pace| {
            (index < pace.first
                || replay
                    .input_timing
                    .as_ref()
                    .is_some_and(|timeline| timeline.native_fast_setup_ready(replay)))
                && pace.ready(index, &native.entries, recorded_due)
        },
    );
    if !due
        || live.dispatch_pace.inflight.is_some()
        || expired(replay, case, live.epoch, entry.lifetime)
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
        paced_dispatch: dispatch_due.is_some(),
    })
}

fn expired(
    replay: &ReplayState,
    case: &str,
    epoch: DateTime<Utc>,
    lifetime: chrono::TimeDelta,
) -> bool {
    replay
        .redis
        .pubsub
        .native_clock
        .live
        .get(case)
        .is_none_or(|live| live.fast.is_none())
        && reached(replay, case, epoch, lifetime)
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
