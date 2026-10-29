//! One replay-owned driver delivers proven ingress after its live session exists.
use super::*;
use std::sync::Weak;
use tokio::time::{Duration, MissedTickBehavior};

struct Job {
    index: usize,
    case: String,
    sid: String,
    client: Uuid,
    sender: mpsc::Sender<Delivery>,
    frame: Frame,
    started: DateTime<Utc>,
}

pub(in crate::replay) fn start(state: Arc<Mutex<ReplayState>>) {
    let weak = Arc::downgrade(&state);
    tokio::spawn(run(weak));
}

async fn run(weak: Weak<Mutex<ReplayState>>) {
    let mut interval = tokio::time::interval(Duration::from_millis(10));
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let Some(state) = weak.upgrade() else { return };
        let job = {
            let mut replay = state.lock().await;
            if replay.finalized_at.is_some()
                || replay.target_session_stopped
                || replay.redis.pubsub.ingress.entries.is_empty()
            {
                return;
            }
            match ready(&replay) {
                Ok(job) => job,
                Err(index) => {
                    fail(
                        &mut replay,
                        index,
                        "remote Socket.IO session identity is unavailable",
                    );
                    None
                }
            }
        };
        let Some(job) = job else { continue };
        let frame = job.frame.clone();
        let bytes = tokio::task::spawn_blocking(move || frame.bytes()).await;
        let mut replay = state.lock().await;
        if replay.finalized_at.is_some()
            || replay.target_session_stopped
            || replay.active_case_id.as_deref() != Some(&job.case)
            || replay
                .redis
                .request_contracts
                .request_times(&job.case)
                .target
                != Some(job.started)
            || !replay.redis.pubsub.is_subscribed(
                job.client,
                replay.redis.pubsub.ingress.entries[job.index].slot,
            )
        {
            continue;
        }
        let bytes = match bytes {
            Ok(Ok(raw)) => render(
                &raw,
                &replay.redis.pubsub.ingress.entries[job.index],
                &job.sid,
            ),
            _ => Err(anyhow!("notification evidence unavailable")),
        };
        let bytes = match bytes {
            Ok(bytes) => bytes,
            Err(_) => {
                fail(
                    &mut replay,
                    job.index,
                    "remote Socket.IO request materialization failed",
                );
                continue;
            }
        };
        let slot = replay.redis.pubsub.ingress.entries[job.index].slot;
        if !replay.redis.pubsub.push_available(slot) {
            continue;
        }
        replay
            .redis
            .pubsub
            .reserve_case_push(slot, &job.case, job.client);
        let entry = &mut replay.redis.pubsub.ingress.entries[job.index];
        entry.reserved = true;
        entry.target_sid = Some(job.sid);
        if job
            .sender
            .try_send(Delivery {
                push: slot,
                bytes,
                matched: None,
                case_id: Some(job.case),
                request_epoch: Some(job.started),
            })
            .is_err()
        {
            fail(
                &mut replay,
                job.index,
                "remote Socket.IO request delivery queue full",
            );
        }
    }
}

fn ready(replay: &ReplayState) -> std::result::Result<Option<Job>, usize> {
    let Some(case) = replay.active_case_id.as_deref() else {
        return Ok(None);
    };
    let contracts = &replay.redis.request_contracts;
    let Some(started) = contracts.request_times(case).target else {
        return Ok(None);
    };
    if let Some((index, entry)) = replay
        .redis
        .pubsub
        .ingress
        .entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| !entry.reserved && entry.case == case)
        .min_by_key(|(_, entry)| (entry.offset, entry.ordinal))
    {
        let due = started.checked_add_signed(entry.offset).ok_or(index)?;
        if Utc::now() < due {
            return Ok(None);
        }
        if !replay
            .redis
            .pubsub
            .ingress
            .causal_ready(entry, started, &replay.redis.exchanges)
        {
            return Ok(None);
        }
        let Some(sid) = contracts
            .observed_identity_string(case, &entry.source.sid)
            .map_err(|_| index)?
        else {
            return Ok(None);
        };
        let mut subscriptions = replay.redis.pubsub.subscriptions.iter().filter(|sub| {
            !sub.sender.is_closed()
                && sub.target == entry.endpoint
                && (sub.source_connection, sub.sequence) == entry.anchor
                && replay.redis.pubsub.is_subscribed(sub.client, entry.slot)
        });
        let Some(sub) = subscriptions.next() else {
            return Ok(None);
        };
        if subscriptions.next().is_some() {
            return Err(index);
        }
        return Ok(Some(Job {
            index,
            case: case.into(),
            sid,
            client: sub.client,
            sender: sub.sender.clone(),
            frame: entry.frame.clone(),
            started,
        }));
    }
    Ok(None)
}

fn render(raw: &[u8], entry: &Entry, sid: &str) -> Result<Vec<u8>> {
    ensure!(
        !sid.is_empty() && sid.len() <= 1024,
        "invalid observed RPC session identity"
    );
    let frame = parse_pubsub_push(raw)?.context("ingress is not a Pub/Sub frame")?;
    let mut request = rpc::request("PUBLISH", &[frame.channel.clone(), frame.payload])?
        .context("ingress is not a native RPC request")?;
    ensure!(
        frame.channel == entry.channel && request.identity == entry.source,
        "ingress identity changed"
    );
    request.value["room"] = sid.into();
    request.value["callback"][0] = sid.into();
    let mut frame =
        redis_command(&bytes::Bytes::copy_from_slice(raw)).context("invalid Pub/Sub command")?;
    *frame.args.last_mut().context("missing Pub/Sub payload")? =
        serde_json::to_vec(&request.value)?;
    let name = frame.name.to_ascii_lowercase();
    let mut values = vec![name.as_bytes()];
    values.extend(frame.args.iter().map(Vec::as_slice));
    Ok(crate::redis::encode_array(&values))
}

fn fail(replay: &mut ReplayState, index: usize, reason: &str) {
    let entry = &mut replay.redis.pubsub.ingress.entries[index];
    entry.reserved = true;
    entry.target_sid = None;
    let case_id = entry.case.clone();
    let push = entry.slot;
    replay.redis.fail_pubsub_input(push, Some(&case_id), reason);
}
