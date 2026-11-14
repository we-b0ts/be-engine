//! Keep RESP moving while an independently observed close-tail publish waits
//! for its recorded room broadcasts. Effects are committed in Source order.
use super::*;

#[derive(Debug, Clone)]
pub(in crate::replay::redis) struct BroadcastWindow {
    namespace: String,
    pub(in crate::replay::redis) deadline: Instant,
}

pub(super) fn prove(
    state: &ReplayState,
    case: &str,
    first: usize,
    index: usize,
) -> Option<SerialPublish> {
    let (close, deadline) = state.input_timing.as_ref()?.heartbeat_close_window(case)?;
    if Instant::now() >= deadline {
        return None;
    }
    let redis = &state.protocols.redis;
    let later = &redis.exchanges[index];
    if !ordinary_publish(redis, later)
        || !later.status.is_available()
        || later.record.request_started_at?
            < close.checked_add_signed(chrono::TimeDelta::milliseconds(1))?
    {
        return None;
    }
    let message = socketio_rpc::broadcast("PUBLISH", &later.args).ok()??;
    let namespace = message.value["namespace"].as_str()?;
    if message.value["room"].as_str()?.is_empty() {
        return None;
    }
    let prefix = redis.candidates.lane_prefix(first, index, usize::MAX)?;
    let before_close = |slot: usize| {
        let prior = &redis.exchanges[slot];
        ordinary_publish(redis, prior)
            && prior.args.first() == later.args.first()
            && prior.record.timestamp.is_some_and(|at| at < close)
    };
    let is_pair = |a, b| {
        before_close(a)
            && before_close(b)
            && room_broadcast_pair(&redis.exchanges[a], &redis.exchanges[b])
                .is_some_and(|(_, _, message)| message["namespace"] != namespace)
    };
    let mut waits = Vec::new();
    let mut pending = prefix.as_slice();
    if before_close(first) {
        if let Some(&second) = prefix.get(1)
            && is_pair(first, second)
        {
            waits.extend([first, second]);
            pending = &prefix[2..];
        } else {
            let previous = redis.candidates.previous_lane_slot(first)?;
            if redis.exchange_status(previous) != Some(ReplayExchangeStatus::Consumed)
                || !is_pair(previous, first)
            {
                return None;
            }
            waits.push(first);
            pending = &prefix[1..];
        }
        if waits.iter().any(|&slot| {
            !matches!(redis.exchange_status(slot), Some(status) if status.is_available()
                || matches!(status, ReplayExchangeStatus::Responding | ReplayExchangeStatus::Consumed))
        }) {
            return None;
        }
    }

    let mut last_pending = None;
    for &slot in pending {
        let prior = &redis.exchanges[slot];
        match redis.exchange_status(slot)? {
            ReplayExchangeStatus::Consumed => {}
            ReplayExchangeStatus::Responding
                if prior.serial_broadcast.as_ref().is_some_and(|window| {
                    window.namespace == namespace && window.deadline == deadline
                }) =>
            {
                last_pending = Some(slot);
            }
            _ => return None,
        }
    }
    if let Some(slot) = last_pending {
        // The previous pending publish already waits for every earlier slot.
        waits = vec![slot];
    }
    if waits.is_empty() {
        return None;
    }
    Some(SerialPublish {
        index,
        predecessors: waits.into(),
        first_blocker: first,
        broadcast: Some(BroadcastWindow {
            namespace: namespace.into(),
            deadline,
        }),
    })
}

fn ordinary_publish(redis: &RedisReplayState, exchange: &ReplayExchange) -> bool {
    exchange.record.command == "PUBLISH"
        && lane::is_ordinary(exchange)
        && !redis.connection_scopes.is_stateful(exchange)
        && exchange.record.response_kind == "integer"
        && !exchange.record.lifecycle_cleanup
}
