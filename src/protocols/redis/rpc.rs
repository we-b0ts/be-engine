//! RPC attribution is separate from generic RESP Pub/Sub capture.
use super::ConnectionContext;
use crate::AppState;
use crate::active_case::DependencyTargets;
use crate::protocols::recording::events::RedisRpcRequestRef;
use crate::redis::{RedisPubSubPush, socketio_rpc as rpc};
use anyhow::Result;
use std::collections::HashMap;
use std::{sync::Arc, time::Instant};
use traffic_protocol_redis::RedisCommand;
use uuid::Uuid;

type Key = (String, u16, Vec<u8>, rpc::Identity);

#[derive(Default)]
pub(crate) struct CaptureState {
    pending: HashMap<Key, Pending>,
    cleaner_started: bool,
}

struct Pending {
    reference: RedisRpcRequestRef,
    targets: DependencyTargets,
    started: Instant,
}

fn key(context: &ConnectionContext, channel: Vec<u8>, identity: rpc::Identity) -> Key {
    (
        context
            .target_host
            .trim_end_matches('.')
            .to_ascii_lowercase(),
        context.target_port,
        channel,
        identity,
    )
}

pub(super) fn observe(
    state: &AppState,
    context: &ConnectionContext,
    targets: &DependencyTargets,
    command: &RedisCommand,
    connection_id: Uuid,
    sequence: u64,
) -> Result<()> {
    let Some(request) = rpc::request(&command.name, &command.args)? else {
        return Ok(());
    };
    let key = key(context, command.args[0].clone(), request.identity);
    let registry = state
        .recorder()
        .extensions
        .get::<std::sync::Mutex<CaptureState>>();
    let mut captures = registry.lock().expect("Redis RPC captures");
    anyhow::ensure!(
        captures.pending.len() < 4096,
        "Redis RPC capture limit exceeded"
    );
    anyhow::ensure!(
        !captures.pending.contains_key(&key),
        "duplicate outstanding Redis RPC identity"
    );
    captures.pending.insert(
        key.clone(),
        Pending {
            reference: RedisRpcRequestRef {
                connection_id,
                sequence,
                case_id: targets.cases.first().map(|(case, _)| case.id),
            },
            // Callback correlation outlives the completed PUBLISH command. Keep
            // its identity without holding dependency drain open until expiry.
            targets: targets.attribution_only(),
            started: Instant::now(),
        },
    );
    if !captures.cleaner_started {
        captures.cleaner_started = true;
        let registry = registry.clone();
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                timer.tick().await;
                if Arc::strong_count(&registry) == 1 {
                    break;
                }
                registry
                    .lock()
                    .expect("Redis RPC captures")
                    .pending
                    .retain(|_, p| p.started.elapsed().as_secs() < 610);
            }
        });
    }
    drop(captures);
    Ok(())
}

pub(in crate::protocols::redis) fn take(
    state: &AppState,
    context: &ConnectionContext,
    push: &RedisPubSubPush,
) -> Option<(RedisRpcRequestRef, Option<DependencyTargets>, u64)> {
    let registry = state
        .recorder()
        .extensions
        .get::<std::sync::Mutex<CaptureState>>();
    if registry
        .lock()
        .expect("Redis RPC captures")
        .pending
        .is_empty()
    {
        return None;
    }
    let (identity, _) = rpc::callback(&push.payload).ok().flatten()?;
    let pending = registry
        .lock()
        .expect("Redis RPC captures")
        .pending
        .remove(&key(context, push.channel.clone(), identity))?;
    Some((
        pending.reference,
        state.inner.active_cases.reacquire_targets(&pending.targets),
        pending.started.elapsed().as_millis() as u64,
    ))
}
