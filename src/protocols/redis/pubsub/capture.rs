//! Generic RESP push evidence and writer admission.
use super::super::{ConnectionContext, rpc};
use crate::active_case::DependencyTargets;
use crate::protocols::recording::events::RedisPubSubPushEvent;
use crate::redis::RedisPubSubPush;
use crate::{AppState, protocols::recording::events::RecorderEvent, recorder::capture_body};
use anyhow::Result;
use bytes::Bytes;
use chrono::Utc;
use traffic_protocol::connection::NativeFuture;
use traffic_protocol_redis::capture::CaptureSessionState as RedisSession;
use traffic_protocol_redis::capture::connection::CapturedPush as NativeCapturedPush;
use uuid::Uuid;

pub(in crate::protocols::redis) struct CapturedPush {
    state: AppState,
    event: RedisPubSubPushEvent,
    targets: DependencyTargets,
}

impl NativeCapturedPush for CapturedPush {
    fn record(self: Box<Self>) -> NativeFuture<'static, ()> {
        Box::pin(async move {
            let event = RecorderEvent::RedisPubSubPush(self.event);
            self.state.record_event_for_targets(event, self.targets);
            Ok(())
        })
    }
}

#[allow(clippy::too_many_arguments)]
pub(in crate::protocols::redis) fn capture(
    state: &AppState,
    context: &ConnectionContext,
    session: &RedisSession,
    connection_id: Uuid,
    push: &RedisPubSubPush,
    bytes: Bytes,
    subscription_sequence: u64,
    elapsed_ms: u64,
) -> Result<CapturedPush> {
    let pending = rpc::take(state, context, push);
    let (reference, targets, duration_ms) = match pending {
        Some((reference, targets, elapsed)) => (
            Some(reference),
            targets.unwrap_or_else(|| state.inner.active_cases.unattributed_observation_targets()),
            elapsed,
        ),
        // Ordinary received inputs use the same admission window as other
        // dependencies. Explicit process rules still take priority at enqueue.
        // A correlated late RPC reply above must retain its original owner.
        None => (
            None,
            state
                .inner
                .active_cases
                .current_targets_for_request_with_tail(false),
            elapsed_ms,
        ),
    };
    let response = capture_body(&bytes, state.config().recording.max_body_bytes);
    Ok(CapturedPush {
        event: RedisPubSubPushEvent {
            timestamp: Utc::now(),
            target_host: context.target_host.clone(),
            target_port: context.target_port,
            database: session.database,
            username: session.username.clone(),
            connection_id,
            subscription_sequence,
            rpc_request: reference,
            replay_safe: session.resp_version == 2 && !response.truncated,
            response,
            duration_ms,
        },
        state: state.clone(),
        targets,
    })
}
