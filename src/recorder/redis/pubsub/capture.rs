//! Generic RESP push evidence and writer admission.
use super::super::*;
use crate::active_case::DependencyTargets;
use crate::recorder::RedisPubSubPushEvent;
use crate::redis::RedisPubSubPush;

pub(in crate::recorder::redis) struct CapturedPush {
    pub bytes: Bytes,
    event: RedisPubSubPushEvent,
    targets: Option<DependencyTargets>,
}

impl CapturedPush {
    pub async fn record(self, state: &AppState) -> Result<()> {
        let event = RecorderEvent::RedisPubSubPush(self.event);
        if let Some(targets) = self.targets {
            state.record_event_for_targets(event, targets);
        } else {
            // Uncorrelated notifications are process evidence, not attributed to
            // whichever HTTP request happens to be active when they arrive.
            state.recorder().record(event.clone()).await?;
            state
                .recorder()
                .append_global_dependency(
                    &event,
                    "pubsub_notification",
                    "runtime",
                    "confirmed_subscription",
                )
                .await?;
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub(in crate::recorder::redis) fn capture(
    state: &AppState,
    context: &ConnectionContext,
    session: &RedisSession,
    connection_id: Uuid,
    push: &RedisPubSubPush,
    bytes: Bytes,
    subscription_sequence: u64,
    elapsed_ms: u64,
) -> Result<CapturedPush> {
    let pending = super::super::rpc::take(state, context, push);
    let (reference, targets, duration_ms) = match pending {
        Some((reference, targets, elapsed)) => (Some(reference), Some(targets), elapsed),
        None => (None, None, elapsed_ms),
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
        bytes,
        targets,
    })
}
