//! Redis exchange and connection event projection.
use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) async fn record_exchange(
    state: &AppState,
    connection_id: Uuid,
    context: &ConnectionContext,
    mut pending: PendingRedisExchange,
    response_kind: RedisFrameKind,
    response: &[u8],
    outcome: DependencyExchangeOutcome,
    max_frame_bytes: usize,
) -> Result<()> {
    let subscription_replay_safe = if outcome.is_client_terminated()
        || outcome.is_server_terminated()
    {
        true
    } else if is_pubsub_command(&pending.command.name) && pending.session.resp_version != 2 {
        pending
            .warnings
            .push("Redis Pub/Sub replay requires RESP2".to_string());
        false
    } else if is_pubsub_command(&pending.command.name) {
        match response_kind {
            RedisFrameKind::Error => true,
            RedisFrameKind::Array => {
                if let Err(error) = validate_subscription_confirmation(&pending.command, response) {
                    pending.warnings.push(format!(
                        "Redis {} confirmation is unsafe for replay: {error}",
                        pending.command.name
                    ));
                    false
                } else {
                    true
                }
            }
            _ => {
                pending.warnings.push(format!(
                    "Redis {} did not receive a supported subscription confirmation",
                    pending.command.name
                ));
                false
            }
        }
    } else {
        true
    };
    let args = pending
        .recorded_args
        .iter()
        .map(|value| capture_body(value, max_frame_bytes))
        .collect::<Vec<_>>();
    let response = capture_body(response, max_frame_bytes);
    let terminal_quit = is_terminal_quit(&pending.command);
    let replay_safe = pending.replay_safe
        && subscription_replay_safe
        && !response.truncated
        && args.iter().all(|argument| !argument.truncated)
        && (response_kind != RedisFrameKind::Other
            || outcome.is_client_terminated()
            || outcome.is_server_terminated()
            || terminal_quit);
    let confirmed_subscription = replay_safe
        && matches!(
            pending.command.name.as_str(),
            "SUBSCRIBE" | "PSUBSCRIBE" | "SSUBSCRIBE"
        )
        && response_kind == RedisFrameKind::Array
        && outcome == DependencyExchangeOutcome::Response;
    let rpc_callback_capture =
        crate::redis::socketio_rpc::request(&pending.command.name, &pending.command.args)
            .ok()
            .flatten()
            .map(|_| "bounded_window".to_owned());
    let event = RecorderEvent::RedisExchange(RedisExchangeEvent {
        id: Uuid::new_v4(),
        connection_id,
        sequence: pending.sequence,
        timestamp: Utc::now(),
        request_started_at: pending.request_started_at,
        client_addr: context.client_addr.clone(),
        target_host: context.target_host.clone(),
        target_port: context.target_port,
        target_addr: context.target_addr.clone(),
        upstream_addr: context.upstream_addr.clone(),
        resp_version: pending.session.resp_version,
        database: pending.session.database,
        username: pending.session.username,
        command: pending.command.name,
        args,
        response_kind: response_kind.as_str().to_string(),
        response,
        rpc_callback_capture,
        cache_snapshot_rule: pending.cache_snapshot_rule,
        cache_snapshot_hit: pending.cache_snapshot_hit,
        session_setup: pending.session_setup,
        outcome,
        duration_ms: pending
            .ended_at
            .unwrap_or_else(Instant::now)
            .saturating_duration_since(pending.started)
            .as_millis(),
        replay_safe,
        parse_warnings: pending.warnings,
    });
    if confirmed_subscription {
        pubsub::record_subscription(state, event, pending.targets).await?;
    } else {
        state.record_event_for_targets(event, pending.targets);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn record_connection(
    state: &AppState,
    id: Uuid,
    context: &ConnectionContext,
    phase: &str,
    session: &RedisSession,
    duration_ms: Option<u128>,
    client_to_server_bytes: u64,
    server_to_client_bytes: u64,
    replay_safe: bool,
    error: Option<String>,
) -> Result<()> {
    record_event(
        state,
        RecorderEvent::RedisConnection(RedisConnectionEvent {
            id,
            timestamp: Utc::now(),
            phase: phase.to_string(),
            client_addr: context.client_addr.clone(),
            target_host: context.target_host.clone(),
            target_port: context.target_port,
            target_addr: context.target_addr.clone(),
            upstream_addr: context.upstream_addr.clone(),
            resp_version: session.resp_version,
            database: session.database,
            username: session.username.clone(),
            duration_ms,
            client_to_server_bytes,
            server_to_client_bytes,
            replay_safe,
            error,
        }),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn record_termination(
    state: &AppState,
    connection_id: Uuid,
    context: &ConnectionContext,
    mut exchange: PendingRedisExchange,
    response: &[u8],
    termination: &ConnectionTermination,
    healthy: bool,
    max_frame_bytes: usize,
) -> Result<bool> {
    if let Some(key) = exchange.cache_snapshot_key.take() {
        state
            .abort_cache_snapshot(&key, "Redis snapshot fill ended before a response")
            .await;
    }
    let terminal = termination.outcome_since(exchange.started);
    let clean_quit = is_terminal_quit(&exchange.command) && healthy;
    let prefix_timing_known =
        response.is_empty() || terminal.is_some_and(|(outcome, _)| outcome.is_server_terminated());
    let complete = healthy && prefix_timing_known && (terminal.is_some() || clean_quit);
    exchange.replay_safe &= complete;
    if !complete {
        exchange.warnings.push(if termination.engine_stopped() {
            "engine cleanup interrupted Redis capture".to_string()
        } else if !prefix_timing_known {
            "Redis client termination with response prefix lacks delivery timing; multi-stage half-close replay is unsupported".to_string()
        } else {
            "connection closed before Redis response".to_string()
        });
    }
    exchange.ended_at = termination.snapshot().map(|observed| observed.at);
    let outcome = if clean_quit {
        DependencyExchangeOutcome::NoResponse
    } else {
        terminal.map_or(DependencyExchangeOutcome::Response, |(outcome, _)| outcome)
    };
    record_exchange(
        state,
        connection_id,
        context,
        exchange,
        RedisFrameKind::Other,
        response,
        outcome,
        max_frame_bytes,
    )
    .await?;
    Ok(complete)
}
