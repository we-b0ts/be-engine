//! Redis response delivery and transport termination verification.
use super::*;
use crate::ReplayStreamTiming;
use crate::dependency::termination::ConnectionControl;
use crate::replay::admission::{DeliveryGuard, WaitOutcome};
use chrono::{DateTime, Utc};
use tokio::io::AsyncReadExt;

pub(super) async fn deliver_redis_exchange(
    reader: &mut RedisBufferedReader<&mut TcpStream>,
    state: &Arc<Mutex<ReplayState>>,
    matched: &MatchedRedisExchange,
    control: &ConnectionControl,
    started: tokio::time::Instant,
    client_id: Uuid,
) -> Result<bool> {
    let claim_guard = match &matched.claim {
        Claim::Finite(ticket) => Some(ticket.guard()),
        Claim::Native(_) => None,
    };
    let (lifecycle, timing_scope, fast, serial_predecessors) = {
        let state = state.lock().await;
        let exchange = &state.redis.exchanges[matched.index];
        (
            exchange.record.lifecycle_cleanup,
            super::input_timing::scope(&state),
            state.stream_timing == Some(ReplayStreamTiming::Fast),
            exchange.serial_predecessors.clone(),
        )
    };
    if lifecycle {
        match super::lifecycle::deliver(reader, state, matched, client_id).await {
            Ok(()) => {
                state.lock().await.redis.complete_exchange(matched);
                return Ok(true);
            }
            Err(error) => {
                state
                    .lock()
                    .await
                    .redis
                    .fail_exchange(matched, error.to_string());
                return Err(error);
            }
        }
    }
    if matched.timing.outcome().is_client_terminated() {
        let result = if reader.buffer.is_empty() {
            matched
                .timing
                .await_client_termination_at(&mut reader.inner, started)
                .await
                .map(|_| ())
        } else {
            Err(anyhow!(
                "client sent another Redis request instead of terminating the connection"
            ))
        };
        match result {
            Ok(()) => {
                state.lock().await.redis.complete_exchange(matched);
                return Ok(true);
            }
            Err(error) => {
                state
                    .lock()
                    .await
                    .redis
                    .fail_exchange(matched, error.to_string());
                // A failed expectation is a report fact. It is not permission
                // to close the Target's still-live dependency socket.
                retain_failed_connection(reader, state).await;
                return Err(error);
            }
        }
    }

    if matched.timing.outcome().is_server_terminated() {
        // The RESP decoder first obtains a terminal prefix at EOF. Preserve
        // that observed ordering, with a single request-relative deadline.
        if let Err(error) = await_server_end(reader, matched, started).await {
            state
                .lock()
                .await
                .redis
                .fail_exchange(matched, error.to_string());
            return Err(error);
        }
        let pipeline = match claim_terminated_pipeline(reader, state, matched, client_id).await {
            Ok(pipeline) => pipeline,
            Err(error) => {
                state
                    .lock()
                    .await
                    .redis
                    .fail_exchange(matched, error.to_string());
                retain_failed_connection(reader, state).await;
                return Err(error);
            }
        };
        let result = async {
            reader.inner.write_all(&matched.response).await?;
            matched
                .timing
                .terminate_server_at(&mut reader.inner, control, started)
                .await
        }
        .await;
        match result {
            Ok(()) => {
                let mut state = state.lock().await;
                state.redis.complete_exchange(matched);
                for exchange in &pipeline {
                    state.redis.complete_exchange(exchange);
                }
            }
            Err(error) => {
                let mut state = state.lock().await;
                state.redis.fail_exchange(matched, error.to_string());
                for exchange in &pipeline {
                    state.redis.fail_exchange(exchange, error.to_string());
                }
                return Err(error);
            }
        }
        if matched
            .timing
            .outcome()
            .termination()
            .is_some_and(|end| end.kind == crate::dependency::TerminationKind::Eof)
        {
            retain_after_server_end(reader, state, matched).await;
        }
        return Ok(true);
    }

    let written = write_response(reader, state, matched, started, fast).await?;
    if let Some(predecessors) = serial_predecessors {
        // RESP still replies in Target order. The finite call's effects are
        // released only after every independently observed Source predecessor.
        let state = state.clone();
        let matched = matched.clone();
        tokio::spawn(async move {
            let deadline = started + super::admission::POOLED_LANE_WAIT;
            if wait_serial_publishes(&state, timing_scope.as_ref(), &predecessors, deadline).await {
                if let Err(error) = finish_response(
                    &state,
                    &matched,
                    timing_scope.as_ref(),
                    written,
                    claim_guard,
                )
                .await
                {
                    tracing::debug!(%error, "deferred Redis call delivery failed");
                }
            } else {
                state.lock().await.redis.fail_exchange(
                    &matched,
                    "deferred Redis call did not observe every predecessor broadcast".into(),
                );
            }
        });
    } else {
        finish_response(state, matched, timing_scope.as_ref(), written, claim_guard).await?;
    }
    Ok(false)
}

async fn wait_serial_publishes(
    state: &Arc<Mutex<ReplayState>>,
    scope: Option<&super::input_timing::DeliveryScope>,
    predecessors: &[usize],
    deadline: tokio::time::Instant,
) -> bool {
    loop {
        let state = state.lock().await;
        if tokio::time::Instant::now() >= deadline || !serial_scope_current(&state, scope) {
            return false;
        }
        let mut statuses = predecessors
            .iter()
            .map(|&index| state.redis.exchange_status(index));
        if statuses
            .clone()
            .all(|status| status == Some(ReplayExchangeStatus::Consumed))
        {
            return true;
        }
        if statuses.any(|status| matches!(status, None | Some(ReplayExchangeStatus::Failed))) {
            return false;
        }
        let wait = state.redis.lifecycle.subscribe();
        drop(state);
        if wait.wait(deadline).await == WaitOutcome::Deadline {
            return false;
        }
    }
}

pub(super) fn serial_scope_current(
    state: &ReplayState,
    scope: Option<&super::input_timing::DeliveryScope>,
) -> bool {
    scope.is_some() && super::input_timing::scope(state).as_ref() == scope
}

/// These two commands were independently observed and admitted in Source order.
/// RESP replies follow the Target socket order. Subscriber side effects and
/// completion evidence follow Source order once both replies have reached TCP.
pub(super) async fn deliver_publish_pair(
    reader: &mut RedisBufferedReader<&mut TcpStream>,
    state: &Arc<Mutex<ReplayState>>,
    earlier: (&MatchedRedisExchange, tokio::time::Instant),
    later: (&MatchedRedisExchange, tokio::time::Instant),
) -> Result<()> {
    let guard = |matched: &MatchedRedisExchange| match &matched.claim {
        Claim::Finite(ticket) => Some(ticket.guard()),
        Claim::Native(_) => None,
    };
    let earlier_guard = guard(earlier.0);
    let later_guard = guard(later.0);
    let (timing_scope, fast) = {
        let state = state.lock().await;
        (
            super::input_timing::scope(&state),
            state.stream_timing == Some(ReplayStreamTiming::Fast),
        )
    };
    let result = async {
        let later_written = write_response(reader, state, later.0, later.1, fast).await?;
        let earlier_written = write_response(reader, state, earlier.0, earlier.1, fast).await?;
        finish_response(
            state,
            earlier.0,
            timing_scope.as_ref(),
            earlier_written,
            earlier_guard,
        )
        .await?;
        finish_response(
            state,
            later.0,
            timing_scope.as_ref(),
            later_written,
            later_guard,
        )
        .await
    }
    .await;
    if let Err(error) = &result {
        let mut state = state.lock().await;
        let reason = format!("pipelined Redis response delivery failed: {error:#}");
        state.redis.fail_exchange(earlier.0, reason.clone());
        state.redis.fail_exchange(later.0, reason);
    }
    result
}

struct WrittenResponse {
    rendered_at: DateTime<Utc>,
    delivered_at: DateTime<Utc>,
    rendered: Option<Vec<u8>>,
    published: Result<()>,
}

async fn write_response(
    reader: &mut RedisBufferedReader<&mut TcpStream>,
    state: &Arc<Mutex<ReplayState>>,
    matched: &MatchedRedisExchange,
    started: tokio::time::Instant,
    fast: bool,
) -> Result<WrittenResponse> {
    matched
        .timing
        .delay_response_from_request(started, fast)
        .await;
    let unified_rendered_at = chrono::Utc::now();
    let unified_rendered = matched
        .unified_delivery
        .as_ref()
        .map(|delivery| {
            delivery.render_consistent(
                unified_rendered_at,
                matched
                    .read_back
                    .as_ref()
                    .map(|native| native.response.as_slice()),
            )
        })
        .transpose();
    let unified_rendered = match unified_rendered {
        Ok(rendered) => rendered,
        Err(error) => {
            state
                .lock()
                .await
                .redis
                .fail_exchange(matched, error.to_string());
            return Err(error);
        }
    };
    let response = unified_rendered
        .as_deref()
        .unwrap_or(matched.response.as_slice());
    if let Err(error) = reader.inner.write_all(response).await {
        state.lock().await.redis.fail_exchange(
            matched,
            format!("failed to deliver recorded Redis response: {error}"),
        );
        return Err(error.into());
    }
    let delivered_at = chrono::Utc::now();
    // Preserve publication before reacquiring ReplayState: a pooled successor
    // may already be comparing this successfully delivered value.
    let published = (|| {
        if let Some(read) = &matched.time_read {
            read.publish(response, delivered_at)?;
        }
        if let Some(write) = &matched.time_write {
            write.publish(delivered_at)?;
        }
        Ok(())
    })();
    if published.is_ok() || ordinary_finite_response(matched) {
        matched.publish_wire();
    }
    Ok(WrittenResponse {
        rendered_at: unified_rendered_at,
        delivered_at,
        rendered: unified_rendered,
        published,
    })
}

async fn finish_response(
    state: &Arc<Mutex<ReplayState>>,
    matched: &MatchedRedisExchange,
    timing_scope: Option<&super::input_timing::DeliveryScope>,
    written: WrittenResponse,
    mut claim_guard: Option<DeliveryGuard>,
) -> Result<()> {
    let WrittenResponse {
        rendered_at: unified_rendered_at,
        delivered_at,
        rendered,
        published,
    } = written;
    let response = rendered.as_deref().unwrap_or(matched.response.as_slice());
    if ordinary_finite_response(matched) {
        // Actual wire progress is visible before waiting for ReplayState's
        // mutex; the common transaction owns every subsequent commit/failure.
        let mut replay = state.lock().await;
        if !serial_delivery_current(&mut replay, matched, timing_scope) {
            return Ok(());
        }
        replay.redis.finish_delivery(
            matched,
            response,
            unified_rendered_at,
            delivered_at,
            published,
        )?;
        super::input_timing::response_delivered(&mut replay, matched, timing_scope);
        return Ok(());
    }
    if let Err(error) = published {
        state
            .lock()
            .await
            .redis
            .fail_exchange(matched, error.to_string());
        return Err(error);
    }
    let state_ref = state;
    let mut state = state_ref.lock().await;
    if !serial_delivery_current(&mut state, matched, timing_scope) {
        return Ok(());
    }
    let serial_scope = state.redis.exchanges[matched.index]
        .serial_predecessors
        .as_ref()
        .and(timing_scope);
    if let Some(delivery) = &matched.read_back
        && let Err(error) = state
            .redis
            .request_contracts
            .commit_redis_read_back(delivery, chrono::Utc::now())
    {
        state.redis.fail_exchange(matched, error.to_string());
        return Err(error);
    }
    if let Some(delivery) = &matched.unified_delivery
        && let Err(error) = state.redis.request_contracts.commit_redis_delivery(
            delivery,
            response,
            unified_rendered_at,
        )
    {
        state.redis.fail_exchange(matched, error.to_string());
        return Err(error);
    }
    if let Some(read) = &matched.time_read {
        // Ordinary Case responses remain resident and immutable. Publish the
        // scalar pairs only after the final native/schema bytes reached TCP.
        let original = &state.redis.exchanges[matched.index].response;
        if let Err(error) = state
            .redis
            .request_contracts
            .record_redis_time_read_witness(read, Some(original), response, delivered_at)
        {
            state.redis.fail_exchange(matched, error.to_string());
            return Err(error);
        }
    }
    // TCP and contract commits have succeeded. An RPC callback may still be
    // pending, so complete_exchange is deliberately a separate fact.
    if matches!(matched.claim, Claim::Finite(_)) {
        super::input_timing::response_delivered(&mut state, matched, timing_scope);
    }
    drop(state);
    if let Err(error) = pubsub::echo::deliver(state_ref, matched, serial_scope).await {
        state_ref
            .lock()
            .await
            .redis
            .fail_exchange(matched, format!("adapter self-echo failed: {error:#}"));
        return Err(error);
    }
    let mut state = state_ref.lock().await;
    if !serial_delivery_current(&mut state, matched, timing_scope) {
        return Ok(());
    }
    if let Some(push) = matched.rpc_push {
        let detached = state.redis.pubsub.rpc_is_detached(matched);
        let delivery = state.redis.pubsub.rpc_delivery(matched);
        match delivery {
            Ok((delay, mut delivery)) => {
                if let Some(case) = serial_scope.and(matched.report.case_id.as_deref()) {
                    delivery.case_id = Some(case.into());
                    delivery.request_epoch = state.redis.native_request_epoch(case);
                }
                if detached {
                    state.redis.complete_exchange(matched);
                }
                drop(state);
                pubsub::schedule(state_ref.clone(), delay, delivery, None);
                if !detached && let Some(guard) = claim_guard.take() {
                    guard.handoff();
                }
            }
            Err(error) => {
                state.redis.pubsub.fail(pubsub::PushId::Inline(push));
                state.redis.fail_exchange(matched, error.to_string());
            }
        }
    } else if let Some(covered) = state.redis.complete_exchange_covered(matched) {
        super::input_timing::response_indices_delivered(&mut state, &covered, timing_scope);
    }
    Ok(())
}

fn ordinary_finite_response(matched: &MatchedRedisExchange) -> bool {
    matches!(matched.claim, Claim::Finite(_))
        && matched.rpc_push.is_none()
        && matched.adapter_echo.is_none()
}

fn serial_delivery_current(
    state: &mut ReplayState,
    matched: &MatchedRedisExchange,
    timing_scope: Option<&super::input_timing::DeliveryScope>,
) -> bool {
    if state.redis.exchanges[matched.index]
        .serial_predecessors
        .is_none()
        || serial_scope_current(state, timing_scope)
    {
        return true;
    }
    state.redis.fail_exchange(
        matched,
        "deferred Redis call lost its Case before delivery".into(),
    );
    false
}

async fn await_server_end(
    reader: &mut RedisBufferedReader<&mut TcpStream>,
    matched: &MatchedRedisExchange,
    started: tokio::time::Instant,
) -> Result<()> {
    let deadline = started + std::time::Duration::from_millis(matched.publish_duration_ms);
    loop {
        ensure!(
            reader.buffer.len() <= reader.max_frame_bytes,
            "Redis pipeline exceeds recording frame budget"
        );
        tokio::select! {
            biased;
            read = reader.inner.read_buf(&mut reader.buffer) => {
                match read {
                    Ok(0) => return Err(anyhow!("Target closed Redis connection before recorded server termination")),
                    Ok(_) => {},
                    Err(error) => return Err(anyhow!("Target failed Redis connection before recorded server termination: {error}")),
                }
            }
            _ = tokio::time::sleep_until(deadline) => return Ok(()),
        }
    }
}

async fn claim_terminated_pipeline(
    reader: &mut RedisBufferedReader<&mut TcpStream>,
    state: &Arc<Mutex<ReplayState>>,
    first: &MatchedRedisExchange,
    client_id: Uuid,
) -> Result<Vec<MatchedRedisExchange>> {
    let mut state = state.lock().await;
    let case_id = state.active_case_id.clone();
    let record = state.redis.exchanges[first.index].record.clone();
    let connection = TargetConnection {
        id: client_id,
        bound: Some(first.connection_id),
    };
    let mut pipeline = Vec::new();
    let result: Result<()> = (|| {
        while !reader.buffer.is_empty() {
            let Some((_, _, raw)) = redis_protocol::resp2::decode::decode_bytes_mut(
                &mut reader.buffer,
            )
            .map_err(|_| anyhow!("invalid Redis request before recorded server termination"))?
            else {
                return Err(anyhow!(
                    "incomplete Redis request before recorded server termination"
                ));
            };
            let command = redis_command(&raw)?;
            let matched = if redis_is_builtin(&command.name) {
                state
                    .redis
                    .match_redis_builtin_failure(
                        case_id.as_deref(),
                        &first.report.target,
                        connection,
                        record.resp_version,
                        record.database,
                        record.username.as_deref(),
                        &command,
                    )
                    .ok_or_else(|| anyhow!("no recorded Redis pipeline termination matched"))?
            } else {
                state
                    .redis
                    .match_redis(
                        case_id.as_deref(),
                        &first.report.target,
                        connection,
                        record.resp_version,
                        record.database,
                        record.username.as_deref(),
                        &command.name,
                        &command.args,
                    )
                    .map_err(|_| anyhow!("no recorded Redis pipeline termination matched"))?
            };
            if matched.connection_id != first.connection_id
                || matched.timing.outcome() != first.timing.outcome()
                || !matched.response.is_empty()
            {
                let reason =
                    "Redis pipelined command did not share the recorded connection termination";
                state.redis.fail_exchange(&matched, reason.into());
                return Err(anyhow!(reason));
            }
            if let Some(policy) = &mut state.replay_policy {
                policy.commit_redis_rule_usage(case_id.as_deref(), &matched.rule_ids);
            }
            pipeline.push(matched);
        }
        Ok(())
    })();
    if let Err(error) = result {
        for exchange in &pipeline {
            state.redis.fail_exchange(exchange, error.to_string());
        }
        return Err(error);
    }
    Ok(pipeline)
}

async fn retain_failed_connection(
    reader: &mut RedisBufferedReader<&mut TcpStream>,
    state: &Arc<Mutex<ReplayState>>,
) {
    tokio::select! {
        _ = crate::replay::exchange::retain_connection(&mut reader.inner) => {},
        _ = await_finalization(state) => {},
    }
}

async fn retain_after_server_end(
    reader: &mut RedisBufferedReader<&mut TcpStream>,
    state: &Arc<Mutex<ReplayState>>,
    matched: &MatchedRedisExchange,
) {
    let mut probe = [0; 1024];
    let extra = tokio::select! {
        read = reader.inner.read(&mut probe) => matches!(read, Ok(n) if n > 0),
        _ = await_finalization(state) => false,
    };
    if !extra {
        return;
    }
    {
        let mut state = state.lock().await;
        if let Some(case) = &matched.report.case_id {
            state.redis.events.dirty_case_ids.insert(case.clone());
        }
        state.redis.events.unsafe_events.push(CommandRequestReport {
            target_observation_id: None,
            case_id: matched.report.case_id.clone(),
            target: matched.report.target.clone(),
            command: "POST_TERMINATION_BYTES".into(),
            target_event_index: None,
            request_fingerprint: None,
            reason: "Target sent Redis data after recorded server termination".into(),
            diagnostic: None,
        });
    }
    retain_failed_connection(reader, state).await;
}

async fn await_finalization(state: &Arc<Mutex<ReplayState>>) {
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        if state.lock().await.finalized_at.is_some() {
            return;
        }
    }
}
