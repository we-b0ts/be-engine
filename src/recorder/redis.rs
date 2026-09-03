use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use chrono::Utc;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, mpsc};
use uuid::Uuid;

use crate::AppState;
use crate::DependencyExchangeOutcome;
use crate::access_policy::AccessDecision;
use crate::dependency::termination::ConnectionTermination;
use crate::recorder::cache_snapshot::CacheSnapshotReservation;
use crate::recorder::capture_health::{ConnectionCaptureHealth, RawTrafficDirection};
use crate::recorder::{RecorderEvent, RedisConnectionEvent, RedisExchangeEvent, capture_body};

use crate::redis::access::classify_command;
use crate::redis::{
    BufferedReader, RedisCommand, RedisFrameKind, frame_kind, is_subscription_command, read_frame,
    redis_command, validate_subscription_confirmation,
};

#[derive(Debug, Clone)]
pub(crate) struct ConnectionContext {
    pub(crate) client_addr: Option<String>,
    pub(crate) target_host: String,
    pub(crate) target_port: u16,
    pub(crate) target_addr: String,
    pub(crate) upstream_addr: String,
}

#[derive(Debug, Clone)]
struct RedisSession {
    resp_version: u8,
    database: i64,
    username: Option<String>,
}

#[derive(Debug)]
struct PendingRedisExchange {
    sequence: u64,
    command: RedisCommand,
    recorded_args: Vec<Vec<u8>>,
    session: RedisSession,
    session_setup: bool,
    replay_safe: bool,
    warnings: Vec<String>,
    cache_snapshot_rule: Option<String>,
    cache_snapshot_key: Option<Vec<u8>>,
    cache_snapshot_hit: bool,
    started: Instant,
}

enum RedisOutput {
    Sequenced {
        sequence: u64,
        bytes: Bytes,
        completion: Option<(PendingRedisExchange, RedisFrameKind)>,
    },
}

pub(crate) async fn handle_connected(
    client: TcpStream,
    upstream: TcpStream,
    state: AppState,
    context: ConnectionContext,
) -> Result<()> {
    let connection_id = Uuid::new_v4();
    let started = Instant::now();
    let session = Arc::new(Mutex::new(RedisSession {
        resp_version: 2,
        database: 0,
        username: None,
    }));
    let pending = Arc::new(Mutex::new(VecDeque::<PendingRedisExchange>::new()));
    let capture_health = Arc::new(ConnectionCaptureHealth::new(
        connection_id,
        "redis",
        context.client_addr.clone(),
        context.target_addr.clone(),
    ));
    let termination = ConnectionTermination::default();
    let opening_session = session.lock().await.clone();
    record_connection(
        &state,
        connection_id,
        &context,
        "opened",
        &opening_session,
        None,
        0,
        0,
        true,
        None,
    )
    .await?;

    let max_frame_bytes = state.config().recording.max_body_bytes;
    let (client_read, client_write) = client.into_split();
    let (upstream_read, mut upstream_write) = upstream.into_split();
    let client_write = Arc::new(Mutex::new(client_write));
    let (output_tx, output_rx) = mpsc::unbounded_channel();
    let writer = tokio::spawn(run_ordered_writer(
        client_write.clone(),
        output_rx,
        state.clone(),
        context.clone(),
        connection_id,
        termination.clone(),
        max_frame_bytes,
    ));

    let c2s_pending = pending.clone();
    let c2s_session = session.clone();
    let c2s_capture_health = capture_health.clone();
    let c2s_state = state.clone();
    let c2s_context = context.clone();
    let c2s_output = output_tx.clone();
    let c2s_termination = termination.clone();
    let c2s = tokio::spawn(async move {
        let mut reader = BufferedReader::new(client_read, max_frame_bytes);
        let mut sequence = 0_u64;
        let mut bytes = 0_u64;
        loop {
            if c2s_capture_health.is_degraded() {
                bytes += forward_buffer_and_copy(
                    &mut reader,
                    &mut upstream_write,
                    None,
                    &c2s_capture_health,
                    &c2s_state,
                    RawTrafficDirection::ClientToServer,
                )
                .await?;
                break;
            }
            let frame = match read_frame(&mut reader).await {
                Ok(Some(frame)) => frame,
                Ok(None) => {
                    c2s_termination.observe_client_eof();
                    break;
                }
                Err(error) => {
                    // SO_LINGER=0 clients reset even after a complete exchange. Pending-response
                    // and writer checks below still reject resets that interrupt data transfer.
                    if is_abortive_close_between_frames(&reader, &error) {
                        c2s_termination.observe_client_error(&error);
                        break;
                    }
                    c2s_capture_health.activate(
                        &c2s_state,
                        format!("Redis client parse failed; switched to raw forwarding: {error}"),
                    );
                    bytes += forward_buffer_and_copy(
                        &mut reader,
                        &mut upstream_write,
                        None,
                        &c2s_capture_health,
                        &c2s_state,
                        RawTrafficDirection::ClientToServer,
                    )
                    .await?;
                    break;
                }
            };
            if c2s_capture_health.is_degraded() {
                bytes += forward_buffer_and_copy(
                    &mut reader,
                    &mut upstream_write,
                    Some(&frame.raw),
                    &c2s_capture_health,
                    &c2s_state,
                    RawTrafficDirection::ClientToServer,
                )
                .await?;
                break;
            }
            let command = match redis_command(&frame.raw) {
                Ok(command) => command,
                Err(error) => {
                    c2s_capture_health.activate(
                        &c2s_state,
                        format!("Redis command parse failed; switched to raw forwarding: {error}"),
                    );
                    bytes += forward_buffer_and_copy(
                        &mut reader,
                        &mut upstream_write,
                        Some(&frame.raw),
                        &c2s_capture_health,
                        &c2s_state,
                        RawTrafficDirection::ClientToServer,
                    )
                    .await?;
                    break;
                }
            };
            sequence += 1;
            let operation_class = classify_command(&command);
            if c2s_state.access_decision(operation_class) == AccessDecision::Reject {
                c2s_state
                    .record_readonly_rejection(
                        "redis",
                        operation_class,
                        command.name.clone(),
                        c2s_context.client_addr.clone(),
                        Some(c2s_context.target_addr.clone()),
                        "Redis command is classified as a write operation",
                    )
                    .await;
                c2s_output
                    .send(RedisOutput::Sequenced {
                        sequence,
                        bytes: Bytes::from_static(
                            b"-READONLY request blocked by recording access policy\r\n",
                        ),
                        completion: None,
                    })
                    .map_err(|_| anyhow!("Redis client response writer closed"))?;
                bytes += frame.raw.len() as u64;
                continue;
            }
            let (recorded_args, session_setup, replay_safe, warnings) =
                sanitize_and_classify(&command);
            let current_session = c2s_session.lock().await.clone();
            let cache_snapshot_rule = c2s_state
                .matching_redis_snapshot_rule(c2s_context.target_port, &command.name, &command.args)
                .map(ToOwned::to_owned);
            if cache_snapshot_rule.is_some() {
                c2s_state.record_redis_cache_request();
            }
            let cache_snapshot_key = cache_snapshot_rule.as_ref().map(|rule| {
                redis_snapshot_key(rule, &current_session, &command.name, &command.args)
            });
            let mut pending_exchange = PendingRedisExchange {
                sequence,
                command,
                recorded_args,
                session: current_session,
                session_setup,
                replay_safe,
                warnings,
                cache_snapshot_rule,
                cache_snapshot_key: None,
                cache_snapshot_hit: false,
                started: Instant::now(),
            };
            if let Some(key) = cache_snapshot_key {
                match c2s_state.reserve_cache_snapshot(key.clone()).await? {
                    CacheSnapshotReservation::Leader => {
                        pending_exchange.cache_snapshot_key = Some(key);
                    }
                    CacheSnapshotReservation::Hit(response) => {
                        pending_exchange.cache_snapshot_hit = true;
                        let kind = frame_kind(&response)
                            .context("cached Redis response is not a complete RESP2 frame")?;
                        c2s_output
                            .send(RedisOutput::Sequenced {
                                sequence,
                                bytes: response,
                                completion: Some((pending_exchange, kind)),
                            })
                            .map_err(|_| anyhow!("Redis client response writer closed"))?;
                        bytes += frame.raw.len() as u64;
                        continue;
                    }
                    CacheSnapshotReservation::Wait(waiter) => {
                        let response = waiter.response().await?;
                        pending_exchange.cache_snapshot_hit = true;
                        let kind = frame_kind(&response)
                            .context("shared Redis response is not a complete RESP2 frame")?;
                        c2s_output
                            .send(RedisOutput::Sequenced {
                                sequence,
                                bytes: response,
                                completion: Some((pending_exchange, kind)),
                            })
                            .map_err(|_| anyhow!("Redis client response writer closed"))?;
                        bytes += frame.raw.len() as u64;
                        continue;
                    }
                }
            }
            c2s_pending.lock().await.push_back(pending_exchange);
            upstream_write.write_all(&frame.raw).await?;
            bytes += frame.raw.len() as u64;
        }
        let _ = upstream_write.shutdown().await;
        Ok::<u64, anyhow::Error>(bytes)
    });

    let s2c_state = state.clone();
    let s2c_pending = pending.clone();
    let s2c_session = session.clone();
    let s2c_capture_health = capture_health.clone();
    let s2c_output = output_tx.clone();
    let s2c_client_write = client_write.clone();
    let s2c_termination = termination.clone();
    let s2c = tokio::spawn(async move {
        let mut reader = BufferedReader::new(upstream_read, max_frame_bytes);
        let mut bytes = 0_u64;
        loop {
            let frame = match read_frame(&mut reader).await {
                Ok(Some(frame)) => frame,
                Ok(None) => {
                    s2c_termination.observe_server_eof();
                    break;
                }
                Err(error) => {
                    s2c_termination.observe_server_error(&error);
                    s2c_capture_health.activate(
                        &s2c_state,
                        format!("Redis server parse failed; switched to raw forwarding: {error}"),
                    );
                    let mut writer = s2c_client_write.lock().await;
                    bytes += forward_buffer_and_copy(
                        &mut reader,
                        &mut *writer,
                        None,
                        &s2c_capture_health,
                        &s2c_state,
                        RawTrafficDirection::ServerToClient,
                    )
                    .await?;
                    break;
                }
            };
            if s2c_capture_health.is_degraded() {
                let mut writer = s2c_client_write.lock().await;
                bytes += forward_buffer_and_copy(
                    &mut reader,
                    &mut *writer,
                    Some(&frame.raw),
                    &s2c_capture_health,
                    &s2c_state,
                    RawTrafficDirection::ServerToClient,
                )
                .await?;
                break;
            }
            let Some(mut exchange) = s2c_pending.lock().await.pop_front() else {
                s2c_capture_health.activate(
                    &s2c_state,
                    "Redis response arrived without a pending request; switched to raw forwarding"
                        .to_string(),
                );
                let mut writer = s2c_client_write.lock().await;
                bytes += forward_buffer_and_copy(
                    &mut reader,
                    &mut *writer,
                    Some(&frame.raw),
                    &s2c_capture_health,
                    &s2c_state,
                    RawTrafficDirection::ServerToClient,
                )
                .await?;
                break;
            };
            let response_sequence = exchange.sequence;
            exchange.session = s2c_session.lock().await.clone();
            let response_is_error = frame.kind == RedisFrameKind::Error;
            if let Some(key) = exchange.cache_snapshot_key.take() {
                s2c_state
                    .complete_cache_snapshot(
                        &key,
                        frame.raw.clone(),
                        exchange.replay_safe && !response_is_error,
                    )
                    .await?;
            }
            if !response_is_error {
                apply_successful_setup(&s2c_session, &exchange.command).await;
            }
            s2c_output
                .send(RedisOutput::Sequenced {
                    sequence: response_sequence,
                    bytes: frame.raw.clone(),
                    completion: Some((exchange, frame.kind)),
                })
                .map_err(|_| anyhow!("Redis client response writer closed"))?;
            bytes += frame.raw.len() as u64;
        }
        Ok::<u64, anyhow::Error>(bytes)
    });

    drop(output_tx);
    let (c2s_result, s2c_result, writer_result) = tokio::join!(c2s, s2c, writer);
    let transfer_result = async {
        let c2s_bytes = c2s_result.context("Redis client task panicked")??;
        let _upstream_bytes = s2c_result.context("Redis server task panicked")??;
        let s2c_bytes = writer_result.context("Redis writer task panicked")??;
        Ok::<_, anyhow::Error>((c2s_bytes, s2c_bytes))
    }
    .await;
    let (c2s_bytes, s2c_bytes, mut transfer_error) = match transfer_result {
        Ok((c2s_bytes, s2c_bytes)) => (c2s_bytes, s2c_bytes, None),
        Err(error) => {
            let message = error.to_string();
            record_event(
                &state,
                RecorderEvent::ProxyError(crate::recorder::ProxyErrorEvent {
                    id: Uuid::new_v4(),
                    connection_id: Some(connection_id),
                    timestamp: Utc::now(),
                    protocol: "redis".to_string(),
                    client_addr: context.client_addr.clone(),
                    target: Some(context.target_addr.clone()),
                    error: message.clone(),
                }),
            )
            .await?;
            (0, 0, Some(message))
        }
    };
    if transfer_error.is_none() {
        transfer_error = capture_health.reason();
    }
    let client_terminated = termination.client_ended_first() && transfer_error.is_none();
    let mut replay_safe = transfer_error.is_none();
    let mut incomplete = pending.lock().await;
    while let Some(exchange) = incomplete.pop_front() {
        if let Some(key) = exchange.cache_snapshot_key.as_deref() {
            state
                .abort_cache_snapshot(key, "Redis snapshot fill ended before a response")
                .await;
        }
        let clean_terminal_quit = is_terminal_quit(&exchange.command) && transfer_error.is_none();
        let exchange_completed = client_terminated || clean_terminal_quit;
        if !exchange_completed {
            replay_safe = false;
        }
        record_exchange(
            &state,
            connection_id,
            &context,
            PendingRedisExchange {
                replay_safe: exchange.replay_safe && exchange_completed,
                warnings: if exchange_completed {
                    exchange.warnings
                } else {
                    vec!["connection closed before Redis response".to_string()]
                },
                ..exchange
            },
            RedisFrameKind::Other,
            b"",
            if clean_terminal_quit {
                DependencyExchangeOutcome::NoResponse
            } else if client_terminated {
                DependencyExchangeOutcome::ClientTerminated
            } else {
                DependencyExchangeOutcome::Response
            },
            max_frame_bytes,
        )
        .await?;
    }
    drop(incomplete);
    let closing_session = session.lock().await.clone();
    record_connection(
        &state,
        connection_id,
        &context,
        "closed",
        &closing_session,
        Some(started.elapsed().as_millis()),
        c2s_bytes,
        s2c_bytes,
        replay_safe,
        transfer_error.clone(),
    )
    .await?;
    if let Some(error) = transfer_error {
        return Err(anyhow!(error));
    }
    Ok(())
}

async fn run_ordered_writer(
    client_write: Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    mut output_rx: mpsc::UnboundedReceiver<RedisOutput>,
    state: AppState,
    context: ConnectionContext,
    connection_id: Uuid,
    termination: ConnectionTermination,
    max_frame_bytes: usize,
) -> Result<u64> {
    let mut next_sequence = 1_u64;
    let mut buffered =
        BTreeMap::<u64, (Bytes, Option<(PendingRedisExchange, RedisFrameKind)>)>::new();
    let mut bytes = 0_u64;
    let mut client_open = true;
    while let Some(output) = output_rx.recv().await {
        match output {
            RedisOutput::Sequenced {
                sequence,
                bytes: payload,
                completion,
            } => {
                buffered.insert(sequence, (payload, completion));
                while let Some((payload, completion)) = buffered.remove(&next_sequence) {
                    if client_open && !termination.client_ended_first() {
                        match client_write.lock().await.write_all(&payload).await {
                            Ok(()) => {
                                bytes += payload.len() as u64;
                                if let Some((exchange, response_kind)) = completion {
                                    record_exchange(
                                        &state,
                                        connection_id,
                                        &context,
                                        exchange,
                                        response_kind,
                                        &payload,
                                        DependencyExchangeOutcome::Response,
                                        max_frame_bytes,
                                    )
                                    .await?;
                                }
                            }
                            Err(error) if termination.observe_client_io_error(&error) => {
                                client_open = false;
                                if let Some((exchange, _)) = completion {
                                    record_exchange(
                                        &state,
                                        connection_id,
                                        &context,
                                        exchange,
                                        RedisFrameKind::Other,
                                        b"",
                                        DependencyExchangeOutcome::ClientTerminated,
                                        max_frame_bytes,
                                    )
                                    .await?;
                                }
                            }
                            Err(error) => return Err(error.into()),
                        }
                    } else if let Some((exchange, _)) = completion {
                        client_open = false;
                        record_exchange(
                            &state,
                            connection_id,
                            &context,
                            exchange,
                            RedisFrameKind::Other,
                            b"",
                            DependencyExchangeOutcome::ClientTerminated,
                            max_frame_bytes,
                        )
                        .await?;
                    }
                    next_sequence += 1;
                }
            }
        }
    }
    if !buffered.is_empty() {
        return Err(anyhow!("Redis response ordering ended with sequence gaps"));
    }
    if client_open {
        let _ = client_write.lock().await.shutdown().await;
    }
    Ok(bytes)
}

async fn record_event(state: &AppState, event: RecorderEvent) -> Result<()> {
    state.record_event(event);
    Ok(())
}

async fn forward_buffer_and_copy<R, W>(
    reader: &mut BufferedReader<R>,
    writer: &mut W,
    prefix: Option<&[u8]>,
    capture_health: &ConnectionCaptureHealth,
    state: &AppState,
    direction: RawTrafficDirection,
) -> Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut copied = 0_u64;
    if let Some(prefix) = prefix {
        copied += capture_health
            .write_raw(state, direction, writer, prefix)
            .await?;
    }
    let buffered = reader.buffer.split().freeze();
    copied += capture_health
        .write_raw(state, direction, writer, &buffered)
        .await?;
    copied += capture_health
        .copy_raw(state, direction, &mut reader.inner, writer)
        .await?;
    Ok(copied)
}

fn is_abortive_close_between_frames<R>(reader: &BufferedReader<R>, error: &anyhow::Error) -> bool {
    reader.buffer.is_empty()
        && error.chain().any(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::ConnectionReset)
        })
}

#[allow(clippy::too_many_arguments)]
async fn record_exchange(
    state: &AppState,
    connection_id: Uuid,
    context: &ConnectionContext,
    mut pending: PendingRedisExchange,
    response_kind: RedisFrameKind,
    response: &[u8],
    outcome: DependencyExchangeOutcome,
    max_frame_bytes: usize,
) -> Result<()> {
    let subscription_replay_safe = if is_subscription_command(&pending.command.name) {
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
            || terminal_quit);
    record_event(
        state,
        RecorderEvent::RedisExchange(RedisExchangeEvent {
            id: Uuid::new_v4(),
            connection_id,
            sequence: pending.sequence,
            timestamp: Utc::now(),
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
            cache_snapshot_rule: pending.cache_snapshot_rule,
            cache_snapshot_hit: pending.cache_snapshot_hit,
            session_setup: pending.session_setup,
            outcome,
            duration_ms: pending.started.elapsed().as_millis(),
            replay_safe,
            parse_warnings: pending.warnings,
        }),
    )
    .await
}

fn redis_snapshot_key(
    rule: &str,
    session: &RedisSession,
    command: &str,
    args: &[Vec<u8>],
) -> Vec<u8> {
    let mut key = Vec::new();
    push_snapshot_component(&mut key, b"redis");
    push_snapshot_component(&mut key, rule.as_bytes());
    key.extend_from_slice(&session.resp_version.to_be_bytes());
    key.extend_from_slice(&session.database.to_be_bytes());
    push_snapshot_component(
        &mut key,
        session.username.as_deref().unwrap_or_default().as_bytes(),
    );
    push_snapshot_component(&mut key, command.as_bytes());
    for argument in args {
        push_snapshot_component(&mut key, argument);
    }
    key
}

fn push_snapshot_component(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_be_bytes());
    target.extend_from_slice(value);
}

fn is_terminal_quit(command: &RedisCommand) -> bool {
    command.name == "QUIT"
}

#[allow(clippy::too_many_arguments)]
async fn record_connection(
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

fn sanitize_and_classify(command: &RedisCommand) -> (Vec<Vec<u8>>, bool, bool, Vec<String>) {
    let mut args = command.args.clone();
    let mut warnings = Vec::new();
    let session_setup = matches!(command.name.as_str(), "AUTH" | "HELLO" | "SELECT")
        || (command.name == "CLIENT"
            && command.args.first().is_some_and(|subcommand| {
                matches_ignore_ascii_case(subcommand, &[b"SETNAME", b"SETINFO", b"ID", b"GETNAME"])
            }));
    let replay_safe = match command.name.as_str() {
        "AUTH" => {
            if args.len() == 1 {
                args[0] = b"<redacted>".to_vec();
            } else if args.len() >= 2 {
                args[1] = b"<redacted>".to_vec();
            }
            true
        }
        "HELLO" => {
            for index in 0..args.len() {
                if args[index].eq_ignore_ascii_case(b"AUTH") && index + 2 < args.len() {
                    args[index + 2] = b"<redacted>".to_vec();
                }
            }
            true
        }
        "SUBSCRIBE" | "PSUBSCRIBE" | "SSUBSCRIBE" => {
            if command.args.len() == 1 {
                true
            } else {
                warnings.push(format!(
                    "Redis {} confirmation replay requires exactly one subscription argument",
                    command.name
                ));
                false
            }
        }
        "UNSUBSCRIBE" | "PUNSUBSCRIBE" | "SUNSUBSCRIBE" => {
            warnings.push(format!("Redis {} mode is unsupported", command.name));
            false
        }
        "MONITOR" | "CLUSTER" => {
            warnings.push(format!("Redis {} push mode is unsupported", command.name));
            false
        }
        "CLIENT"
            if command.args.first().is_some_and(|value| {
                matches_ignore_ascii_case(value, &[b"TRACKING", b"CACHING"])
            }) =>
        {
            warnings.push("Redis CLIENT tracking mode is unsupported".to_string());
            false
        }
        "ACL" | "CONFIG" | "MIGRATE" | "SENTINEL" => {
            args.clear();
            warnings.push(format!(
                "Redis {} arguments were omitted because the command may contain credentials",
                command.name
            ));
            false
        }
        _ => true,
    };
    (args, session_setup, replay_safe, warnings)
}

fn matches_ignore_ascii_case(value: &[u8], candidates: &[&[u8]]) -> bool {
    candidates
        .iter()
        .any(|candidate| value.eq_ignore_ascii_case(candidate))
}

async fn apply_successful_setup(session: &Arc<Mutex<RedisSession>>, command: &RedisCommand) {
    let mut session = session.lock().await;
    match command.name.as_str() {
        "HELLO" => {
            if let Some(version) = command
                .args
                .first()
                .and_then(|value| std::str::from_utf8(value).ok())
                .and_then(|value| value.parse::<u8>().ok())
                .filter(|version| matches!(version, 2 | 3))
            {
                session.resp_version = version;
            }
            for index in 0..command.args.len() {
                if command.args[index].eq_ignore_ascii_case(b"AUTH")
                    && index + 1 < command.args.len()
                {
                    session.username = std::str::from_utf8(&command.args[index + 1])
                        .ok()
                        .map(ToOwned::to_owned);
                }
            }
        }
        "AUTH" => {
            session.username = if command.args.len() >= 2 {
                std::str::from_utf8(&command.args[0])
                    .ok()
                    .map(ToOwned::to_owned)
            } else {
                Some("default".to_string())
            };
        }
        "SELECT" => {
            if let Some(database) = command
                .args
                .first()
                .and_then(|value| std::str::from_utf8(value).ok())
                .and_then(|value| value.parse::<i64>().ok())
            {
                session.database = database;
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests;
