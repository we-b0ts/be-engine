use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use chrono::Utc;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, mpsc};
use uuid::Uuid;

use super::{
    CaptureSessionState as RedisSession, Subscriptions, is_terminal_quit, sanitize_and_classify,
};
use crate::events::{RedisConnectionEvent, RedisExchangeEvent};
use crate::{
    BufferedReader, RedisCommand, RedisFrameKind, RedisSession as RedisDecoder, frame_kind,
    is_pubsub_command, parse_pubsub_push, read_frame, redis_command,
    validate_subscription_confirmation,
};
use traffic_model::{DependencyExchangeOutcome, TerminationKind, TerminationSide};
use traffic_protocol::transport::{ConnectionControl, ConnectionTermination, ObservedIo};

mod host;
pub use host::{
    CaptureDecision, CaptureHost, CaptureRequest, CapturedPush, CapturedRequest, PushRequest,
};
mod events;
mod pubsub;
#[cfg(test)]
mod tests;
mod writer;
use events::{record_connection, record_exchange, record_termination};
use writer::run_ordered_writer;
pub(crate) use writer::write_payload;

#[derive(Debug, Clone)]
pub struct ConnectionContext {
    pub client_addr: Option<String>,
    pub target_host: String,
    pub target_port: u16,
    pub target_addr: String,
    pub upstream_addr: String,
}

pub struct ConnectionOptions {
    pub context: ConnectionContext,
    pub connection_id: Uuid,
    pub max_frame_bytes: usize,
    pub client_decoder: RedisDecoder,
    pub server_decoder: RedisDecoder,
    pub termination: ConnectionTermination,
}

struct PendingRedisExchange {
    capture: Box<dyn CapturedRequest>,
    sequence: u64,
    command: RedisCommand,
    recorded_args: Vec<Vec<u8>>,
    session: RedisSession,
    session_setup: bool,
    replay_safe: bool,
    warnings: Vec<String>,
    started: Instant,
    request_started_at: chrono::DateTime<Utc>,
    ended_at: Option<Instant>,
}

struct SequencedRedisOutput {
    sequence: u64,
    bytes: Bytes,
    completion: Option<(PendingRedisExchange, RedisFrameKind)>,
}

struct QueuedPush {
    bytes: Bytes,
    capture: Box<dyn CapturedPush>,
}

enum RedisOutput {
    Sequenced(Box<SequencedRedisOutput>),
    PubSubPush {
        push: QueuedPush,
    },
    Terminated {
        exchanges: Vec<PendingRedisExchange>,
        response: Bytes,
        reset: bool,
    },
}

pub async fn run(
    client: TcpStream,
    upstream: TcpStream,
    options: ConnectionOptions,
    host: Arc<dyn CaptureHost>,
) -> Result<()> {
    let ConnectionOptions {
        context,
        connection_id,
        max_frame_bytes,
        client_decoder,
        server_decoder,
        termination,
    } = options;
    let client_control = ConnectionControl::new(&client)?;
    let upstream_control = ConnectionControl::new(&upstream)?;
    let started = Instant::now();
    let session = Arc::new(Mutex::new(RedisSession {
        resp_version: 2,
        database: 0,
        username: None,
        subscriptions: Subscriptions::default(),
    }));
    let pending = Arc::new(Mutex::new(VecDeque::<PendingRedisExchange>::new()));
    let opening_session = session.lock().await.clone();
    record_connection(
        host.as_ref(),
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

    let (client_read, client_write) = client.into_split();
    let (upstream_read, upstream_write) = upstream.into_split();
    let client_write = Arc::new(Mutex::new(client_write));
    // Apply backpressure to long-lived notification streams while the client
    // or recording writer is slower than the upstream. Ordering stays with the writer.
    let (output_tx, output_rx) = mpsc::channel(256);
    let writer = tokio::spawn(run_ordered_writer(
        client_write.clone(),
        output_rx,
        host.clone(),
        context.clone(),
        connection_id,
        termination.clone(),
        client_control,
    ));

    let c2s_pending = pending.clone();
    let c2s_session = session.clone();
    let c2s_host = host.clone();
    let c2s_output = output_tx.clone();
    let c2s_termination = termination.clone();
    let c2s = tokio::spawn(async move {
        let mut reader = BufferedReader::with_session(
            ObservedIo::new(
                client_read,
                c2s_termination.clone(),
                TerminationSide::Client,
            ),
            max_frame_bytes,
            client_decoder,
        );
        let mut upstream_write = ObservedIo::new(
            upstream_write,
            c2s_termination.clone(),
            TerminationSide::Server,
        );
        let mut sequence = 0_u64;
        let mut bytes = 0_u64;
        loop {
            if c2s_host.is_degraded() {
                bytes += forward_buffer_and_copy(
                    &mut reader,
                    &mut upstream_write,
                    None,
                    c2s_host.as_ref(),
                    TerminationSide::Client,
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
                    if is_reset_error(&error) && c2s_termination.observe_client_error(&error) {
                        if reader.buffer.is_empty() {
                            upstream_control.reset()?;
                            break;
                        }
                        c2s_host
                            .degrade("Redis client reset with an incomplete request".to_string());
                        let buffered = reader.buffer.split().freeze();
                        c2s_host.raw_activity(TerminationSide::Client);
                        let _ = upstream_write.write_all(&buffered).await;
                        upstream_control.reset()?;
                        return Err(error);
                    }
                    c2s_host.degrade(format!(
                        "Redis client parse failed; switched to raw forwarding: {error}"
                    ));
                    bytes += forward_buffer_and_copy(
                        &mut reader,
                        &mut upstream_write,
                        None,
                        c2s_host.as_ref(),
                        TerminationSide::Client,
                    )
                    .await?;
                    break;
                }
            };
            if c2s_host.is_degraded() {
                bytes += forward_buffer_and_copy(
                    &mut reader,
                    &mut upstream_write,
                    Some(&frame.raw),
                    c2s_host.as_ref(),
                    TerminationSide::Client,
                )
                .await?;
                break;
            }
            let command = match redis_command(&frame.raw) {
                Ok(command) => command,
                Err(error) => {
                    c2s_host.degrade(format!(
                        "Redis command parse failed; switched to raw forwarding: {error}"
                    ));
                    bytes += forward_buffer_and_copy(
                        &mut reader,
                        &mut upstream_write,
                        Some(&frame.raw),
                        c2s_host.as_ref(),
                        TerminationSide::Client,
                    )
                    .await?;
                    break;
                }
            };
            sequence += 1;
            let current_session = c2s_session.lock().await.clone();
            let decision = c2s_host
                .begin_request(CaptureRequest {
                    connection_id,
                    sequence,
                    command: &command,
                    session: &current_session,
                })
                .await?;
            let CaptureDecision::Admitted(capture) = decision else {
                c2s_output
                    .send(RedisOutput::Sequenced(Box::new(SequencedRedisOutput {
                        sequence,
                        bytes: Bytes::from_static(
                            b"-READONLY request blocked by recording access policy\r\n",
                        ),
                        completion: None,
                    })))
                    .await
                    .map_err(|_| anyhow!("Redis client response writer closed"))?;
                bytes += frame.raw.len() as u64;
                continue;
            };
            let (recorded_args, session_setup, replay_safe, warnings) =
                sanitize_and_classify(&command);
            let mut pending_exchange = PendingRedisExchange {
                capture,
                sequence,
                command,
                recorded_args,
                session: current_session,
                session_setup,
                replay_safe,
                warnings,
                started: Instant::now(),
                request_started_at: Utc::now(),
                ended_at: None,
            };
            if let Some(response) = pending_exchange.capture.cached_response().await? {
                let kind = frame_kind(&response)
                    .context("cached Redis response is not a complete RESP2 frame")?;
                c2s_output
                    .send(RedisOutput::Sequenced(Box::new(SequencedRedisOutput {
                        sequence,
                        bytes: response,
                        completion: Some((pending_exchange, kind)),
                    })))
                    .await
                    .map_err(|_| anyhow!("Redis client response writer closed"))?;
                bytes += frame.raw.len() as u64;
                continue;
            }
            c2s_pending.lock().await.push_back(pending_exchange);
            if let Err(error) = upstream_write.write_all(&frame.raw).await {
                if c2s_termination.snapshot().is_some_and(|observed| {
                    observed.termination.side == TerminationSide::Server
                        && observed.termination.kind == TerminationKind::Reset
                }) {
                    break;
                }
                return Err(error.into());
            }
            bytes += frame.raw.len() as u64;
        }
        let _ = upstream_write.shutdown().await;
        Ok::<u64, anyhow::Error>(bytes)
    });

    let s2c_host = host.clone();
    let s2c_pending = pending.clone();
    let s2c_session = session.clone();
    let s2c_output = output_tx.clone();
    let s2c_client_write = client_write.clone();
    let s2c_termination = termination.clone();
    let s2c = tokio::spawn(async move {
        let mut reader = BufferedReader::with_session(
            ObservedIo::new(
                upstream_read,
                s2c_termination.clone(),
                TerminationSide::Server,
            ),
            max_frame_bytes,
            server_decoder,
        );
        let mut terminal_response = Bytes::new();
        let mut server_reset = false;
        let mut bytes = 0_u64;
        loop {
            let frame = match read_frame(&mut reader).await {
                Ok(Some(frame)) => frame,
                Ok(None) => {
                    s2c_termination.observe_server_eof();
                    break;
                }
                Err(error) => {
                    if s2c_termination.observe_server_error(&error) {
                        server_reset = is_reset_error(&error);
                        terminal_response = reader.buffer.split().freeze();
                        break;
                    }
                    s2c_host.degrade(format!(
                        "Redis server parse failed; switched to raw forwarding: {error}"
                    ));
                    let mut writer = s2c_client_write.lock().await;
                    bytes += forward_buffer_and_copy(
                        &mut reader,
                        &mut *writer,
                        None,
                        s2c_host.as_ref(),
                        TerminationSide::Server,
                    )
                    .await?;
                    break;
                }
            };
            if s2c_host.is_degraded() {
                let mut writer = s2c_client_write.lock().await;
                bytes += forward_buffer_and_copy(
                    &mut reader,
                    &mut *writer,
                    Some(&frame.raw),
                    s2c_host.as_ref(),
                    TerminationSide::Server,
                )
                .await?;
                break;
            }
            let subscriptions_active = s2c_session.lock().await.subscriptions.is_active();
            match parse_pubsub_push(&frame.raw) {
                Ok(Some(push))
                    if subscriptions_active
                        && s2c_session.lock().await.subscriptions.accepts(&push) =>
                {
                    let session = s2c_session.lock().await.clone();
                    let (subscription_sequence, elapsed_ms) =
                        session
                            .subscriptions
                            .anchor(&push)
                            .context("missing subscription anchor")?;
                    let capture = s2c_host.capture_push(PushRequest {
                        session: &session,
                        connection_id,
                        push: &push,
                        bytes: frame.raw.clone(),
                        subscription_sequence,
                        elapsed_ms,
                    })?;
                    s2c_output
                        .send(RedisOutput::PubSubPush {
                            push: QueuedPush {
                                bytes: frame.raw.clone(),
                                capture,
                            },
                        })
                        .await
                        .map_err(|_| anyhow!("Redis client response writer closed"))?;
                    bytes += frame.raw.len() as u64;
                    continue;
                }
                Ok(Some(_)) if subscriptions_active => {
                    s2c_host.degrade(
                        "Redis Pub/Sub push did not match an active subscription; switched to raw forwarding"
                            .to_string(),
                    );
                    let mut writer = s2c_client_write.lock().await;
                    bytes += forward_buffer_and_copy(
                        &mut reader,
                        &mut *writer,
                        Some(&frame.raw),
                        s2c_host.as_ref(),
                        TerminationSide::Server,
                    )
                    .await?;
                    break;
                }
                Err(error) if subscriptions_active => {
                    s2c_host.degrade(format!(
                        "Redis Pub/Sub push parse failed; switched to raw forwarding: {error}"
                    ));
                    let mut writer = s2c_client_write.lock().await;
                    bytes += forward_buffer_and_copy(
                        &mut reader,
                        &mut *writer,
                        Some(&frame.raw),
                        s2c_host.as_ref(),
                        TerminationSide::Server,
                    )
                    .await?;
                    break;
                }
                Ok(Some(_)) | Ok(None) | Err(_) => {}
            }
            let Some(mut exchange) = s2c_pending.lock().await.pop_front() else {
                s2c_host.degrade(
                    "Redis response arrived without a pending request; switched to raw forwarding"
                        .to_string(),
                );
                let mut writer = s2c_client_write.lock().await;
                bytes += forward_buffer_and_copy(
                    &mut reader,
                    &mut *writer,
                    Some(&frame.raw),
                    s2c_host.as_ref(),
                    TerminationSide::Server,
                )
                .await?;
                break;
            };
            let response_sequence = exchange.sequence;
            exchange.session = s2c_session.lock().await.clone();
            let response_is_error = frame.kind == RedisFrameKind::Error;
            exchange
                .capture
                .observe_response(
                    frame.raw.clone(),
                    exchange.replay_safe && !response_is_error,
                )
                .await?;
            if !response_is_error {
                s2c_session.lock().await.apply_successful_setup(
                    &exchange.command,
                    &frame.raw,
                    response_sequence,
                );
            }
            s2c_output
                .send(RedisOutput::Sequenced(Box::new(SequencedRedisOutput {
                    sequence: response_sequence,
                    bytes: frame.raw.clone(),
                    completion: Some((exchange, frame.kind)),
                })))
                .await
                .map_err(|_| anyhow!("Redis client response writer closed"))?;
            bytes += frame.raw.len() as u64;
        }
        let exchanges = { s2c_pending.lock().await.drain(..).collect() };
        s2c_output
            .send(RedisOutput::Terminated {
                exchanges,
                response: terminal_response,
                reset: server_reset,
            })
            .await
            .map_err(|_| anyhow!("Redis client response writer closed before termination"))?;
        Ok::<u64, anyhow::Error>(bytes)
    });

    drop(output_tx);
    let (c2s_result, s2c_result, writer_result) = tokio::join!(c2s, s2c, writer);
    let transfer_result = async {
        let c2s_bytes = c2s_result.context("Redis client task panicked")??;
        let _upstream_bytes = s2c_result.context("Redis server task panicked")??;
        let (s2c_bytes, writer_safe) = writer_result.context("Redis writer task panicked")??;
        Ok::<_, anyhow::Error>((c2s_bytes, s2c_bytes, writer_safe))
    }
    .await;
    let (c2s_bytes, s2c_bytes, writer_safe, mut transfer_error) = match transfer_result {
        Ok((c2s_bytes, s2c_bytes, writer_safe)) => (c2s_bytes, s2c_bytes, writer_safe, None),
        Err(error) => {
            let message = error.to_string();
            host.record_error(message.clone());
            (0, 0, false, Some(message))
        }
    };
    if transfer_error.is_none() {
        transfer_error = host.degradation_reason();
    }
    let mut replay_safe = transfer_error.is_none()
        && writer_safe
        && !termination.engine_stopped()
        && termination
            .snapshot()
            .is_none_or(|observed| observed.termination.side != TerminationSide::Engine);
    let mut incomplete = pending.lock().await;
    while let Some(exchange) = incomplete.pop_front() {
        replay_safe &= record_termination(
            connection_id,
            &context,
            exchange,
            b"",
            &termination,
            transfer_error.is_none(),
        )
        .await?;
    }
    drop(incomplete);
    let closing_session = session.lock().await.clone();
    record_connection(
        host.as_ref(),
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

async fn forward_buffer_and_copy<R, W>(
    reader: &mut BufferedReader<R>,
    writer: &mut W,
    prefix: Option<&[u8]>,
    host: &dyn CaptureHost,
    side: TerminationSide,
) -> Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut copied = 0_u64;
    if let Some(prefix) = prefix.filter(|bytes| !bytes.is_empty()) {
        host.raw_activity(side);
        writer.write_all(prefix).await?;
        copied += prefix.len() as u64;
    }
    let buffered = reader.buffer.split().freeze();
    if !buffered.is_empty() {
        host.raw_activity(side);
        writer.write_all(&buffered).await?;
        copied += buffered.len() as u64;
    }
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let read = reader.inner.read(&mut buffer).await?;
        if read == 0 {
            return Ok(copied);
        }
        host.raw_activity(side);
        writer.write_all(&buffer[..read]).await?;
        copied += read as u64;
    }
}

fn is_reset_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<std::io::Error>().is_some_and(|error| {
            matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::NotConnected
            )
        })
    })
}
