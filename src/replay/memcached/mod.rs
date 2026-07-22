use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use uuid::Uuid;

use super::{
    ReplayExchangeStatus, ReplayExchangeTiming, ReplayProtocol, ReplayReportWriter, ReplaySource,
    ReplayState, ReplayTarget, TargetKey, normalize_host, push_success_detail,
    register_replay_target,
};
use crate::DependencyExchangeOutcome;
use crate::memcached::{
    BufferedReader as MemcachedBufferedReader, MemcachedRequest, MemcachedWireProtocol,
    read_binary_frame, read_text_request,
};

mod builtins;
use super::report::command::{
    CommandMatchedReport, CommandProtocolReport, CommandRequestReport, CommandUnusedReport,
};
use builtins::{binary_error, memcached_is_unsupported};

#[derive(Debug, Clone, Deserialize)]
pub(super) struct RecordedConnection {
    target_host: String,
    target_port: u16,
    replay_safe: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct RecordedExchange {
    connection_id: Uuid,
    sequence: u64,
    target_host: String,
    target_port: u16,
    wire_protocol: String,
    command: String,
    opcode: Option<u8>,
    key: Option<RecordedCapture>,
    #[serde(default)]
    args: Vec<RecordedCapture>,
    value: Option<RecordedCapture>,
    extras: Option<RecordedCapture>,
    cas: Option<u64>,
    quiet: bool,
    noreply: bool,
    #[serde(default)]
    response_frames: Vec<RecordedCapture>,
    no_response: bool,
    #[serde(default)]
    outcome: DependencyExchangeOutcome,
    #[serde(default)]
    duration_ms: u64,
    replay_safe: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct RecordedCapture {
    encoding: String,
    data: String,
    #[serde(default)]
    truncated: bool,
}

#[derive(Debug, Clone)]
struct ReplayExchange {
    source: ReplaySource,
    case_id: Option<String>,
    record: RecordedExchange,
    key: Option<Vec<u8>>,
    args: Vec<Vec<u8>>,
    value: Option<Vec<u8>>,
    extras: Option<Vec<u8>>,
    response_frames: Vec<Vec<u8>>,
    status: ReplayExchangeStatus,
    timing: ReplayExchangeTiming,
}

#[derive(Debug, Clone)]
struct MatchedMemcachedExchange {
    index: usize,
    connection_id: Uuid,
    response_frames: Vec<Vec<u8>>,
    timing: ReplayExchangeTiming,
    report: CommandMatchedReport,
}

#[derive(Debug, Default)]
pub(super) struct MemcachedReplayState {
    exchanges: Vec<ReplayExchange>,
    pub(super) events: MemcachedReplayEvents,
}

#[derive(Debug, Default)]
pub(super) struct MemcachedReplayEvents {
    pub(super) connections: usize,
    matched_count: usize,
    matched: Vec<CommandMatchedReport>,
    pub(super) unmatched: Vec<CommandRequestReport>,
    pub(super) unsupported: Vec<CommandRequestReport>,
    pub(super) unsafe_events: Vec<CommandRequestReport>,
}

impl MemcachedReplayState {
    pub(super) fn register_connection(
        &mut self,
        record: RecordedConnection,
        targets: &mut BTreeMap<TargetKey, ReplayTarget>,
    ) -> Result<()> {
        if !record.replay_safe {
            return Err(anyhow!(
                "unsafe Memcached connection metadata for {}:{}",
                record.target_host,
                record.target_port
            ));
        }
        register_target(
            targets,
            &record.target_host,
            record.target_port,
            ReplayProtocol::Memcached,
        )
    }

    pub(super) fn reject_proxy_error(record: &super::RecordedProxyError) -> Result<()> {
        if record.protocol == "memcached" {
            return Err(anyhow!(
                "unsafe {} dependency proxy error: {}",
                record.protocol,
                record.error
            ));
        }
        Ok(())
    }

    pub(super) fn register_exchange(
        &mut self,
        record: RecordedExchange,
        source: ReplaySource,
        case_id: Option<&str>,
        targets: &mut BTreeMap<TargetKey, ReplayTarget>,
    ) -> Result<()> {
        let truncated = record.key.as_ref().is_some_and(|capture| capture.truncated)
            || record
                .value
                .as_ref()
                .is_some_and(|capture| capture.truncated)
            || record
                .extras
                .as_ref()
                .is_some_and(|capture| capture.truncated)
            || record.args.iter().any(|capture| capture.truncated)
            || record
                .response_frames
                .iter()
                .any(|capture| capture.truncated);
        validate_recorded_exchange(
            "memcached_exchange",
            &record.command,
            record.replay_safe,
            truncated,
        )?;
        register_target(
            targets,
            &record.target_host,
            record.target_port,
            ReplayProtocol::Memcached,
        )?;
        let key = record
            .key
            .as_ref()
            .map(RecordedCapture::decode)
            .transpose()?;
        let args = record
            .args
            .iter()
            .map(RecordedCapture::decode)
            .collect::<Result<Vec<_>>>()?;
        let value = record
            .value
            .as_ref()
            .map(RecordedCapture::decode)
            .transpose()?;
        let extras = record
            .extras
            .as_ref()
            .map(RecordedCapture::decode)
            .transpose()?;
        let response_frames = record
            .response_frames
            .iter()
            .map(RecordedCapture::decode)
            .collect::<Result<Vec<_>>>()?;
        let outcome = if record.no_response {
            DependencyExchangeOutcome::NoResponse
        } else {
            record.outcome
        };
        let timing = ReplayExchangeTiming::from_recorded(record.duration_ms, outcome);
        self.exchanges.push(ReplayExchange {
            source,
            case_id: case_id.map(ToOwned::to_owned),
            record,
            key,
            args,
            value,
            extras,
            response_frames,
            status: ReplayExchangeStatus::Available,
            timing,
        });
        Ok(())
    }

    fn match_memcached(
        &mut self,
        active_case_id: Option<&str>,
        target: &TargetKey,
        bound_connection: Option<Uuid>,
        wire_protocol: MemcachedWireProtocol,
        request: &MemcachedRequest,
    ) -> Option<MatchedMemcachedExchange> {
        let wire = wire_protocol.as_str();
        let index = preferred_index(&self.exchanges, active_case_id, |index, exchange| {
            exchange.status.is_available()
                && is_lane_head(&self.exchanges, index)
                && bound_connection.is_none_or(|id| exchange.record.connection_id == id)
                && target_matches(
                    target,
                    &exchange.record.target_host,
                    exchange.record.target_port,
                )
                && exchange.record.wire_protocol == wire
                && exchange
                    .record
                    .command
                    .eq_ignore_ascii_case(&request.command)
                && exchange.record.opcode == request.opcode
                && exchange.key == request.key
                && exchange.args == request.args
                && exchange.value == request.value
                && exchange.extras == request.extras
                && exchange.record.cas == request.cas
                && exchange.record.quiet == request.quiet
                && exchange.record.noreply == request.noreply
        })?;
        let exchange = &mut self.exchanges[index];
        exchange.status = if exchange.timing.outcome().is_client_terminated() {
            ReplayExchangeStatus::AwaitingClientTermination
        } else {
            ReplayExchangeStatus::Responding
        };
        Some(MatchedMemcachedExchange {
            index,
            connection_id: exchange.record.connection_id,
            response_frames: exchange.response_frames.clone(),
            timing: exchange.timing,
            report: CommandMatchedReport {
                case_id: exchange.case_id.clone(),
                source: exchange.source,
                index,
                target: target.clone(),
                connection_id: exchange.record.connection_id,
                sequence: exchange.record.sequence,
                command: exchange.record.command.clone(),
            },
        })
    }

    fn complete_exchange(&mut self, matched: &MatchedMemcachedExchange) {
        if let Some(exchange) = self.exchanges.get_mut(matched.index) {
            exchange.status = ReplayExchangeStatus::Consumed;
        }
        push_success_detail(
            &mut self.events.matched_count,
            &mut self.events.matched,
            matched.report.clone(),
        );
    }

    fn fail_exchange(&mut self, matched: &MatchedMemcachedExchange, reason: String) {
        if let Some(exchange) = self.exchanges.get_mut(matched.index) {
            exchange.status = ReplayExchangeStatus::Failed;
        }
        self.events.unsafe_events.push(CommandRequestReport {
            case_id: matched.report.case_id.clone(),
            target: matched.report.target.clone(),
            command: matched.report.command.clone(),
            reason,
        });
    }

    pub(super) fn snapshot(&self) -> CommandProtocolReport {
        CommandProtocolReport {
            connections: self.events.connections,
            matched_count: self.events.matched_count,
            matched: self.events.matched.clone(),
            unmatched: self.events.unmatched.clone(),
            unsupported: self.events.unsupported.clone(),
            unsafe_events: self.events.unsafe_events.clone(),
            unused_case: unused(&self.exchanges, ReplaySource::Case),
            unused_bootstrap: unused(&self.exchanges, ReplaySource::Bootstrap),
            ..Default::default()
        }
    }
}

pub(super) async fn handle_connection(
    mut stream: TcpStream,
    target: ReplayTarget,
    state: Arc<Mutex<ReplayState>>,
    report_writer: ReplayReportWriter,
) -> Result<()> {
    let target_key = TargetKey {
        host: target.host,
        port: target.port,
    };
    state.lock().await.memcached.events.connections += 1;
    report_writer.request();
    let mut prefix = [0_u8; 1];
    let len = stream.peek(&mut prefix).await?;
    if len == 0 {
        return Ok(());
    }
    let wire = if prefix[0] == 0x80 {
        MemcachedWireProtocol::Binary
    } else {
        MemcachedWireProtocol::Text
    };
    let mut bound_connection = None;
    match wire {
        MemcachedWireProtocol::Text => {
            let mut reader = MemcachedBufferedReader::new(&mut stream, 64 * 1024 * 1024);
            loop {
                let request = match read_text_request(&mut reader).await {
                    Ok(Some(request)) => request,
                    Ok(None) => break,
                    Err(error) => {
                        record_runtime_unsafe(
                            &state,
                            &target_key,
                            "memcached",
                            "parse_error",
                            error.to_string(),
                        )
                        .await;
                        report_writer.request();
                        return Err(error);
                    }
                };
                let matched = match_memcached_request(
                    &state,
                    &target_key,
                    &mut bound_connection,
                    wire,
                    &request,
                )
                .await;
                match matched {
                    Some(matched) => {
                        if deliver_memcached_exchange(&mut reader, &state, &matched).await? {
                            report_writer.request();
                            break;
                        }
                    }
                    None => {
                        if !request.noreply {
                            reader
                                .inner
                                .write_all(
                                    b"SERVER_ERROR no recorded Memcached dependency matched\r\n",
                                )
                                .await?;
                        }
                    }
                }
                report_writer.request();
            }
        }
        MemcachedWireProtocol::Binary => {
            let mut reader = MemcachedBufferedReader::new(&mut stream, 64 * 1024 * 1024);
            loop {
                let frame = match read_binary_frame(&mut reader).await {
                    Ok(Some(frame)) => frame,
                    Ok(None) => break,
                    Err(error) => {
                        record_runtime_unsafe(
                            &state,
                            &target_key,
                            "memcached",
                            "parse_error",
                            error.to_string(),
                        )
                        .await;
                        report_writer.request();
                        return Err(error);
                    }
                };
                let request = match frame.as_request() {
                    Ok(request) => request,
                    Err(error) => {
                        record_runtime_unsafe(
                            &state,
                            &target_key,
                            "memcached",
                            "parse_error",
                            error.to_string(),
                        )
                        .await;
                        report_writer.request();
                        return Err(error);
                    }
                };
                let matched = match_memcached_request(
                    &state,
                    &target_key,
                    &mut bound_connection,
                    wire,
                    &request,
                )
                .await;
                match matched {
                    Some(mut matched) => {
                        for response in &mut matched.response_frames {
                            if response.len() >= 16 {
                                response[12..16].copy_from_slice(&frame.opaque.to_be_bytes());
                            }
                        }
                        if deliver_memcached_exchange(&mut reader, &state, &matched).await? {
                            report_writer.request();
                            break;
                        }
                    }
                    None => {
                        reader
                            .inner
                            .write_all(&binary_error(frame.opcode, frame.opaque))
                            .await?;
                    }
                }
                report_writer.request();
            }
        }
    }
    Ok(())
}

async fn deliver_memcached_exchange(
    reader: &mut MemcachedBufferedReader<&mut TcpStream>,
    state: &Arc<Mutex<ReplayState>>,
    matched: &MatchedMemcachedExchange,
) -> Result<bool> {
    if matched.timing.outcome().is_client_terminated() {
        let result = if reader.buffer.is_empty() {
            matched
                .timing
                .await_client_termination(&mut reader.inner)
                .await
                .map(|_| ())
        } else {
            Err(anyhow!(
                "client sent another Memcached request instead of terminating the connection"
            ))
        };
        match result {
            Ok(()) => {
                state.lock().await.memcached.complete_exchange(matched);
                return Ok(true);
            }
            Err(error) => {
                state
                    .lock()
                    .await
                    .memcached
                    .fail_exchange(matched, error.to_string());
                return Err(error);
            }
        }
    }

    matched.timing.delay_response().await;
    for response in &matched.response_frames {
        if let Err(error) = reader.inner.write_all(response).await {
            state.lock().await.memcached.fail_exchange(
                matched,
                format!("failed to deliver recorded Memcached response: {error}"),
            );
            return Err(error.into());
        }
    }
    state.lock().await.memcached.complete_exchange(matched);
    Ok(false)
}

async fn record_runtime_unsafe(
    state: &Arc<Mutex<ReplayState>>,
    target: &TargetKey,
    protocol: &str,
    command: &str,
    reason: String,
) {
    let mut state = state.lock().await;
    let request = CommandRequestReport {
        case_id: state.active_case_id.clone(),
        target: target.clone(),
        command: command.to_string(),
        reason,
    };
    let _ = protocol;
    state.memcached.events.unsafe_events.push(request);
}

async fn match_memcached_request(
    state: &Arc<Mutex<ReplayState>>,
    target: &TargetKey,
    bound_connection: &mut Option<Uuid>,
    wire: MemcachedWireProtocol,
    request: &MemcachedRequest,
) -> Option<MatchedMemcachedExchange> {
    let mut state = state.lock().await;
    let active_case_id = state.active_case_id.clone();
    if memcached_is_unsupported(request) {
        state
            .memcached
            .events
            .unsupported
            .push(CommandRequestReport {
                case_id: active_case_id,
                target: target.clone(),
                command: request.command.clone(),
                reason: "Memcached command mode is unsupported for replay".to_string(),
            });
        return None;
    }
    match state.memcached.match_memcached(
        active_case_id.as_deref(),
        target,
        *bound_connection,
        wire,
        request,
    ) {
        Some(matched) => {
            bound_connection.get_or_insert(matched.connection_id);
            Some(matched)
        }
        None => {
            state.memcached.events.unmatched.push(CommandRequestReport {
                case_id: active_case_id,
                target: target.clone(),
                command: request.command.clone(),
                reason: "no recorded Memcached exchange matched target/protocol/arguments"
                    .to_string(),
            });
            None
        }
    }
}

impl RecordedCapture {
    fn decode(&self) -> Result<Vec<u8>> {
        if self.truncated {
            return Err(anyhow!("recorded Memcached capture is truncated"));
        }
        match self.encoding.as_str() {
            "base64" => STANDARD
                .decode(&self.data)
                .context("invalid Memcached capture base64"),
            "utf8" => Ok(self.data.as_bytes().to_vec()),
            other => Err(anyhow!("unsupported Memcached capture encoding {other}")),
        }
    }
}

fn register_target(
    targets: &mut BTreeMap<TargetKey, ReplayTarget>,
    host: &str,
    port: u16,
    protocol: ReplayProtocol,
) -> Result<()> {
    register_replay_target(
        targets,
        &TargetKey {
            host: normalize_host(host),
            port,
        },
        protocol,
    )
}

fn validate_recorded_exchange(
    event_type: &str,
    command: &str,
    replay_safe: bool,
    truncated: bool,
) -> Result<()> {
    if !replay_safe || truncated {
        return Err(anyhow!(
            "{event_type} command {command} contains unsafe or truncated replay evidence"
        ));
    }
    Ok(())
}

fn target_matches(target: &TargetKey, host: &str, port: u16) -> bool {
    target.host == normalize_host(host) && target.port == port
}

fn preferred_index<T>(
    exchanges: &[T],
    active_case_id: Option<&str>,
    matches: impl Fn(usize, &T) -> bool,
) -> Option<usize>
where
    T: ExchangeScope,
{
    exchanges
        .iter()
        .enumerate()
        .find(|(index, exchange)| {
            exchange.source() == ReplaySource::Case
                && exchange.case_id() == active_case_id
                && matches(*index, exchange)
        })
        .map(|(index, _)| index)
        .or_else(|| {
            exchanges
                .iter()
                .enumerate()
                .find(|(index, exchange)| {
                    exchange.source() == ReplaySource::Bootstrap && matches(*index, exchange)
                })
                .map(|(index, _)| index)
        })
}

fn is_lane_head(exchanges: &[ReplayExchange], candidate: usize) -> bool {
    let exchange = &exchanges[candidate];
    !exchanges.iter().any(|other| {
        !other.status.is_consumed()
            && other.record.connection_id == exchange.record.connection_id
            && other.record.sequence < exchange.record.sequence
    })
}

trait ExchangeScope {
    fn source(&self) -> ReplaySource;
    fn case_id(&self) -> Option<&str>;
}

impl ExchangeScope for ReplayExchange {
    fn source(&self) -> ReplaySource {
        self.source
    }

    fn case_id(&self) -> Option<&str> {
        self.case_id.as_deref()
    }
}

fn unused(exchanges: &[ReplayExchange], source: ReplaySource) -> Vec<CommandUnusedReport> {
    exchanges
        .iter()
        .enumerate()
        .filter(|(_, exchange)| exchange.source == source && !exchange.status.is_consumed())
        .map(|(index, exchange)| CommandUnusedReport {
            index,
            case_id: exchange.case_id.clone(),
            source,
            target: TargetKey {
                host: normalize_host(&exchange.record.target_host),
                port: exchange.record.target_port,
            },
            connection_id: exchange.record.connection_id,
            sequence: exchange.record.sequence,
            command: exchange.record.command.clone(),
        })
        .collect()
}
