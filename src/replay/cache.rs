use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::cache_protocol::{
    BufferedReader, MemcachedWireProtocol, read_binary_frame, read_redis_frame, read_text_request,
    redis_command,
};

use super::{
    ReplayProtocol, ReplaySource, ReplayState, ReplayTarget, TargetKey, normalize_host,
    register_replay_target, write_report_snapshot,
};

mod builtins;
mod report;
use builtins::{
    binary_error, memcached_is_unsupported, redis_builtin, redis_is_builtin, redis_is_unsupported,
};
pub(super) use report::*;

#[derive(Debug, Clone, Deserialize)]
pub(super) struct RecordedRedisConnection {
    target_host: String,
    target_port: u16,
    replay_safe: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct RecordedRedisExchange {
    connection_id: Uuid,
    sequence: u64,
    target_host: String,
    target_port: u16,
    resp_version: u8,
    database: i64,
    username: Option<String>,
    command: String,
    args: Vec<RecordedCapture>,
    response_kind: String,
    response: RecordedCapture,
    replay_safe: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct RecordedMemcachedConnection {
    target_host: String,
    target_port: u16,
    replay_safe: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct RecordedMemcachedExchange {
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
struct ReplayRedisExchange {
    source: ReplaySource,
    case_id: Option<String>,
    record: RecordedRedisExchange,
    args: Vec<Vec<u8>>,
    response: Vec<u8>,
    consumed: bool,
}

#[derive(Debug, Clone)]
struct ReplayMemcachedExchange {
    source: ReplaySource,
    case_id: Option<String>,
    record: RecordedMemcachedExchange,
    key: Option<Vec<u8>>,
    args: Vec<Vec<u8>>,
    value: Option<Vec<u8>>,
    extras: Option<Vec<u8>>,
    response_frames: Vec<Vec<u8>>,
    consumed: bool,
}

#[derive(Debug, Default)]
pub(super) struct CacheReplayState {
    redis: Vec<ReplayRedisExchange>,
    memcached: Vec<ReplayMemcachedExchange>,
    events: CacheReplayEvents,
}

#[derive(Debug, Default)]
struct CacheReplayEvents {
    redis_connections: usize,
    memcached_connections: usize,
    redis_matched: Vec<CacheMatchedReport>,
    redis_unmatched: Vec<CacheRequestReport>,
    redis_unsupported: Vec<CacheRequestReport>,
    redis_unsafe: Vec<CacheRequestReport>,
    memcached_matched: Vec<CacheMatchedReport>,
    memcached_unmatched: Vec<CacheRequestReport>,
    memcached_unsupported: Vec<CacheRequestReport>,
    memcached_unsafe: Vec<CacheRequestReport>,
}

impl CacheReplayState {
    pub(super) fn register_redis_connection(
        &mut self,
        record: RecordedRedisConnection,
        targets: &mut BTreeMap<TargetKey, ReplayTarget>,
    ) -> Result<()> {
        if !record.replay_safe {
            return Err(anyhow!(
                "unsafe Redis connection metadata for {}:{}",
                record.target_host,
                record.target_port
            ));
        }
        register_cache_target(
            targets,
            &record.target_host,
            record.target_port,
            ReplayProtocol::Redis,
        )
    }

    pub(super) fn register_memcached_connection(
        &mut self,
        record: RecordedMemcachedConnection,
        targets: &mut BTreeMap<TargetKey, ReplayTarget>,
    ) -> Result<()> {
        if !record.replay_safe {
            return Err(anyhow!(
                "unsafe Memcached connection metadata for {}:{}",
                record.target_host,
                record.target_port
            ));
        }
        register_cache_target(
            targets,
            &record.target_host,
            record.target_port,
            ReplayProtocol::Memcached,
        )
    }

    pub(super) fn reject_cache_proxy_error(record: &super::RecordedProxyError) -> Result<()> {
        if matches!(record.protocol.as_str(), "redis" | "memcached") {
            return Err(anyhow!(
                "unsafe {} dependency proxy error: {}",
                record.protocol,
                record.error
            ));
        }
        Ok(())
    }

    pub(super) fn register_redis_exchange(
        &mut self,
        record: RecordedRedisExchange,
        source: ReplaySource,
        case_id: Option<&str>,
        targets: &mut BTreeMap<TargetKey, ReplayTarget>,
    ) -> Result<()> {
        validate_recorded_cache_exchange(
            "redis_exchange",
            &record.command,
            record.replay_safe,
            record.response.truncated || record.args.iter().any(|capture| capture.truncated),
        )?;
        register_cache_target(
            targets,
            &record.target_host,
            record.target_port,
            ReplayProtocol::Redis,
        )?;
        let args = record
            .args
            .iter()
            .map(RecordedCapture::decode)
            .collect::<Result<Vec<_>>>()?;
        let response = record.response.decode()?;
        self.redis.push(ReplayRedisExchange {
            source,
            case_id: case_id.map(ToOwned::to_owned),
            record,
            args,
            response,
            consumed: false,
        });
        Ok(())
    }

    pub(super) fn register_memcached_exchange(
        &mut self,
        record: RecordedMemcachedExchange,
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
        validate_recorded_cache_exchange(
            "memcached_exchange",
            &record.command,
            record.replay_safe,
            truncated,
        )?;
        register_cache_target(
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
        self.memcached.push(ReplayMemcachedExchange {
            source,
            case_id: case_id.map(ToOwned::to_owned),
            record,
            key,
            args,
            value,
            extras,
            response_frames,
            consumed: false,
        });
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn match_redis(
        &mut self,
        active_case_id: Option<&str>,
        target: &TargetKey,
        bound_connection: Option<Uuid>,
        resp_version: u8,
        database: i64,
        username: Option<&str>,
        command: &str,
        args: &[Vec<u8>],
    ) -> Option<(Uuid, Vec<u8>)> {
        let index = preferred_index(&self.redis, active_case_id, |index, exchange| {
            !exchange.consumed
                && redis_is_lane_head(&self.redis, index)
                && bound_connection.is_none_or(|id| exchange.record.connection_id == id)
                && target_matches(
                    target,
                    &exchange.record.target_host,
                    exchange.record.target_port,
                )
                && exchange.record.resp_version == resp_version
                && exchange.record.database == database
                && normalize_optional(username)
                    == normalize_optional(exchange.record.username.as_deref())
                && exchange.record.command.eq_ignore_ascii_case(command)
                && exchange.args == args
        })?;
        let exchange = &mut self.redis[index];
        exchange.consumed = true;
        self.events.redis_matched.push(CacheMatchedReport {
            case_id: exchange.case_id.clone(),
            source: exchange.source,
            index,
            target: target.clone(),
            connection_id: exchange.record.connection_id,
            sequence: exchange.record.sequence,
            command: exchange.record.command.clone(),
        });
        Some((exchange.record.connection_id, exchange.response.clone()))
    }

    #[allow(clippy::too_many_arguments)]
    fn match_redis_builtin_failure(
        &mut self,
        active_case_id: Option<&str>,
        target: &TargetKey,
        bound_connection: Option<Uuid>,
        resp_version: u8,
        database: i64,
        username: Option<&str>,
        command: &crate::cache_protocol::RedisCommand,
    ) -> Option<(Uuid, Vec<u8>)> {
        let index = preferred_index(&self.redis, active_case_id, |index, exchange| {
            !exchange.consumed
                && redis_is_lane_head(&self.redis, index)
                && exchange.record.response_kind == "error"
                && bound_connection.is_none_or(|id| exchange.record.connection_id == id)
                && target_matches(
                    target,
                    &exchange.record.target_host,
                    exchange.record.target_port,
                )
                && exchange.record.resp_version == resp_version
                && exchange.record.database == database
                && normalize_optional(username)
                    == normalize_optional(exchange.record.username.as_deref())
                && exchange.record.command.eq_ignore_ascii_case(&command.name)
                && (matches!(command.name.as_str(), "AUTH" | "HELLO")
                    || exchange.args == command.args)
        })?;
        let exchange = &mut self.redis[index];
        exchange.consumed = true;
        self.events.redis_matched.push(CacheMatchedReport {
            case_id: exchange.case_id.clone(),
            source: exchange.source,
            index,
            target: target.clone(),
            connection_id: exchange.record.connection_id,
            sequence: exchange.record.sequence,
            command: exchange.record.command.clone(),
        });
        Some((exchange.record.connection_id, exchange.response.clone()))
    }

    fn match_memcached(
        &mut self,
        active_case_id: Option<&str>,
        target: &TargetKey,
        bound_connection: Option<Uuid>,
        wire_protocol: MemcachedWireProtocol,
        request: &crate::cache_protocol::MemcachedRequest,
    ) -> Option<(Uuid, Vec<Vec<u8>>, bool)> {
        let wire = wire_protocol.as_str();
        let index = preferred_index(&self.memcached, active_case_id, |index, exchange| {
            !exchange.consumed
                && memcached_is_lane_head(&self.memcached, index)
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
        let exchange = &mut self.memcached[index];
        exchange.consumed = true;
        self.events.memcached_matched.push(CacheMatchedReport {
            case_id: exchange.case_id.clone(),
            source: exchange.source,
            index,
            target: target.clone(),
            connection_id: exchange.record.connection_id,
            sequence: exchange.record.sequence,
            command: exchange.record.command.clone(),
        });
        Some((
            exchange.record.connection_id,
            exchange.response_frames.clone(),
            exchange.record.no_response,
        ))
    }

    pub(super) fn snapshot(&self) -> CacheProtocolsReport {
        CacheProtocolsReport {
            redis: CacheProtocolReport {
                connections: self.events.redis_connections,
                matched: self.events.redis_matched.clone(),
                unmatched: self.events.redis_unmatched.clone(),
                unsupported: self.events.redis_unsupported.clone(),
                unsafe_events: self.events.redis_unsafe.clone(),
                unused_case: redis_unused(&self.redis, ReplaySource::Case),
                unused_bootstrap: redis_unused(&self.redis, ReplaySource::Bootstrap),
                ..Default::default()
            },
            memcached: CacheProtocolReport {
                connections: self.events.memcached_connections,
                matched: self.events.memcached_matched.clone(),
                unmatched: self.events.memcached_unmatched.clone(),
                unsupported: self.events.memcached_unsupported.clone(),
                unsafe_events: self.events.memcached_unsafe.clone(),
                unused_case: memcached_unused(&self.memcached, ReplaySource::Case),
                unused_bootstrap: memcached_unused(&self.memcached, ReplaySource::Bootstrap),
                ..Default::default()
            },
        }
    }
}

pub(super) async fn handle_redis_connection(
    mut stream: TcpStream,
    target: ReplayTarget,
    state: Arc<Mutex<ReplayState>>,
    report_path: Option<PathBuf>,
) -> Result<()> {
    let target_key = TargetKey {
        host: target.host,
        port: target.port,
    };
    state.lock().await.cache.events.redis_connections += 1;
    write_report_snapshot(state.clone(), report_path.clone()).await?;
    let mut reader = BufferedReader::new(&mut stream, 64 * 1024 * 1024);
    let mut resp_version = 2_u8;
    let mut database = 0_i64;
    let mut username: Option<String> = None;
    let mut bound_connection = None;
    loop {
        let frame = match read_redis_frame(&mut reader).await {
            Ok(Some(frame)) => frame,
            Ok(None) => break,
            Err(error) => {
                record_runtime_unsafe(
                    &state,
                    &target_key,
                    "redis",
                    "parse_error",
                    error.to_string(),
                )
                .await;
                write_report_snapshot(state.clone(), report_path.clone()).await?;
                return Err(error);
            }
        };
        let command = match redis_command(&frame.raw) {
            Ok(command) => command,
            Err(error) => {
                record_runtime_unsafe(
                    &state,
                    &target_key,
                    "redis",
                    "parse_error",
                    error.to_string(),
                )
                .await;
                write_report_snapshot(state.clone(), report_path.clone()).await?;
                return Err(error);
            }
        };
        if redis_is_unsupported(&command) {
            let mut replay_state = state.lock().await;
            let case_id = replay_state.active_case_id.clone();
            replay_state
                .cache
                .events
                .redis_unsupported
                .push(CacheRequestReport {
                    case_id,
                    target: target_key.clone(),
                    command: command.name.clone(),
                    reason: "Redis command mode is unsupported for replay".to_string(),
                });
            drop(replay_state);
            reader
                .inner
                .write_all(b"-ERR Redis command mode is unsupported for replay\r\n")
                .await?;
            write_report_snapshot(state.clone(), report_path.clone()).await?;
            continue;
        }
        let recorded_failure = if redis_is_builtin(&command.name) {
            let mut state = state.lock().await;
            let active_case_id = state.active_case_id.clone();
            state.cache.match_redis_builtin_failure(
                active_case_id.as_deref(),
                &target_key,
                bound_connection,
                resp_version,
                database,
                username.as_deref(),
                &command,
            )
        } else {
            None
        };
        if let Some((connection_id, response)) = recorded_failure {
            bound_connection.get_or_insert(connection_id);
            reader.inner.write_all(&response).await?;
            write_report_snapshot(state.clone(), report_path.clone()).await?;
            continue;
        }
        if let Some(response) =
            redis_builtin(&command, &mut resp_version, &mut database, &mut username)
        {
            reader.inner.write_all(&response).await?;
            write_report_snapshot(state.clone(), report_path.clone()).await?;
            if command.name == "QUIT" {
                break;
            }
            continue;
        }
        let response = {
            let mut state = state.lock().await;
            let active_case_id = state.active_case_id.clone();
            match state.cache.match_redis(
                active_case_id.as_deref(),
                &target_key,
                bound_connection,
                resp_version,
                database,
                username.as_deref(),
                &command.name,
                &command.args,
            ) {
                Some((connection_id, response)) => {
                    bound_connection.get_or_insert(connection_id);
                    response
                }
                None => {
                    state.cache.events.redis_unmatched.push(CacheRequestReport {
                        case_id: active_case_id,
                        target: target_key.clone(),
                        command: command.name.clone(),
                        reason: "no recorded Redis exchange matched target/session/arguments"
                            .to_string(),
                    });
                    b"-ERR no recorded Redis dependency matched\r\n".to_vec()
                }
            }
        };
        reader.inner.write_all(&response).await?;
        write_report_snapshot(state.clone(), report_path.clone()).await?;
    }
    Ok(())
}

pub(super) async fn handle_memcached_connection(
    mut stream: TcpStream,
    target: ReplayTarget,
    state: Arc<Mutex<ReplayState>>,
    report_path: Option<PathBuf>,
) -> Result<()> {
    let target_key = TargetKey {
        host: target.host,
        port: target.port,
    };
    state.lock().await.cache.events.memcached_connections += 1;
    write_report_snapshot(state.clone(), report_path.clone()).await?;
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
            let mut reader = BufferedReader::new(&mut stream, 64 * 1024 * 1024);
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
                        write_report_snapshot(state.clone(), report_path.clone()).await?;
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
                    Some((frames, no_response)) => {
                        if !no_response {
                            for frame in frames {
                                reader.inner.write_all(&frame).await?;
                            }
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
                write_report_snapshot(state.clone(), report_path.clone()).await?;
            }
        }
        MemcachedWireProtocol::Binary => {
            let mut reader = BufferedReader::new(&mut stream, 64 * 1024 * 1024);
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
                        write_report_snapshot(state.clone(), report_path.clone()).await?;
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
                        write_report_snapshot(state.clone(), report_path.clone()).await?;
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
                    Some((frames, no_response)) => {
                        if !no_response {
                            for mut response in frames {
                                if response.len() >= 16 {
                                    response[12..16].copy_from_slice(&frame.opaque.to_be_bytes());
                                }
                                reader.inner.write_all(&response).await?;
                            }
                        }
                    }
                    None => {
                        reader
                            .inner
                            .write_all(&binary_error(frame.opcode, frame.opaque))
                            .await?;
                    }
                }
                write_report_snapshot(state.clone(), report_path.clone()).await?;
            }
        }
    }
    Ok(())
}

async fn record_runtime_unsafe(
    state: &Arc<Mutex<ReplayState>>,
    target: &TargetKey,
    protocol: &str,
    command: &str,
    reason: String,
) {
    let mut state = state.lock().await;
    let request = CacheRequestReport {
        case_id: state.active_case_id.clone(),
        target: target.clone(),
        command: command.to_string(),
        reason,
    };
    if protocol == "redis" {
        state.cache.events.redis_unsafe.push(request);
    } else {
        state.cache.events.memcached_unsafe.push(request);
    }
}

async fn match_memcached_request(
    state: &Arc<Mutex<ReplayState>>,
    target: &TargetKey,
    bound_connection: &mut Option<Uuid>,
    wire: MemcachedWireProtocol,
    request: &crate::cache_protocol::MemcachedRequest,
) -> Option<(Vec<Vec<u8>>, bool)> {
    let mut state = state.lock().await;
    let active_case_id = state.active_case_id.clone();
    if memcached_is_unsupported(request) {
        state
            .cache
            .events
            .memcached_unsupported
            .push(CacheRequestReport {
                case_id: active_case_id,
                target: target.clone(),
                command: request.command.clone(),
                reason: "Memcached command mode is unsupported for replay".to_string(),
            });
        return None;
    }
    match state.cache.match_memcached(
        active_case_id.as_deref(),
        target,
        *bound_connection,
        wire,
        request,
    ) {
        Some((connection_id, frames, no_response)) => {
            bound_connection.get_or_insert(connection_id);
            Some((frames, no_response))
        }
        None => {
            state
                .cache
                .events
                .memcached_unmatched
                .push(CacheRequestReport {
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
            return Err(anyhow!("recorded cache capture is truncated"));
        }
        match self.encoding.as_str() {
            "base64" => STANDARD
                .decode(&self.data)
                .context("invalid cache capture base64"),
            "utf8" => Ok(self.data.as_bytes().to_vec()),
            other => Err(anyhow!("unsupported cache capture encoding {other}")),
        }
    }
}

fn register_cache_target(
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

fn validate_recorded_cache_exchange(
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

fn normalize_optional(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase())
}

fn preferred_index<T>(
    exchanges: &[T],
    active_case_id: Option<&str>,
    matches: impl Fn(usize, &T) -> bool,
) -> Option<usize>
where
    T: CacheExchangeScope,
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

fn redis_is_lane_head(exchanges: &[ReplayRedisExchange], candidate: usize) -> bool {
    let exchange = &exchanges[candidate];
    !exchanges.iter().any(|other| {
        !other.consumed
            && other.record.connection_id == exchange.record.connection_id
            && other.record.sequence < exchange.record.sequence
    })
}

fn memcached_is_lane_head(exchanges: &[ReplayMemcachedExchange], candidate: usize) -> bool {
    let exchange = &exchanges[candidate];
    !exchanges.iter().any(|other| {
        !other.consumed
            && other.record.connection_id == exchange.record.connection_id
            && other.record.sequence < exchange.record.sequence
    })
}

trait CacheExchangeScope {
    fn source(&self) -> ReplaySource;
    fn case_id(&self) -> Option<&str>;
}

impl CacheExchangeScope for ReplayRedisExchange {
    fn source(&self) -> ReplaySource {
        self.source
    }

    fn case_id(&self) -> Option<&str> {
        self.case_id.as_deref()
    }
}

impl CacheExchangeScope for ReplayMemcachedExchange {
    fn source(&self) -> ReplaySource {
        self.source
    }

    fn case_id(&self) -> Option<&str> {
        self.case_id.as_deref()
    }
}

fn redis_unused(exchanges: &[ReplayRedisExchange], source: ReplaySource) -> Vec<CacheUnusedReport> {
    exchanges
        .iter()
        .enumerate()
        .filter(|(_, exchange)| exchange.source == source && !exchange.consumed)
        .map(|(index, exchange)| CacheUnusedReport {
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

fn memcached_unused(
    exchanges: &[ReplayMemcachedExchange],
    source: ReplaySource,
) -> Vec<CacheUnusedReport> {
    exchanges
        .iter()
        .enumerate()
        .filter(|(_, exchange)| exchange.source == source && !exchange.consumed)
        .map(|(index, exchange)| CacheUnusedReport {
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
