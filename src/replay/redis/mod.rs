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

use crate::redis::{
    BufferedReader as RedisBufferedReader, RedisCommand, read_frame as read_redis_frame,
    redis_command,
};

use super::{
    ReplayProtocol, ReplaySource, ReplayState, ReplayTarget, TargetKey, normalize_host,
    register_replay_target, write_report_snapshot,
};

mod builtins;
use super::report::command::{
    CommandMatchedReport, CommandProtocolReport, CommandRequestReport, CommandUnusedReport,
};
use builtins::{redis_builtin, redis_is_builtin, redis_is_unsupported};

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
    args: Vec<Vec<u8>>,
    response: Vec<u8>,
    consumed: bool,
}

#[derive(Debug, Default)]
pub(super) struct RedisReplayState {
    exchanges: Vec<ReplayExchange>,
    pub(super) events: RedisReplayEvents,
}

#[derive(Debug, Default)]
pub(super) struct RedisReplayEvents {
    pub(super) connections: usize,
    matched: Vec<CommandMatchedReport>,
    pub(super) unmatched: Vec<CommandRequestReport>,
    pub(super) unsupported: Vec<CommandRequestReport>,
    pub(super) unsafe_events: Vec<CommandRequestReport>,
}

impl RedisReplayState {
    pub(super) fn register_connection(
        &mut self,
        record: RecordedConnection,
        targets: &mut BTreeMap<TargetKey, ReplayTarget>,
    ) -> Result<()> {
        if !record.replay_safe {
            return Err(anyhow!(
                "unsafe Redis connection metadata for {}:{}",
                record.target_host,
                record.target_port
            ));
        }
        register_target(
            targets,
            &record.target_host,
            record.target_port,
            ReplayProtocol::Redis,
        )
    }

    pub(super) fn reject_proxy_error(record: &super::RecordedProxyError) -> Result<()> {
        if record.protocol == "redis" {
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
        validate_recorded_exchange(
            "redis_exchange",
            &record.command,
            record.replay_safe,
            record.response.truncated || record.args.iter().any(|capture| capture.truncated),
        )?;
        register_target(
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
        self.exchanges.push(ReplayExchange {
            source,
            case_id: case_id.map(ToOwned::to_owned),
            record,
            args,
            response,
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
        let index = preferred_index(&self.exchanges, active_case_id, |index, exchange| {
            !exchange.consumed
                && is_lane_head(&self.exchanges, index)
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
        let exchange = &mut self.exchanges[index];
        exchange.consumed = true;
        self.events.matched.push(CommandMatchedReport {
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
        command: &RedisCommand,
    ) -> Option<(Uuid, Vec<u8>)> {
        let index = preferred_index(&self.exchanges, active_case_id, |index, exchange| {
            !exchange.consumed
                && is_lane_head(&self.exchanges, index)
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
        let exchange = &mut self.exchanges[index];
        exchange.consumed = true;
        self.events.matched.push(CommandMatchedReport {
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

    pub(super) fn snapshot(&self) -> CommandProtocolReport {
        CommandProtocolReport {
            connections: self.events.connections,
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
    report_path: Option<PathBuf>,
) -> Result<()> {
    let target_key = TargetKey {
        host: target.host,
        port: target.port,
    };
    state.lock().await.redis.events.connections += 1;
    write_report_snapshot(state.clone(), report_path.clone()).await?;
    let mut reader = RedisBufferedReader::new(&mut stream, 64 * 1024 * 1024);
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
                .redis
                .events
                .unsupported
                .push(CommandRequestReport {
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
            state.redis.match_redis_builtin_failure(
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
            match state.redis.match_redis(
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
                    state.redis.events.unmatched.push(CommandRequestReport {
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

async fn record_runtime_unsafe(
    state: &Arc<Mutex<ReplayState>>,
    target: &TargetKey,
    _protocol: &str,
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
    state.redis.events.unsafe_events.push(request);
}

impl RecordedCapture {
    fn decode(&self) -> Result<Vec<u8>> {
        if self.truncated {
            return Err(anyhow!("recorded Redis capture is truncated"));
        }
        match self.encoding.as_str() {
            "base64" => STANDARD
                .decode(&self.data)
                .context("invalid Redis capture base64"),
            "utf8" => Ok(self.data.as_bytes().to_vec()),
            other => Err(anyhow!("unsupported Redis capture encoding {other}")),
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
        !other.consumed
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
        .filter(|(_, exchange)| exchange.source == source && !exchange.consumed)
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
