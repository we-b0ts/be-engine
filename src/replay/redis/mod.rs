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

use crate::DependencyExchangeOutcome;
use crate::redis::{
    BufferedReader as RedisBufferedReader, RedisCommand, read_frame as read_redis_frame,
    redis_command,
};

use super::{
    ReplayExchangeStatus, ReplayExchangeTiming, ReplayProtocol, ReplayReportWriter, ReplaySource,
    ReplayState, ReplayTarget, TargetKey, normalize_host, push_success_detail,
    register_replay_target,
};

mod builtins;
use super::command_matching::{
    CaseConnectionBinding, CommandExchangeScope, PreferredMatch, lane_blocked_diagnostic,
    preferred_match, unmatched_diagnostic,
};
use super::report::command::{
    CommandMatchDiagnostic, CommandMatchedReport, CommandProtocolReport, CommandRequestReport,
    CommandUnusedReport,
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
    args: Vec<Vec<u8>>,
    response: Vec<u8>,
    status: ReplayExchangeStatus,
    timing: ReplayExchangeTiming,
}

#[derive(Debug, Clone)]
struct MatchedRedisExchange {
    index: usize,
    connection_id: Uuid,
    response: Vec<u8>,
    timing: ReplayExchangeTiming,
    report: CommandMatchedReport,
}

#[derive(Debug, Default)]
pub(super) struct RedisReplayState {
    exchanges: Vec<ReplayExchange>,
    pub(super) events: RedisReplayEvents,
}

#[derive(Debug, Default)]
pub(super) struct RedisReplayEvents {
    pub(super) connections: usize,
    matched_count: usize,
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
        let timing = ReplayExchangeTiming::from_recorded(record.duration_ms, record.outcome);
        self.exchanges.push(ReplayExchange {
            source,
            case_id: case_id.map(ToOwned::to_owned),
            record,
            args,
            response,
            status: ReplayExchangeStatus::Available,
            timing,
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
    ) -> std::result::Result<MatchedRedisExchange, CommandMatchDiagnostic> {
        let matched = preferred_match(&self.exchanges, active_case_id, |exchange| {
            exchange.status.is_available()
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
        });
        let index = match matched {
            PreferredMatch::Matched(index) => index,
            PreferredMatch::LaneBlocked { candidate, blocker } => {
                return Err(lane_blocked_diagnostic(&self.exchanges, candidate, blocker));
            }
            PreferredMatch::NotFound => {
                return Err(unmatched_diagnostic(
                    &self.exchanges,
                    active_case_id,
                    |exchange| {
                        redis_mismatch_fields(
                            exchange,
                            target,
                            bound_connection,
                            resp_version,
                            database,
                            username,
                            command,
                            args,
                        )
                    },
                ));
            }
        };
        let exchange = &mut self.exchanges[index];
        exchange.status = if exchange.timing.outcome().is_client_terminated() {
            ReplayExchangeStatus::AwaitingClientTermination
        } else {
            ReplayExchangeStatus::Responding
        };
        Ok(MatchedRedisExchange {
            index,
            connection_id: exchange.record.connection_id,
            response: exchange.response.clone(),
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
    ) -> Option<MatchedRedisExchange> {
        let index = match preferred_match(&self.exchanges, active_case_id, |exchange| {
            exchange.status.is_available()
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
        }) {
            PreferredMatch::Matched(index) => index,
            PreferredMatch::LaneBlocked { .. } | PreferredMatch::NotFound => return None,
        };
        let exchange = &mut self.exchanges[index];
        exchange.status = if exchange.timing.outcome().is_client_terminated() {
            ReplayExchangeStatus::AwaitingClientTermination
        } else {
            ReplayExchangeStatus::Responding
        };
        Some(MatchedRedisExchange {
            index,
            connection_id: exchange.record.connection_id,
            response: exchange.response.clone(),
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

    fn complete_exchange(&mut self, matched: &MatchedRedisExchange) {
        if let Some(exchange) = self.exchanges.get_mut(matched.index) {
            exchange.status = ReplayExchangeStatus::Consumed;
        }
        push_success_detail(
            &mut self.events.matched_count,
            &mut self.events.matched,
            matched.report.clone(),
        );
    }

    fn fail_exchange(&mut self, matched: &MatchedRedisExchange, reason: String) {
        if let Some(exchange) = self.exchanges.get_mut(matched.index) {
            exchange.status = ReplayExchangeStatus::Failed;
        }
        self.events.unsafe_events.push(CommandRequestReport {
            case_id: matched.report.case_id.clone(),
            target: matched.report.target.clone(),
            command: matched.report.command.clone(),
            reason,
            diagnostic: None,
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
            unused_global: unused(&self.exchanges, ReplaySource::Global),
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
    state.lock().await.redis.events.connections += 1;
    report_writer.request();
    let mut reader = RedisBufferedReader::new(&mut stream, 64 * 1024 * 1024);
    let mut resp_version = 2_u8;
    let mut database = 0_i64;
    let mut username: Option<String> = None;
    let mut connection_binding = CaseConnectionBinding::default();
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
                report_writer.request();
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
                report_writer.request();
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
                    diagnostic: None,
                });
            drop(replay_state);
            reader
                .inner
                .write_all(b"-ERR Redis command mode is unsupported for replay\r\n")
                .await?;
            report_writer.request();
            continue;
        }
        let (recorded_failure_case_id, recorded_failure) = if redis_is_builtin(&command.name) {
            let mut state = state.lock().await;
            let active_case_id = state.active_case_id.clone();
            let bound_connection = connection_binding.connection(active_case_id.as_deref());
            let matched = state.redis.match_redis_builtin_failure(
                active_case_id.as_deref(),
                &target_key,
                bound_connection,
                resp_version,
                database,
                username.as_deref(),
                &command,
            );
            (active_case_id, matched)
        } else {
            (None, None)
        };
        if let Some(matched) = recorded_failure {
            connection_binding.bind(recorded_failure_case_id.as_deref(), matched.connection_id);
            if deliver_redis_exchange(&mut reader, &state, &matched).await? {
                report_writer.request();
                break;
            }
            report_writer.request();
            continue;
        }
        if let Some(response) =
            redis_builtin(&command, &mut resp_version, &mut database, &mut username)
        {
            reader.inner.write_all(&response).await?;
            report_writer.request();
            if command.name == "QUIT" {
                break;
            }
            continue;
        }
        let response = {
            let mut state = state.lock().await;
            let active_case_id = state.active_case_id.clone();
            let bound_connection = connection_binding.connection(active_case_id.as_deref());
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
                Ok(matched) => {
                    connection_binding.bind(active_case_id.as_deref(), matched.connection_id);
                    Some(matched)
                }
                Err(diagnostic) => {
                    state.redis.events.unmatched.push(CommandRequestReport {
                        case_id: active_case_id,
                        target: target_key.clone(),
                        command: command.name.clone(),
                        reason: "no recorded Redis exchange matched target/session/arguments"
                            .to_string(),
                        diagnostic: Some(diagnostic),
                    });
                    None
                }
            }
        };
        if let Some(matched) = response {
            if deliver_redis_exchange(&mut reader, &state, &matched).await? {
                report_writer.request();
                break;
            }
        } else {
            reader
                .inner
                .write_all(b"-ERR no recorded Redis dependency matched\r\n")
                .await?;
        }
        report_writer.request();
    }
    Ok(())
}

async fn deliver_redis_exchange(
    reader: &mut RedisBufferedReader<&mut TcpStream>,
    state: &Arc<Mutex<ReplayState>>,
    matched: &MatchedRedisExchange,
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
                return Err(error);
            }
        }
    }

    matched.timing.delay_response().await;
    if let Err(error) = reader.inner.write_all(&matched.response).await {
        state.lock().await.redis.fail_exchange(
            matched,
            format!("failed to deliver recorded Redis response: {error}"),
        );
        return Err(error.into());
    }
    state.lock().await.redis.complete_exchange(matched);
    Ok(false)
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
        diagnostic: None,
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

impl CommandExchangeScope for ReplayExchange {
    fn source(&self) -> ReplaySource {
        self.source
    }

    fn case_id(&self) -> Option<&str> {
        self.case_id.as_deref()
    }

    fn connection_id(&self) -> Uuid {
        self.record.connection_id
    }

    fn sequence(&self) -> u64 {
        self.record.sequence
    }

    fn command(&self) -> &str {
        &self.record.command
    }

    fn is_available(&self) -> bool {
        self.status.is_available()
    }

    fn is_consumed(&self) -> bool {
        self.status.is_consumed()
    }
}

#[allow(clippy::too_many_arguments)]
fn redis_mismatch_fields(
    exchange: &ReplayExchange,
    target: &TargetKey,
    bound_connection: Option<Uuid>,
    resp_version: u8,
    database: i64,
    username: Option<&str>,
    command: &str,
    args: &[Vec<u8>],
) -> Vec<&'static str> {
    let mut fields = Vec::new();
    if bound_connection.is_some_and(|id| exchange.record.connection_id != id) {
        fields.push("connection");
    }
    if !target_matches(
        target,
        &exchange.record.target_host,
        exchange.record.target_port,
    ) {
        fields.push("target");
    }
    if exchange.record.resp_version != resp_version
        || exchange.record.database != database
        || normalize_optional(username) != normalize_optional(exchange.record.username.as_deref())
    {
        fields.push("session");
    }
    if !exchange.record.command.eq_ignore_ascii_case(command) {
        fields.push("command");
    }
    if exchange.args != args {
        fields.push("arguments");
    }
    fields
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
