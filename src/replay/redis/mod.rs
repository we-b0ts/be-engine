use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::DependencyExchangeOutcome;
use crate::config::process_owned_dependencies::redis_rule_matches;
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
    CaseConnectionBinding, CommandExchangeScope, PreferredMatch,
    is_connection_independent_background, lane_blocked_diagnostic, preferred_match,
    unmatched_diagnostic,
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
    #[serde(default)]
    cache_snapshot_rule: Option<String>,
    #[serde(default)]
    cache_snapshot_hit: bool,
    #[serde(default)]
    global_dependency_reason: Option<String>,
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
    connection_independent: bool,
    reusable_snapshot: bool,
    matched_once: bool,
}

#[derive(Debug, Clone)]
struct MatchedRedisExchange {
    index: usize,
    connection_id: Uuid,
    response: Vec<u8>,
    timing: ReplayExchangeTiming,
    connection_independent: bool,
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
        process_owned_dependencies: &[crate::BackgroundDependencyRuleConfig],
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
        ensure!(
            !record.cache_snapshot_hit,
            "Redis cache snapshot hits are diagnostic events and must not be replay dependencies"
        );
        let reusable_snapshot = match record.cache_snapshot_rule.as_deref() {
            Some(rule_name) => {
                ensure!(
                    source == ReplaySource::Global
                        && record.global_dependency_reason.as_deref() == Some("background_rule"),
                    "Redis cache snapshot seed must be a background Global dependency"
                );
                ensure!(
                    record.outcome == DependencyExchangeOutcome::Response
                        && record.response_kind != "error",
                    "Redis cache snapshot seed must contain a successful response"
                );
                ensure!(
                    process_owned_dependencies.iter().any(|rule| {
                        rule.name() == rule_name
                            && redis_rule_matches(rule, record.target_port, &record.command, &args)
                    }),
                    "Redis cache snapshot seed rule is absent or no longer matches the recording"
                );
                true
            }
            None => false,
        };
        let connection_independent = is_connection_independent_background(
            source,
            record.global_dependency_reason.as_deref(),
        ) || (source == ReplaySource::Global
            && record.global_dependency_reason.as_deref() == Some("bootstrap_window")
            && process_owned_dependencies
                .iter()
                .any(|rule| redis_rule_matches(rule, record.target_port, &record.command, &args)));
        self.exchanges.push(ReplayExchange {
            source,
            case_id: case_id.map(ToOwned::to_owned),
            record,
            args,
            response,
            status: ReplayExchangeStatus::Available,
            timing,
            connection_independent,
            reusable_snapshot,
            matched_once: false,
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
            (exchange.status.is_available()
                || (exchange.reusable_snapshot && exchange.status != ReplayExchangeStatus::Failed))
                && (exchange.connection_independent
                    || bound_connection.is_none_or(|id| exchange.record.connection_id == id))
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
        let timing = if exchange.reusable_snapshot && exchange.matched_once {
            ReplayExchangeTiming::from_recorded(0, DependencyExchangeOutcome::Response)
        } else {
            exchange.timing
        };
        exchange.status = if exchange.reusable_snapshot {
            exchange.status
        } else if exchange.timing.outcome().is_client_terminated() {
            ReplayExchangeStatus::AwaitingClientTermination
        } else {
            ReplayExchangeStatus::Responding
        };
        Ok(MatchedRedisExchange {
            index,
            connection_id: exchange.record.connection_id,
            response: exchange.response.clone(),
            timing,
            connection_independent: exchange.connection_independent,
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
            connection_independent: false,
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
            exchange.matched_once = true;
            if !exchange.reusable_snapshot {
                exchange.status = ReplayExchangeStatus::Consumed;
            }
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
            if !matched.connection_independent {
                connection_binding.bind(recorded_failure_case_id.as_deref(), matched.connection_id);
            }
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
                    if !matched.connection_independent {
                        connection_binding.bind(active_case_id.as_deref(), matched.connection_id);
                    }
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
            || (self.reusable_snapshot && self.status != ReplayExchangeStatus::Failed)
    }

    fn is_consumed(&self) -> bool {
        self.status.is_consumed() || (self.reusable_snapshot && self.matched_once)
    }

    fn preserves_connection_order(&self) -> bool {
        !self.connection_independent
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
    if !exchange.connection_independent
        && bound_connection.is_some_and(|id| exchange.record.connection_id != id)
    {
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
        .filter(|(_, exchange)| {
            exchange.source == source
                && if exchange.reusable_snapshot {
                    !exchange.matched_once
                } else {
                    !exchange.status.is_consumed()
                }
        })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BackgroundDependencyRuleConfig;

    #[test]
    fn cache_snapshot_seed_can_satisfy_repeated_logical_reads() {
        let mut state = RedisReplayState::default();
        let mut targets = BTreeMap::new();
        let rule = BackgroundDependencyRuleConfig::Redis {
            name: "snapshot-get".to_string(),
            ports: vec![6379],
            command: "GET".to_string(),
            keys: vec!["key".to_string()],
            key_patterns: Vec::new(),
            key_prefix: String::new(),
            key_suffix: String::new(),
            initial_load_timeout_ms: Some(1_000),
            fields: Vec::new(),
            source_revision: "abcdef1".to_string(),
            source_evidence: "Cache.java:42".to_string(),
        };
        state
            .register_exchange(
                RecordedExchange {
                    connection_id: Uuid::new_v4(),
                    sequence: 1,
                    target_host: "redis.test".to_string(),
                    target_port: 6379,
                    resp_version: 2,
                    database: 0,
                    username: None,
                    command: "GET".to_string(),
                    args: vec![capture("key")],
                    response_kind: "bulk_string".to_string(),
                    response: capture("$2\r\nv1\r\n"),
                    outcome: DependencyExchangeOutcome::Response,
                    duration_ms: 1,
                    replay_safe: true,
                    cache_snapshot_rule: Some("snapshot-get".to_string()),
                    cache_snapshot_hit: false,
                    global_dependency_reason: Some("background_rule".to_string()),
                },
                ReplaySource::Global,
                None,
                &mut targets,
                std::slice::from_ref(&rule),
            )
            .unwrap();

        let target = TargetKey {
            host: "redis.test".to_string(),
            port: 6379,
        };
        for _ in 0..2 {
            let matched = state
                .match_redis(None, &target, None, 2, 0, None, "GET", &[b"key".to_vec()])
                .unwrap();
            assert_eq!(matched.response, b"$2\r\nv1\r\n");
            state.complete_exchange(&matched);
        }

        let report = state.snapshot();
        assert_eq!(report.matched_count, 2);
        assert!(report.unused_global.is_empty());
    }

    fn capture(data: &str) -> RecordedCapture {
        RecordedCapture {
            encoding: "utf8".to_string(),
            data: data.to_string(),
            truncated: false,
        }
    }
}
