use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::DependencyExchangeOutcome;
use crate::config::process_owned_dependencies::redis_rule_matches;
use crate::redis::{
    BufferedReader as RedisBufferedReader, RedisCommand, RedisFrameKind,
    frame_kind as redis_frame_kind, is_pubsub_command, read_frame as read_redis_frame,
    redis_command, validate_subscription_confirmation,
};

use super::{
    CaseExchangeIndex, ReplayExchangeStatus, ReplayExchangeTiming, ReplayProtocol, ReplaySource,
    ReplayState, ReplayTarget, SuccessDetailBudget, TargetKey, normalize_host, push_success_detail,
    register_replay_target,
};

mod builtins;
mod connection_scope;
pub(in crate::replay) mod cross_case;
use crate::replay::json_order as json;
pub(in crate::replay) use cross_case::load as load_cross_case;
pub(in crate::replay) mod key_selector;
#[cfg(test)]
mod lane_tests;
pub(crate) mod lock;
mod matching;
pub(crate) mod publish;
pub(crate) mod time_shift;
pub(crate) mod value;
use connection_scope::{ConnectionScopes, TargetConnection};
use matching::redis_authentication_hint;
pub(super) mod snapshot_overlay;
use super::command_matching::{CaseConnectionBinding, is_connection_independent_background};
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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(super) struct RecordedExchange {
    #[serde(default)]
    timestamp: Option<chrono::DateTime<chrono::Utc>>,
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
    session_setup: bool,
    #[serde(default)]
    global_dependency_reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct RecordedCapture {
    encoding: String,
    data: String,
    #[serde(default)]
    truncated: bool,
}

#[derive(Debug, Clone)]
struct ReplayExchange {
    response_time_shift: Option<time_shift::ResponseShift>,
    shared_rule_id: Option<String>,
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
    response_time_shift: Option<time_shift::ResponseShift>,
    index: usize,
    connection_id: Uuid,
    response: Vec<u8>,
    timing: ReplayExchangeTiming,
    requires_binding: bool,
    report: CommandMatchedReport,
    rule_ids: Vec<String>,
}

#[derive(Debug, Default)]
pub(super) struct RedisReplayState {
    pub(super) request_contracts: super::policy::request_contract::RequestContracts,
    pub(super) dynamic_values: super::policy::dynamic_values::DynamicValues,
    time_shifts: Vec<time_shift::TimeShiftObservation>,
    connection_scopes: ConnectionScopes,
    pub(super) value_rules: Vec<value::ValueRule>,
    unordered_value: value::evidence::OrderEvidence,
    lock_tokens: lock::LockTokens,
    lock_evidence: lock::evidence::LockEvidence,
    publish_rules: publish::PublishRules,
    publish_evidence: publish::evidence::PublishEvidence,
    exchanges: Vec<ReplayExchange>,
    case_exchange_index: CaseExchangeIndex,
    pub(super) events: RedisReplayEvents,
    snapshot_overlays: Vec<super::report::command::CommandSnapshotOverlayReport>,
    snapshot_overlay_warnings: Vec<String>,
}

#[derive(Debug, Default)]
pub(super) struct RedisReplayEvents {
    dirty_case_ids: BTreeSet<String>,
    pub(super) connections: usize,
    matched_count: usize,
    matched: Vec<CommandMatchedReport>,
    matched_details: SuccessDetailBudget,
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
        let args = record
            .args
            .iter()
            .map(RecordedCapture::decode)
            .collect::<Result<Vec<_>>>()?;
        let response = record.response.decode()?;
        validate_subscription_exchange(&record, &args, &response)?;
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
        register_target(
            targets,
            &record.target_host,
            record.target_port,
            ReplayProtocol::Redis,
        )?;
        // Older recordings retained rejected SDK identity announcements. Neither
        // success nor failure makes these a business dependency or lane barrier.
        if record.outcome == DependencyExchangeOutcome::Response
            && crate::redis::is_client_library_info(&record.command, &args)
        {
            return Ok(());
        }
        self.connection_scopes.register(&record, &args);
        let exchange_index = self.exchanges.len();
        self.case_exchange_index
            .register(source, case_id, exchange_index);
        self.exchanges.push(ReplayExchange {
            response_time_shift: None,
            shared_rule_id: None,
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

    fn complete_exchange(&mut self, matched: &MatchedRedisExchange) {
        if let Some(exchange) = self.exchanges.get_mut(matched.index) {
            exchange.matched_once = true;
            if !exchange.reusable_snapshot {
                exchange.status = ReplayExchangeStatus::Consumed;
            }
        }
        let case_id = matched.report.case_id.clone();
        push_success_detail(
            &mut self.events.matched_count,
            &mut self.events.matched,
            &mut self.events.matched_details,
            case_id.as_deref(),
            |target_event_index| {
                let mut report = matched.report.clone();
                report.target_event_index = Some(target_event_index);
                report
            },
        );
    }

    fn fail_exchange(&mut self, matched: &MatchedRedisExchange, reason: String) {
        if let Some(exchange) = self.exchanges.get_mut(matched.index) {
            exchange.status = ReplayExchangeStatus::Failed;
        }
        if let Some(case_id) = &matched.report.case_id {
            self.events.dirty_case_ids.insert(case_id.clone());
        }
        self.events.unsafe_events.push(CommandRequestReport {
            case_id: matched.report.case_id.clone(),
            target: matched.report.target.clone(),
            command: matched.report.command.clone(),
            request_fingerprint: None,
            reason,
            diagnostic: None,
        });
    }

    pub(super) fn snapshot(&self) -> CommandProtocolReport {
        CommandProtocolReport {
            time_shifts: self.time_shifts.clone(),
            unordered_value: Some(self.unordered_value.clone()),
            lock_tokens: Some(self.lock_evidence.clone()),
            publish: Some(self.publish_evidence.clone()),
            connections: self.events.connections,
            matched_count: self.events.matched_count,
            matched: self.events.matched.clone(),
            unmatched: self.events.unmatched.clone(),
            unsupported: self.events.unsupported.clone(),
            unsafe_events: self.events.unsafe_events.clone(),
            unused_case: unused(&self.exchanges, ReplaySource::Case),
            unused_global: unused(&self.exchanges, ReplaySource::Global),
            snapshot_overlays: self.snapshot_overlays.clone(),
            warnings: self.snapshot_overlay_warnings.clone(),
        }
    }

    pub(super) fn case_is_dirty(&self, case_id: &str) -> bool {
        self.events.dirty_case_ids.contains(case_id)
            || self.case_exchange_index.any(case_id, |index| {
                self.exchanges.get(index).is_some_and(|exchange| {
                    if exchange.source != ReplaySource::Case {
                        return false;
                    }
                    if exchange.reusable_snapshot {
                        !exchange.matched_once
                    } else {
                        !exchange.status.is_consumed()
                    }
                })
            })
    }
}

pub(super) async fn handle_connection(
    mut stream: TcpStream,
    target: ReplayTarget,
    state: Arc<Mutex<ReplayState>>,
) -> Result<()> {
    let target_key = TargetKey {
        host: target.host,
        port: target.port,
    };
    state.lock().await.redis.events.connections += 1;
    let mut reader = RedisBufferedReader::new(&mut stream, 64 * 1024 * 1024);
    let mut resp_version = 2_u8;
    let mut database = 0_i64;
    let mut username: Option<String> = None;
    let mut connection_binding = CaseConnectionBinding::default();
    let client_id = Uuid::new_v4();
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
                    request_fingerprint: None,
                    reason: "Redis command mode is unsupported for replay".to_string(),
                    diagnostic: None,
                });
            drop(replay_state);
            reader
                .inner
                .write_all(b"-ERR Redis command mode is unsupported for replay\r\n")
                .await?;
            continue;
        }
        let (recorded_failure_case_id, recorded_failure) = if redis_is_builtin(&command.name) {
            let mut state = state.lock().await;
            let active_case_id = state.active_case_id.clone();
            let bound_connection = connection_binding.connection(active_case_id.as_deref());
            let matched = state.redis.match_redis_builtin_failure(
                active_case_id.as_deref(),
                &target_key,
                TargetConnection {
                    id: client_id,
                    bound: bound_connection,
                },
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
            if matched.requires_binding {
                connection_binding.bind(recorded_failure_case_id.as_deref(), matched.connection_id);
            }
            if deliver_redis_exchange(&mut reader, &state, &matched).await? {
                break;
            }
            continue;
        }
        if let Some(response) =
            redis_builtin(&command, &mut resp_version, &mut database, &mut username)
        {
            reader.inner.write_all(&response).await?;
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
                TargetConnection {
                    id: client_id,
                    bound: bound_connection,
                },
                resp_version,
                database,
                username.as_deref(),
                &command.name,
                &command.args,
            ) {
                Ok(matched) => {
                    if let Some(policy) = &mut state.replay_policy {
                        policy.commit_redis_value(active_case_id.as_deref(), &matched.rule_ids);
                    }
                    if matched.requires_binding {
                        connection_binding.bind(active_case_id.as_deref(), matched.connection_id);
                    }
                    Ok(matched)
                }
                Err(diagnostic) => {
                    let authentication_hint = redis_authentication_hint(&diagnostic);
                    if let Some(case_id) = &active_case_id {
                        state.redis.events.dirty_case_ids.insert(case_id.clone());
                    }
                    state.redis.events.unmatched.push(CommandRequestReport {
                        case_id: active_case_id,
                        target: target_key.clone(),
                        command: command.name.clone(),
                        request_fingerprint: Some(cross_case::target_fingerprint(
                            &target_key,
                            resp_version,
                            database,
                            username.as_deref(),
                            &command.name,
                            &command.args,
                        )),
                        reason: authentication_hint
                            .unwrap_or(
                                "no recorded Redis exchange matched target/session/arguments",
                            )
                            .to_string(),
                        diagnostic: Some(diagnostic),
                    });
                    Err(authentication_hint.unwrap_or("no recorded Redis dependency matched"))
                }
            }
        };
        match response {
            Ok(matched) => {
                if deliver_redis_exchange(&mut reader, &state, &matched).await? {
                    break;
                }
            }
            Err(reason) => {
                reader
                    .inner
                    .write_all(format!("-ERR {reason}\r\n").as_bytes())
                    .await?;
            }
        }
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
    let rendered = matched
        .response_time_shift
        .as_ref()
        .map(|shift| shift.render(chrono::Utc::now()))
        .transpose();
    let rendered = match rendered {
        Ok(value) => value,
        Err(error) => {
            state
                .lock()
                .await
                .redis
                .fail_exchange(matched, error.to_string());
            return Err(error);
        }
    };
    let response = rendered
        .as_ref()
        .map_or(matched.response.as_slice(), |(bytes, _)| bytes.as_slice());
    if let Err(error) = reader.inner.write_all(response).await {
        state.lock().await.redis.fail_exchange(
            matched,
            format!("failed to deliver recorded Redis response: {error}"),
        );
        return Err(error.into());
    }
    let mut state = state.lock().await;
    if let (Some(shift), Some((_, offset_milliseconds))) = (&matched.response_time_shift, rendered)
    {
        if let Some(policy) = state.replay_policy.as_mut() {
            policy.commit_redis_value(matched.report.case_id.as_deref(), &shift.rule_ids);
        }
        for rule_id in &shift.rule_ids {
            if state.redis.time_shifts.len() >= 1000 {
                break;
            }
            state
                .redis
                .time_shifts
                .push(time_shift::TimeShiftObservation {
                    rule_id: rule_id.clone(),
                    case_id: matched.report.case_id.clone(),
                    connection_id: matched.connection_id,
                    sequence: matched.report.sequence,
                    offset_milliseconds,
                });
        }
    }
    state.redis.complete_exchange(matched);
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
        request_fingerprint: None,
        reason,
        diagnostic: None,
    };
    if let Some(case_id) = &request.case_id {
        state.redis.events.dirty_case_ids.insert(case_id.clone());
    }
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

fn validate_subscription_exchange(
    record: &RecordedExchange,
    args: &[Vec<u8>],
    response: &[u8],
) -> Result<()> {
    if !is_pubsub_command(&record.command) {
        return Ok(());
    }

    ensure!(
        record.resp_version == 2,
        "Redis Pub/Sub replay requires RESP2"
    );
    ensure!(
        args.len() == 1,
        "Redis {} confirmation replay requires exactly one subscription argument",
        record.command
    );

    let command = RedisCommand {
        name: record.command.clone(),
        args: args.to_vec(),
    };
    match record.response_kind.as_str() {
        "array" => validate_subscription_confirmation(&command, response),
        "error" => {
            let raw = bytes::Bytes::copy_from_slice(response);
            ensure!(
                redis_frame_kind(&raw)? == RedisFrameKind::Error,
                "Redis {} recorded error response is not a RESP2 error frame",
                record.command
            );
            Ok(())
        }
        other => Err(anyhow!(
            "Redis {} replay requires an exact subscription confirmation or error, got {other}",
            record.command
        )),
    }
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
mod tests;
