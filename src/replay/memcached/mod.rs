use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use uuid::Uuid;

use super::{
    CaseExchangeIndex, DependencyRuleDecision, MemcachedPolicyContext, ReplayExchangeStatus,
    ReplayExchangeTiming, ReplayPolicyRuntime, ReplayProtocol, ReplaySource, ReplayState,
    ReplayTarget, SuccessDetailBudget, TargetKey, normalize_host, push_success_detail,
    register_replay_target,
};
use crate::DependencyExchangeOutcome;
use crate::memcached::{
    BufferedReader as MemcachedBufferedReader, MemcachedRequest, MemcachedWireProtocol,
    read_binary_frame, read_text_request,
};
use crate::replay::admission::{Barrier, ClaimKind, ClaimTicket, Finish, Lifecycle, RequestOrder};

mod admission;
mod builtins;
mod case_status;
pub(in crate::replay) mod contracts;
mod delivery;
mod evidence;
mod expiration;
mod finite_inventory;
mod lifecycle;
mod matching;
mod report_inventory;
#[cfg(test)]
mod termination_tests;
use super::command_matching::{
    CommandExchangeScope, PreferredMatch, is_process_lane, lane_blocked_diagnostic,
    preferred_match, unmatched_diagnostic,
};
use super::report::command::{
    CommandMatchDiagnostic, CommandMatchedReport, CommandProtocolReport, CommandRequestReport,
    CommandUnusedReport,
};
use admission::match_memcached_request;
use builtins::{adapt_binary_get_responses, binary_get_opcodes_match, memcached_is_unsupported};
use delivery::deliver_memcached_exchange;
use expiration::{ArgumentSnapshot, arguments_match};

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
    #[serde(default = "default_recorded_timestamp")]
    timestamp: DateTime<Utc>,
    #[serde(default)]
    request_started_at: Option<DateTime<Utc>>,
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
    #[serde(default)]
    response_frame_offsets_ms: Vec<u64>,
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

fn default_recorded_timestamp() -> DateTime<Utc> {
    DateTime::UNIX_EPOCH
}

#[derive(Debug, Clone)]
struct ReplayExchange {
    response_evidence: Option<crate::dependency_index::RecordRef>,
    source: ReplaySource,
    case_id: Option<String>,
    record: RecordedExchange,
    key: Option<Vec<u8>>,
    args: Vec<Vec<u8>>,
    value: Option<Vec<u8>>,
    extras: Option<Vec<u8>>,
    response_frames: Vec<Vec<u8>>,
    status: ReplayExchangeStatus,
    claim: Option<ClaimTicket>,
    timing: ReplayExchangeTiming,
    connection_independent: bool,
}

#[derive(Debug, Clone)]
struct MatchedMemcachedExchange {
    index: usize,
    claim: ClaimTicket,
    response_frames: Vec<Vec<u8>>,
    response_frame_offsets_ms: Vec<u64>,
    timing: ReplayExchangeTiming,
    request_observed_at: DateTime<Utc>,
    request_opcode: Option<u8>,
    request_opaque: Option<u32>,
    policy_decision: DependencyRuleDecision,
    report: CommandMatchedReport,
}

#[derive(Clone, Copy)]
struct MemcachedMatchContext<'a> {
    active_case_id: Option<&'a str>,
    target: &'a TargetKey,
    wire_protocol: MemcachedWireProtocol,
    request: &'a MemcachedRequest,
    policy: Option<&'a ReplayPolicyRuntime>,
    observed_at: DateTime<Utc>,
}

#[derive(Debug, Default)]
pub(crate) struct MemcachedReplayState {
    exchanges: Vec<ReplayExchange>,
    case_exchange_index: CaseExchangeIndex,
    lifecycle: Lifecycle,
    pub(super) events: MemcachedReplayEvents,
}

#[derive(Debug, Default)]
pub(super) struct MemcachedReplayEvents {
    request_order: RequestOrder,
    global_report: crate::replay::report::global_evidence::regular_usage::Usage,
    dirty_case_ids: BTreeSet<String>,
    pub(super) connections: usize,
    matched_count: usize,
    matched: Vec<CommandMatchedReport>,
    pub(in crate::replay) matched_details: SuccessDetailBudget,
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
        delivery::validate_termination(&record)?;
        let outcome = if record.no_response {
            DependencyExchangeOutcome::NoResponse
        } else {
            record.outcome
        };
        let timing = ReplayExchangeTiming::from_recorded(record.duration_ms, outcome);
        let connection_independent = is_process_lane(source);
        let exchange_index = self.exchanges.len();
        self.case_exchange_index
            .register(source, case_id, exchange_index);
        self.exchanges.push(ReplayExchange {
            response_evidence: None,
            source,
            case_id: case_id.map(ToOwned::to_owned),
            record,
            key,
            args,
            value,
            extras,
            response_frames,
            status: ReplayExchangeStatus::Available,
            claim: None,
            timing,
            connection_independent,
        });
        Ok(())
    }

    pub(crate) fn snapshot(&self) -> CommandProtocolReport {
        CommandProtocolReport {
            connections: self.events.connections,
            matched_count: self.events.matched_count,
            matched: self.events.matched.clone(),
            unmatched: self.events.unmatched.clone(),
            unsupported: self.events.unsupported.clone(),
            unsafe_events: self.events.unsafe_events.clone(),
            unused_case: unused(&self.exchanges, ReplaySource::Case),
            unused_global_count: Some(self.global_unused_count()),
            unused_global: unused(&self.exchanges, ReplaySource::Startup),
            ..Default::default()
        }
    }
}

pub(crate) async fn handle_connection(
    mut stream: TcpStream,
    target: ReplayTarget,
    state: Arc<Mutex<ReplayState>>,
) -> Result<()> {
    let target_key = TargetKey {
        host: target.host,
        port: target.port,
    };
    state.lock().await.protocols.memcached.events.connections += 1;
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
                        return Err(error);
                    }
                };
                let request_started = tokio::time::Instant::now();
                let matched = match_memcached_request(&state, &target_key, wire, &request).await;
                match matched {
                    Some(matched) => {
                        if deliver_memcached_exchange(
                            &mut reader,
                            &state,
                            &matched,
                            request_started,
                        )
                        .await?
                        {
                            break;
                        }
                    }
                    None => break,
                }
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
                        return Err(error);
                    }
                };
                let request_started = tokio::time::Instant::now();
                let matched = match_memcached_request(&state, &target_key, wire, &request).await;
                match matched {
                    Some(mut matched) => {
                        if let Err(reason) = adapt_binary_get_responses(
                            &mut matched.response_frames,
                            frame.opcode,
                            frame.opaque,
                            request.key.as_deref(),
                            matched.timing.outcome() == DependencyExchangeOutcome::NoResponse,
                        ) {
                            state
                                .lock()
                                .await
                                .protocols
                                .memcached
                                .fail_exchange(&matched, reason.to_string());
                            return Err(anyhow!(reason));
                        }
                        if deliver_memcached_exchange(
                            &mut reader,
                            &state,
                            &matched,
                            request_started,
                        )
                        .await?
                        {
                            break;
                        }
                    }
                    None => break,
                }
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
    let request = CommandRequestReport {
        target_observation_id: None,
        case_id: state.active_case_id.clone(),
        target: target.clone(),
        command: command.to_string(),
        target_event_index: None,
        request_fingerprint: None,
        reason,
        diagnostic: None,
    };
    let _ = protocol;
    if let Some(case_id) = &request.case_id {
        state
            .protocols
            .memcached
            .events
            .dirty_case_ids
            .insert(case_id.clone());
    }
    state.protocols.memcached.events.unsafe_events.push(request);
}

pub(super) fn observe_recorded_policy_exchanges(
    policy: &mut ReplayPolicyRuntime,
    state: &MemcachedReplayState,
) {
    for exchange in state
        .exchanges
        .iter()
        .filter(|exchange| exchange.source == ReplaySource::Case)
    {
        policy.observe_recorded_memcached_exchange(
            exchange.case_id.as_deref(),
            &TargetKey {
                host: normalize_host(&exchange.record.target_host),
                port: exchange.record.target_port,
            },
            &exchange.record.command,
            exchange.key.as_deref(),
        );
    }
}

fn memcached_value_matches_policy(
    policy: Option<&ReplayPolicyRuntime>,
    exchange: &ReplayExchange,
    target: &TargetKey,
    request: &MemcachedRequest,
    observed_at: DateTime<Utc>,
) -> bool {
    policy.map_or(exchange.value == request.value, |policy| {
        policy
            .preview_memcached(&memcached_policy_context(
                exchange,
                target,
                request,
                observed_at,
            ))
            .is_ok()
    })
}

fn memcached_policy_context<'a>(
    exchange: &'a ReplayExchange,
    target: &'a TargetKey,
    request: &'a MemcachedRequest,
    observed_at: DateTime<Utc>,
) -> MemcachedPolicyContext<'a> {
    MemcachedPolicyContext {
        case_id: exchange.case_id.as_deref(),
        target,
        command: &request.command,
        key: request.key.as_deref(),
        recorded_value: exchange.value.as_deref(),
        actual_value: request.value.as_deref(),
        recorded_request_started_at: contracts::source_start(&exchange.record),
        actual_observed_at: observed_at,
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

    fn satisfies_lane_order(&self) -> bool {
        let barrier = if self.source == ReplaySource::Case
            && self.timing.outcome() == DependencyExchangeOutcome::Response
            && !self.record.quiet
            && !self.record.noreply
        {
            Barrier::Admitted
        } else {
            Barrier::Delivered
        };
        Lifecycle::satisfies(self.status, self.source, barrier)
            && self
                .claim
                .as_ref()
                .is_none_or(|claim| claim.satisfies(barrier))
    }

    fn preserves_connection_order(&self) -> bool {
        !self.connection_independent
    }
}

fn memcached_mismatch_fields(
    exchange: &ReplayExchange,
    target: &TargetKey,
    wire_protocol: MemcachedWireProtocol,
    request: &MemcachedRequest,
    observed_at: DateTime<Utc>,
) -> Vec<&'static str> {
    let mut fields = Vec::new();
    if !target_matches(
        target,
        &exchange.record.target_host,
        exchange.record.target_port,
    ) {
        fields.push("target");
    }
    let wire = wire_protocol.as_str();
    if exchange.record.wire_protocol != wire {
        fields.push("wire_protocol");
    }
    if !exchange
        .record
        .command
        .eq_ignore_ascii_case(&request.command)
        || !binary_get_opcodes_match(exchange.record.opcode, request.opcode)
    {
        fields.push("command");
    }
    if exchange.key != request.key
        || (exchange.record.wire_protocol == wire
            && !arguments_match(
                wire_protocol,
                &request.command,
                ArgumentSnapshot {
                    args: &exchange.args,
                    extras: exchange.extras.as_deref(),
                    observed_at: contracts::source_start(&exchange.record),
                },
                ArgumentSnapshot {
                    args: &request.args,
                    extras: request.extras.as_deref(),
                    observed_at: Some(observed_at),
                },
            ))
        || exchange.value != request.value
        || exchange.record.cas != request.cas
        || (exchange.record.quiet != request.quiet
            && !binary_get_opcodes_match(exchange.record.opcode, request.opcode))
        || exchange.record.noreply != request.noreply
    {
        fields.push("arguments");
    }
    fields
}

fn unused_iter(
    exchanges: &[ReplayExchange],
    source: ReplaySource,
) -> impl Iterator<Item = CommandUnusedReport> + '_ {
    exchanges
        .iter()
        .enumerate()
        .filter(move |(_, exchange)| {
            exchange.source.matches_scope(source) && !exchange.status.is_consumed()
        })
        .map(move |(index, exchange)| CommandUnusedReport {
            source_exchange_id: None,
            index,
            case_id: exchange.case_id.clone(),
            source: exchange.source,
            target: TargetKey {
                host: normalize_host(&exchange.record.target_host),
                port: exchange.record.target_port,
            },
            connection_id: exchange.record.connection_id,
            sequence: exchange.record.sequence,
            command: exchange.record.command.clone(),
        })
}

fn unused(exchanges: &[ReplayExchange], source: ReplaySource) -> Vec<CommandUnusedReport> {
    unused_iter(exchanges, source)
        .take(if source.is_run_owned() {
            100
        } else {
            usize::MAX
        })
        .collect()
}

impl MemcachedReplayState {
    pub(super) fn release_consumed_payloads(
        &mut self,
        cases: &BTreeMap<String, super::ReplayCase>,
    ) {
        for exchange in &mut self.exchanges {
            if exchange.source == ReplaySource::Case
                && exchange.status.is_consumed()
                && exchange.case_id.as_ref().is_some_and(|id| {
                    cases
                        .get(id)
                        .is_some_and(|case| case.status == super::ReplayCaseStatus::Ended)
                })
            {
                exchange.response_frames = Vec::new();
                exchange.record.response_frames = Vec::new();
                exchange.value = None;
                exchange.record.value = None;
            }
        }
    }
}
