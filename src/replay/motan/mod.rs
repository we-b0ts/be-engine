use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::Ipv4Addr;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, tcp::OwnedWriteHalf};
use tokio::sync::{Mutex, mpsc, watch};
use tokio::time::{Duration, Instant, sleep_until};
use uuid::Uuid;

use crate::DependencyExchangeOutcome;
use crate::motan::{Frame, RequestIdentity, patch_request_id, read_frame};

use super::command_matching::{
    CaseConnectionBinding, CommandExchangeScope, PreferredMatch, lane_blocked_diagnostic,
    preferred_match, unmatched_diagnostic,
};
use super::report::command::{
    CommandMatchDiagnostic, CommandMatchedReport, CommandProtocolReport, CommandRequestReport,
    CommandUnusedReport,
};
use super::{
    CaseExchangeIndex, ReplayExchangeStatus, ReplayExchangeTiming, ReplayProtocol, ReplaySource,
    ReplayState, ReplayTarget, SuccessDetailBudget, TargetKey, is_connection_termination,
    normalize_host, push_success_detail, register_replay_target_at,
};

mod auth;
mod evidence;
mod incoming;
mod report_inventory;
mod termination;
use termination::wait_for_connection_close;

use auth::Authentication;

const LANE_BLOCK_WAIT_TIMEOUT: Duration = Duration::from_millis(100);
const INCOMING_FRAME_QUEUE_CAPACITY: usize = 256;

struct PendingRequest {
    frame: Frame,
    identity: RequestIdentity,
    request_match: Option<RequestMatch>,
    lane_wait_deadline: Instant,
    started: Instant,
}

enum IncomingEvent {
    Frame(Frame),
    Closed(Result<()>),
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct RecordedConnection {
    target_host: String,
    target_port: u16,
    advertised_ip: Ipv4Addr,
    replay_safe: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct RecordedExchange {
    connection_id: Uuid,
    sequence: u64,
    target_host: String,
    target_port: u16,
    advertised_ip: Ipv4Addr,
    codec_version: u8,
    interface_name: Option<String>,
    method_name: Option<String>,
    parameter_desc: Option<String>,
    method_sign: Option<String>,
    command: String,
    request: RecordedCapture,
    response: RecordedCapture,
    heartbeat: bool,
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
    response_evidence: Option<crate::dependency_index::RecordRef>,
    source: ReplaySource,
    case_id: Option<String>,
    record: RecordedExchange,
    identity: RequestIdentity,
    request_match: Option<RequestMatch>,
    response: Vec<u8>,
    status: ReplayExchangeStatus,
    timing: ReplayExchangeTiming,
}

#[derive(Clone, PartialEq, Eq)]
struct RequestMatch {
    authentication: Authentication,
}

impl RequestMatch {
    fn from_inspection(inspection: motan_codec::Motan1RequestInspection) -> Self {
        let (_arguments, attachments) = inspection.into_parts();
        Self {
            authentication: Authentication::from_attachments(&attachments),
        }
    }

    fn from_frame(frame: &crate::motan::Frame) -> Result<Option<Self>> {
        Ok(frame.motan1_request()?.map(Self::from_inspection))
    }
}

impl std::fmt::Debug for RequestMatch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RequestMatch")
            .field("authentication", &self.authentication)
            .finish()
    }
}

#[derive(Debug, Clone)]
struct HeartbeatTemplate {
    target: TargetKey,
    codec_version: u8,
    response: Vec<u8>,
    timing: ReplayExchangeTiming,
}

#[derive(Debug, Clone)]
struct MatchedExchange {
    index: usize,
    duration_ms: u64,
    connection_id: Uuid,
    response: Vec<u8>,
    timing: ReplayExchangeTiming,
    report: CommandMatchedReport,
}

#[derive(Debug)]
pub(super) struct MotanReplayState {
    exchanges: Vec<ReplayExchange>,
    case_exchange_index: CaseExchangeIndex,
    heartbeats: Vec<HeartbeatTemplate>,
    lane_progress: watch::Sender<u64>,
    pub(super) events: MotanReplayEvents,
}

#[derive(Debug, Default)]
pub(super) struct MotanReplayEvents {
    global_report: crate::replay::report::global_evidence::regular_usage::Usage,
    dirty_case_ids: BTreeSet<String>,
    connections: usize,
    matched_count: usize,
    matched: Vec<CommandMatchedReport>,
    matched_details: SuccessDetailBudget,
    unmatched: Vec<CommandRequestReport>,
    unsupported: Vec<CommandRequestReport>,
    unsafe_events: Vec<CommandRequestReport>,
}

impl Default for MotanReplayState {
    fn default() -> Self {
        let (lane_progress, _) = watch::channel(0);
        Self {
            exchanges: Vec::new(),
            case_exchange_index: CaseExchangeIndex::default(),
            heartbeats: Vec::new(),
            lane_progress,
            events: MotanReplayEvents::default(),
        }
    }
}

impl MotanReplayState {
    pub(in crate::replay) fn has_case_in_flight(&self) -> bool {
        self.exchanges.iter().any(|e| {
            e.source == ReplaySource::Case
                && matches!(
                    e.status,
                    ReplayExchangeStatus::Responding
                        | ReplayExchangeStatus::AwaitingClientTermination
                )
        })
    }

    pub(in crate::replay) fn has_in_flight(&self) -> bool {
        self.exchanges.iter().any(|e| {
            matches!(
                e.status,
                ReplayExchangeStatus::Responding | ReplayExchangeStatus::AwaitingClientTermination
            )
        })
    }

    pub(super) fn register_connection(
        &mut self,
        record: RecordedConnection,
        targets: &mut BTreeMap<TargetKey, ReplayTarget>,
    ) -> Result<()> {
        if !record.replay_safe {
            return Err(anyhow!(
                "unsafe Motan connection metadata for {}:{}",
                record.target_host,
                record.target_port
            ));
        }
        register_target(
            targets,
            &record.target_host,
            record.target_port,
            record.advertised_ip,
        )
    }

    pub(super) fn reject_proxy_error(record: &super::RecordedProxyError) -> Result<()> {
        if record.protocol == "motan" {
            return Err(anyhow!(
                "unsafe Motan dependency proxy error: {}",
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
        if record.heartbeat {
            return Err(anyhow!(
                "Motan heartbeat must be stored in dependencies-debug.jsonl"
            ));
        }
        validate_capture("request", &record.request)?;
        validate_capture("response", &record.response)?;
        if !record.replay_safe {
            return Err(anyhow!(
                "motan_exchange {} contains unsafe replay evidence",
                record.command
            ));
        }
        register_target(
            targets,
            &record.target_host,
            record.target_port,
            record.advertised_ip,
        )?;
        let identity = identity(&record)?;
        let request_frame = crate::motan::Frame::decode(record.request.decode()?)
            .context("recorded Motan request contains invalid framing")?;
        if !request_frame.request {
            return Err(anyhow!(
                "recorded Motan request capture is a response frame"
            ));
        }
        if request_frame.codec_version != record.codec_version {
            return Err(anyhow!(
                "recorded Motan request codec {} differs from exchange codec {}",
                request_frame.codec_version,
                record.codec_version
            ));
        }
        let request_match = RequestMatch::from_frame(&request_frame)?;
        let response = if record.outcome.termination().is_some() {
            Vec::new()
        } else {
            record.response.decode()?
        };
        anyhow::ensure!(
            !record.outcome.termination().is_some_and(
                |termination| termination.scope == crate::dependency::TerminationScope::Stream
            ),
            "Motan native termination cannot have stream scope"
        );
        let timing = ReplayExchangeTiming::from_recorded(record.duration_ms, record.outcome);
        let exchange_index = self.exchanges.len();
        self.case_exchange_index
            .register(source, case_id, exchange_index);
        self.exchanges.push(ReplayExchange {
            response_evidence: None,
            source,
            case_id: case_id.map(ToOwned::to_owned),
            record,
            identity,
            request_match,
            response,
            status: ReplayExchangeStatus::Available,
            timing,
        });
        Ok(())
    }

    pub(super) fn register_heartbeat(
        &mut self,
        record: RecordedExchange,
        targets: &mut BTreeMap<TargetKey, ReplayTarget>,
    ) -> Result<()> {
        if !record.heartbeat
            || !record.replay_safe
            || record.outcome != DependencyExchangeOutcome::Response
        {
            return Ok(());
        }
        validate_capture("heartbeat response", &record.response)?;
        register_target(
            targets,
            &record.target_host,
            record.target_port,
            record.advertised_ip,
        )?;
        let template = HeartbeatTemplate {
            target: TargetKey {
                host: normalize_host(&record.target_host),
                port: record.target_port,
            },
            codec_version: record.codec_version,
            response: record.response.decode()?,
            timing: ReplayExchangeTiming::from_recorded(record.duration_ms, record.outcome),
        };
        if !self.heartbeats.iter().any(|existing| {
            existing.target == template.target && existing.codec_version == template.codec_version
        }) {
            self.heartbeats.push(template);
        }
        Ok(())
    }

    fn heartbeat(&self, target: &TargetKey, codec_version: u8) -> Option<HeartbeatTemplate> {
        self.heartbeats
            .iter()
            .find(|template| template.target == *target && template.codec_version == codec_version)
            .or_else(|| {
                self.heartbeats
                    .iter()
                    .find(|template| template.codec_version == codec_version)
            })
            .cloned()
    }

    fn match_exchange(
        &mut self,
        active_case_id: Option<&str>,
        target: &TargetKey,
        bound_connection: Option<Uuid>,
        codec_version: u8,
        identity: &RequestIdentity,
        request_match: Option<&RequestMatch>,
    ) -> std::result::Result<MatchedExchange, CommandMatchDiagnostic> {
        let matches_request = |exchange: &ReplayExchange, connection_id: Option<Uuid>| {
            exchange.status.is_available()
                && connection_id.is_none_or(|id| exchange.record.connection_id == id)
                && exchange.record.codec_version == codec_version
                && exchange.identity == *identity
                && request_mismatch_fields(exchange.request_match.as_ref(), request_match)
                    .is_empty()
        };
        let matched = bound_connection.map_or_else(
            || {
                preferred_match(&self.exchanges, active_case_id, |exchange| {
                    matches_request(exchange, None)
                })
            },
            |connection_id| match preferred_match(&self.exchanges, active_case_id, |exchange| {
                matches_request(exchange, Some(connection_id))
            }) {
                PreferredMatch::NotFound => {
                    preferred_match(&self.exchanges, active_case_id, |exchange| {
                        matches_request(exchange, None)
                    })
                }
                preferred => preferred,
            },
        );
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
                        motan_mismatch_fields(exchange, codec_version, identity, request_match)
                    },
                ));
            }
        };
        let response = self.exchanges[index].response_bytes().map_err(|error| {
            CommandMatchDiagnostic::EvidenceUnavailable {
                reason: format!("response evidence unavailable: {error:#}"),
            }
        })?;
        let exchange = &mut self.exchanges[index];
        exchange.status = if exchange.timing.outcome().is_client_terminated() {
            ReplayExchangeStatus::AwaitingClientTermination
        } else {
            ReplayExchangeStatus::Responding
        };
        Ok(MatchedExchange {
            duration_ms: exchange.record.duration_ms,
            index,
            connection_id: exchange.record.connection_id,
            response,
            timing: exchange.timing,
            report: CommandMatchedReport {
                case_id: active_case_id.map(ToOwned::to_owned),
                source: exchange.source,
                index,
                target: target.clone(),
                connection_id: exchange.record.connection_id,
                sequence: exchange.record.sequence,
                command: exchange.record.command.clone(),
                shared_origin: None,
                target_event_index: None,
            },
        })
    }

    fn complete(&mut self, matched: &MatchedExchange) {
        self.exchanges[matched.index].status = ReplayExchangeStatus::Consumed;
        self.refresh_global_report(matched.index);
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
        self.lane_progress
            .send_modify(|progress| *progress = (*progress).wrapping_add(1));
    }

    fn fail(&mut self, matched: &MatchedExchange, reason: String) {
        self.exchanges[matched.index].status = ReplayExchangeStatus::Failed;
        self.refresh_global_report(matched.index);
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
            connections: self.events.connections,
            matched_count: self.events.matched_count,
            matched: self.events.matched.clone(),
            unmatched: self.events.unmatched.clone(),
            unsupported: self.events.unsupported.clone(),
            unsafe_events: self.events.unsafe_events.clone(),
            unused_case: unused(&self.exchanges, ReplaySource::Case),
            unused_global_count: Some(self.global_unused_count()),
            unused_global: unused(&self.exchanges, ReplaySource::Global),
            ..Default::default()
        }
    }

    pub(super) fn case_is_dirty(&self, case_id: &str) -> bool {
        self.events.dirty_case_ids.contains(case_id)
            || self.case_exchange_index.any(case_id, |index| {
                self.exchanges
                    .get(index)
                    .is_some_and(|exchange| !exchange.status.is_consumed())
            })
    }
}

pub(super) async fn handle_connection(
    stream: TcpStream,
    target: ReplayTarget,
    state: Arc<Mutex<ReplayState>>,
) -> Result<()> {
    let target_key = TargetKey {
        host: target.host,
        port: target.port,
    };
    state.lock().await.motan.events.connections += 1;
    let control = crate::dependency::termination::ConnectionControl::new(&stream)?;
    let (reader, mut writer) = stream.into_split();
    let (incoming_sender, mut incoming) = mpsc::channel(INCOMING_FRAME_QUEUE_CAPACITY);
    let reader_task = tokio::spawn(incoming::read(reader, incoming_sender));

    let result = drive_connection(&mut writer, &target_key, &state, &mut incoming, &control).await;
    reader_task.abort();
    result
}

async fn drive_connection(
    writer: &mut OwnedWriteHalf,
    target: &TargetKey,
    state: &Arc<Mutex<ReplayState>>,
    incoming: &mut mpsc::Receiver<IncomingEvent>,
    control: &crate::dependency::termination::ConnectionControl,
) -> Result<()> {
    let mut connection_binding = CaseConnectionBinding::default();
    let mut lane_progress = state.lock().await.motan.lane_progress.subscribe();
    let mut pending = VecDeque::<PendingRequest>::new();
    let mut read_closed = false;
    while !read_closed || !pending.is_empty() {
        if pending.is_empty() {
            let Some(frame) = receive_frame(incoming).await? else {
                read_closed = true;
                continue;
            };
            enqueue_request(writer, target, state, &mut pending, frame).await?;
            continue;
        }

        let mut selected = None;
        let mut unmatched = None;
        for (index, request) in pending.iter().enumerate() {
            let match_result = {
                let mut replay = state.lock().await;
                let active_case_id = replay.active_case_id.clone();
                let bound_connection = connection_binding.connection(active_case_id.as_deref());
                replay
                    .motan
                    .match_exchange(
                        active_case_id.as_deref(),
                        target,
                        bound_connection,
                        request.frame.codec_version,
                        &request.identity,
                        request.request_match.as_ref(),
                    )
                    .map(|matched| (active_case_id.clone(), matched))
                    .map_err(|diagnostic| (active_case_id, diagnostic))
            };
            match match_result {
                Ok((active_case_id, matched)) => {
                    connection_binding.bind(active_case_id.as_deref(), matched.connection_id);
                    selected = Some((index, matched));
                    break;
                }
                Err((_, CommandMatchDiagnostic::LaneBlocked { .. }))
                    if Instant::now() < request.lane_wait_deadline =>
                {
                    continue;
                }
                Err((active_case_id, diagnostic)) => {
                    unmatched = Some((index, active_case_id, diagnostic));
                    break;
                }
            }
        }

        if let Some((index, active_case_id, diagnostic)) = unmatched {
            let request = pending
                .remove(index)
                .expect("unmatched Motan pending-request index disappeared");
            record_unmatched_request(state, active_case_id, target, &request.identity, diagnostic)
                .await;
            return Err(anyhow!("no recorded Motan dependency matched"));
        }

        if let Some((index, mut matched)) = selected {
            let request = pending
                .remove(index)
                .expect("matched Motan pending-request index disappeared");
            if matched.timing.outcome().is_server_terminated() {
                let ready = if pending.is_empty() {
                    termination::await_server_end(
                        incoming,
                        request.started + std::time::Duration::from_millis(matched.duration_ms),
                    )
                    .await
                } else {
                    Err(anyhow!(
                        "Target pipelined another Motan request before recorded termination; native termination batch replay is unsupported"
                    ))
                };
                if let Err(error) = ready {
                    state.lock().await.motan.fail(&matched, error.to_string());
                    termination::retain(incoming).await;
                    return Err(error);
                }
                match matched
                    .timing
                    .terminate_server_at(writer, control, request.started)
                    .await
                {
                    Ok(()) => {
                        state.lock().await.motan.complete(&matched);
                        if let Err(error) = wait_for_connection_close(incoming, None).await {
                            state.lock().await.motan.fail(&matched, error.to_string());
                            termination::retain(incoming).await;
                        }
                        return Ok(());
                    }
                    Err(error) => {
                        state.lock().await.motan.fail(&matched, error.to_string());
                        return Err(error);
                    }
                }
            }
            if matched.timing.outcome().is_client_terminated() {
                if !pending.is_empty() {
                    let error = anyhow!(
                        "client sent another dependency request instead of terminating the connection"
                    );
                    state.lock().await.motan.fail(&matched, error.to_string());
                    termination::retain(incoming).await;
                    return Err(error);
                }
                match matched
                    .timing
                    .await_client_termination_signal_at(
                        wait_for_connection_close(incoming, matched.timing.outcome().termination()),
                        request.started,
                    )
                    .await
                {
                    Ok(_) => {
                        state.lock().await.motan.complete(&matched);
                        return Ok(());
                    }
                    Err(error) => {
                        state.lock().await.motan.fail(&matched, error.to_string());
                        termination::retain(incoming).await;
                        return Err(error);
                    }
                }
            }
            matched.timing.delay_response().await;
            patch_request_id(&mut matched.response, request.frame.request_id)?;
            if let Err(error) = writer.write_all(&matched.response).await {
                state.lock().await.motan.fail(
                    &matched,
                    format!("failed to deliver recorded Motan response: {error}"),
                );
                return Err(error.into());
            }
            state.lock().await.motan.complete(&matched);
            refresh_lane_wait_deadlines(&mut pending);
            continue;
        }

        if read_closed {
            for request in &mut pending {
                request.lane_wait_deadline = Instant::now();
            }
            continue;
        }

        let next_deadline = pending
            .iter()
            .map(|request| request.lane_wait_deadline)
            .min()
            .expect("non-empty Motan pending queue has no deadline");
        tokio::select! {
            frame = receive_frame(incoming) => {
                match frame? {
                    Some(frame) => {
                        enqueue_request(writer, target, state, &mut pending, frame).await?;
                    }
                    None => read_closed = true,
                }
            }
            progress = lane_progress.changed() => {
                progress.map_err(|_| anyhow!("Motan lane progress channel closed"))?;
                refresh_lane_wait_deadlines(&mut pending);
            }
            _ = sleep_until(next_deadline) => {}
        }
    }
    Ok(())
}

async fn enqueue_request(
    writer: &mut OwnedWriteHalf,
    target: &TargetKey,
    state: &Arc<Mutex<ReplayState>>,
    pending: &mut VecDeque<PendingRequest>,
    frame: Frame,
) -> Result<()> {
    if !frame.request {
        return Err(anyhow!("Motan replay client sent a response frame"));
    }
    let request_metadata = frame.request_metadata()?;
    let identity = request_metadata.identity;
    let request_match = RequestMatch::from_frame(&frame)?;
    if request_metadata.heartbeat {
        let template = state
            .lock()
            .await
            .motan
            .heartbeat(target, frame.codec_version);
        let Some(mut template) = template else {
            let mut replay = state.lock().await;
            let case_id = replay.active_case_id.clone();
            if let Some(case_id) = &case_id {
                replay.motan.events.dirty_case_ids.insert(case_id.clone());
            }
            replay.motan.events.unsupported.push(CommandRequestReport {
                case_id,
                target: target.clone(),
                command: identity.command(),
                request_fingerprint: None,
                reason: "no recorded Motan heartbeat response template".to_string(),
                diagnostic: None,
            });
            return Err(anyhow!("no recorded Motan heartbeat response template"));
        };
        template.timing.delay_response().await;
        patch_request_id(&mut template.response, frame.request_id)?;
        writer.write_all(&template.response).await?;
        return Ok(());
    }
    if pending.len() >= INCOMING_FRAME_QUEUE_CAPACITY {
        return Err(anyhow!(
            "Motan replay connection exceeded {INCOMING_FRAME_QUEUE_CAPACITY} pending requests"
        ));
    }
    pending.push_back(PendingRequest {
        frame,
        identity,
        request_match,
        lane_wait_deadline: Instant::now() + LANE_BLOCK_WAIT_TIMEOUT,
        started: Instant::now(),
    });
    Ok(())
}

async fn receive_frame(incoming: &mut mpsc::Receiver<IncomingEvent>) -> Result<Option<Frame>> {
    match incoming.recv().await {
        Some(IncomingEvent::Frame(frame)) => Ok(Some(frame)),
        Some(IncomingEvent::Closed(result)) => result.map(|()| None),
        None => Ok(None),
    }
}

fn refresh_lane_wait_deadlines(pending: &mut VecDeque<PendingRequest>) {
    let deadline = Instant::now() + LANE_BLOCK_WAIT_TIMEOUT;
    for request in pending {
        request.lane_wait_deadline = deadline;
    }
}

async fn record_unmatched_request(
    state: &Arc<Mutex<ReplayState>>,
    active_case_id: Option<String>,
    target: &TargetKey,
    identity: &RequestIdentity,
    diagnostic: CommandMatchDiagnostic,
) {
    let reason = motan_unmatched_reason(&diagnostic);
    let mut state = state.lock().await;
    if let Some(case_id) = &active_case_id {
        state.motan.events.dirty_case_ids.insert(case_id.clone());
    }
    state.motan.events.unmatched.push(CommandRequestReport {
        case_id: active_case_id,
        target: target.clone(),
        command: identity.command(),
        request_fingerprint: None,
        reason,
        diagnostic: Some(diagnostic),
    });
}

impl RecordedCapture {
    fn decode(&self) -> Result<Vec<u8>> {
        if self.truncated {
            return Err(anyhow!("recorded Motan capture is truncated"));
        }
        match self.encoding.as_str() {
            "base64" => STANDARD
                .decode(&self.data)
                .context("invalid Motan capture base64"),
            "utf8" => Ok(self.data.as_bytes().to_vec()),
            other => Err(anyhow!("unsupported Motan capture encoding {other}")),
        }
    }
}

fn identity(record: &RecordedExchange) -> Result<RequestIdentity> {
    if record.method_sign.is_none()
        && (record.interface_name.is_none()
            || record.method_name.is_none()
            || record.parameter_desc.is_none())
    {
        return Err(anyhow!(
            "motan_exchange {} has incomplete method identity",
            record.command
        ));
    }
    Ok(RequestIdentity {
        interface_name: record.interface_name.clone(),
        method_name: record.method_name.clone(),
        parameter_desc: record.parameter_desc.clone(),
        method_sign: record.method_sign.clone(),
    })
}

fn validate_capture(label: &str, capture: &RecordedCapture) -> Result<()> {
    if capture.truncated {
        return Err(anyhow!("recorded Motan {label} is truncated"));
    }
    Ok(())
}

fn register_target(
    targets: &mut BTreeMap<TargetKey, ReplayTarget>,
    host: &str,
    port: u16,
    advertised_ip: Ipv4Addr,
) -> Result<()> {
    register_replay_target_at(
        targets,
        &TargetKey {
            host: normalize_host(host),
            port,
        },
        ReplayProtocol::Motan,
        Some(advertised_ip),
    )
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

fn motan_unmatched_reason(diagnostic: &CommandMatchDiagnostic) -> String {
    match diagnostic {
        CommandMatchDiagnostic::EvidenceUnavailable { reason } => reason.clone(),
        CommandMatchDiagnostic::NoScopedCandidate => {
            "no available recorded Motan exchange exists in the current replay scope".to_string()
        }
        CommandMatchDiagnostic::Mismatch { fields } => format!(
            "the closest available recorded Motan exchange differs in matching fields: {}",
            fields.join(", ")
        ),
        CommandMatchDiagnostic::LaneBlocked { .. } => {
            "a matching recorded Motan exchange is blocked by an earlier unconsumed exchange on the same recorded connection lane".to_string()
        }
    }
}

fn motan_mismatch_fields(
    exchange: &ReplayExchange,
    codec_version: u8,
    identity: &RequestIdentity,
    request_match: Option<&RequestMatch>,
) -> Vec<&'static str> {
    let mut fields = Vec::new();
    if exchange.record.codec_version != codec_version {
        fields.push("codec_version");
    }
    if exchange.identity != *identity {
        fields.push("method_identity");
    }
    fields.extend(request_mismatch_fields(
        exchange.request_match.as_ref(),
        request_match,
    ));
    fields
}

fn request_mismatch_fields(
    expected: Option<&RequestMatch>,
    actual: Option<&RequestMatch>,
) -> Vec<&'static str> {
    let Some(expected) = expected else {
        return Vec::new();
    };
    let Some(actual) = actual else {
        return expected
            .authentication
            .mismatch_fields(&Authentication::None);
    };
    expected
        .authentication
        .mismatch_fields(&actual.authentication)
}

fn unused_iter(
    exchanges: &[ReplayExchange],
    source: ReplaySource,
) -> impl Iterator<Item = CommandUnusedReport> + '_ {
    exchanges
        .iter()
        .enumerate()
        .filter(move |(_, exchange)| exchange.source == source && !exchange.status.is_consumed())
        .map(move |(index, exchange)| CommandUnusedReport {
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
}

fn unused(exchanges: &[ReplayExchange], source: ReplaySource) -> Vec<CommandUnusedReport> {
    unused_iter(exchanges, source)
        .take(if source == ReplaySource::Global {
            100
        } else {
            usize::MAX
        })
        .collect()
}

#[cfg(test)]
mod tests;

impl MotanReplayState {
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
                exchange.response = Vec::new();
                exchange.record.response.data = String::new();
                exchange.record.request.data = String::new();
            }
        }
    }
}
