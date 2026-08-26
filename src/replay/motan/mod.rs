use std::collections::BTreeMap;
use std::net::Ipv4Addr;
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
use crate::motan::{RequestIdentity, patch_request_id, read_frame};

use super::command_matching::{
    CaseConnectionBinding, CommandExchangeScope, PreferredMatch, lane_blocked_diagnostic,
    preferred_match, unmatched_diagnostic,
};
use super::report::command::{
    CommandMatchDiagnostic, CommandMatchedReport, CommandProtocolReport, CommandRequestReport,
    CommandUnusedReport,
};
use super::{
    ReplayExchangeStatus, ReplayExchangeTiming, ReplayProtocol, ReplayReportWriter, ReplaySource,
    ReplayState, ReplayTarget, TargetKey, normalize_host, push_success_detail,
    register_replay_target_at,
};

mod auth;

use auth::Authentication;

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
    arguments: Vec<Vec<u8>>,
    authentication: Authentication,
}

impl RequestMatch {
    fn from_inspection(inspection: motan_codec::Motan1RequestInspection) -> Self {
        let (arguments, attachments) = inspection.into_parts();
        Self {
            arguments,
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
            .field("argument_count", &self.arguments.len())
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
    connection_id: Uuid,
    response: Vec<u8>,
    timing: ReplayExchangeTiming,
    report: CommandMatchedReport,
}

#[derive(Debug, Default)]
pub(super) struct MotanReplayState {
    exchanges: Vec<ReplayExchange>,
    heartbeats: Vec<HeartbeatTemplate>,
    pub(super) events: MotanReplayEvents,
}

#[derive(Debug, Default)]
pub(super) struct MotanReplayEvents {
    connections: usize,
    matched_count: usize,
    matched: Vec<CommandMatchedReport>,
    unmatched: Vec<CommandRequestReport>,
    unsupported: Vec<CommandRequestReport>,
    unsafe_events: Vec<CommandRequestReport>,
}

impl MotanReplayState {
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
        let response = if record.outcome.is_client_terminated() {
            Vec::new()
        } else {
            record.response.decode()?
        };
        let timing = ReplayExchangeTiming::from_recorded(record.duration_ms, record.outcome);
        self.exchanges.push(ReplayExchange {
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
        let matched = preferred_match(&self.exchanges, active_case_id, |exchange| {
            exchange.status.is_available()
                && bound_connection.is_none_or(|id| exchange.record.connection_id == id)
                && exchange.record.codec_version == codec_version
                && exchange.identity == *identity
                && request_mismatch_fields(exchange.request_match.as_ref(), request_match)
                    .is_empty()
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
                        motan_mismatch_fields(
                            exchange,
                            bound_connection,
                            codec_version,
                            identity,
                            request_match,
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
        Ok(MatchedExchange {
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

    fn complete(&mut self, matched: &MatchedExchange) {
        self.exchanges[matched.index].status = ReplayExchangeStatus::Consumed;
        push_success_detail(
            &mut self.events.matched_count,
            &mut self.events.matched,
            matched.report.clone(),
        );
    }

    fn fail(&mut self, matched: &MatchedExchange, reason: String) {
        self.exchanges[matched.index].status = ReplayExchangeStatus::Failed;
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
    state.lock().await.motan.events.connections += 1;
    report_writer.request();
    let mut connection_binding = CaseConnectionBinding::default();
    loop {
        let Some(frame) = read_frame(&mut stream, 64 * 1024 * 1024).await? else {
            break;
        };
        if !frame.request {
            return Err(anyhow!("Motan replay client sent a response frame"));
        }
        let request_metadata = frame.request_metadata()?;
        let identity = request_metadata.identity;
        let request_match = RequestMatch::from_frame(&frame)?;
        if request_metadata.heartbeat {
            let template = {
                state
                    .lock()
                    .await
                    .motan
                    .heartbeat(&target_key, frame.codec_version)
            };
            let Some(mut template) = template else {
                let mut replay = state.lock().await;
                let case_id = replay.active_case_id.clone();
                replay.motan.events.unsupported.push(CommandRequestReport {
                    case_id,
                    target: target_key.clone(),
                    command: identity.command(),
                    reason: "no recorded Motan heartbeat response template".to_string(),
                    diagnostic: None,
                });
                report_writer.request();
                return Err(anyhow!("no recorded Motan heartbeat response template"));
            };
            template.timing.delay_response().await;
            patch_request_id(&mut template.response, frame.request_id)?;
            stream.write_all(&template.response).await?;
            continue;
        }

        let matched = {
            let mut replay = state.lock().await;
            let active_case_id = replay.active_case_id.clone();
            let bound_connection = connection_binding.connection(active_case_id.as_deref());
            match replay.motan.match_exchange(
                active_case_id.as_deref(),
                &target_key,
                bound_connection,
                frame.codec_version,
                &identity,
                request_match.as_ref(),
            ) {
                Ok(matched) => {
                    connection_binding.bind(active_case_id.as_deref(), matched.connection_id);
                    Some(matched)
                }
                Err(diagnostic) => {
                    replay.motan.events.unmatched.push(CommandRequestReport {
                        case_id: active_case_id,
                        target: target_key.clone(),
                        command: identity.command(),
                        reason: "no recorded Motan exchange matched method identity, request arguments, authentication, and connection lane".to_string(),
                        diagnostic: Some(diagnostic),
                    });
                    None
                }
            }
        };
        let Some(mut matched) = matched else {
            report_writer.request();
            return Err(anyhow!("no recorded Motan dependency matched"));
        };
        if matched.timing.outcome().is_client_terminated() {
            match matched.timing.await_client_termination(&mut stream).await {
                Ok(_) => {
                    state.lock().await.motan.complete(&matched);
                    report_writer.request();
                    break;
                }
                Err(error) => {
                    state.lock().await.motan.fail(&matched, error.to_string());
                    report_writer.request();
                    return Err(error);
                }
            }
        }
        matched.timing.delay_response().await;
        patch_request_id(&mut matched.response, frame.request_id)?;
        if let Err(error) = stream.write_all(&matched.response).await {
            state.lock().await.motan.fail(
                &matched,
                format!("failed to deliver recorded Motan response: {error}"),
            );
            report_writer.request();
            return Err(error.into());
        }
        state.lock().await.motan.complete(&matched);
        report_writer.request();
    }
    Ok(())
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

fn motan_mismatch_fields(
    exchange: &ReplayExchange,
    bound_connection: Option<Uuid>,
    codec_version: u8,
    identity: &RequestIdentity,
    request_match: Option<&RequestMatch>,
) -> Vec<&'static str> {
    let mut fields = Vec::new();
    if bound_connection.is_some_and(|id| exchange.record.connection_id != id) {
        fields.push("connection");
    }
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
        let mut fields = vec!["request_arguments"];
        fields.extend(
            expected
                .authentication
                .mismatch_fields(&Authentication::None),
        );
        return fields;
    };
    let mut fields = Vec::new();
    if expected.arguments != actual.arguments {
        fields.push("request_arguments");
    }
    fields.extend(
        expected
            .authentication
            .mismatch_fields(&actual.authentication),
    );
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

#[cfg(test)]
mod tests;
