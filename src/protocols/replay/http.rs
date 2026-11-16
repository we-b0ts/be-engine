use crate::protocols::replay::ReplayState;
mod activity;
mod case_status;
pub(crate) mod preparation;
pub(crate) use activity::{
    case_in_flight_diagnostic, case_is_dirty, has_in_flight, startup_counts,
};
mod admission;
pub(crate) mod cancelled;
pub(crate) mod candidates;
pub(crate) mod contracts;
pub(crate) mod diagnosis;
mod matching;
pub(crate) use traffic_protocol_http::multipart;
mod report_inventory;
pub(crate) use report_inventory::{
    global_report_sharing_is_stable, visit_global_report_range as visit_global_report_rows,
};
use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::future::pending;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use chrono::Utc;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{CONTENT_LENGTH, HOST};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
#[cfg(test)]
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;
use tracing::info;

use crate::DiscoveredTcpTarget;
use crate::policy::runtime::{DependencyRuleDecision, HttpPolicyContext, ReplayPolicyRuntime};
use crate::replay::{
    CaseExchangeIndex, MitmCa, ReplayProtocol, ReplaySource, ReplayTarget, SuccessDetailBudget,
    TargetKey, push_success_detail, register_replay_target, register_replay_target_at,
};

pub(crate) mod cross_case;
mod evidence;
mod identity;
pub(crate) mod ingress;
pub(crate) mod input_timing;
mod lifecycle;
mod recording;
pub(crate) use evidence::register_global_exchange;
pub(crate) mod request_headers;
mod stream_delivery;
mod tail;
mod termination;
mod transport;
pub(crate) mod unordered;
pub(crate) use transport::handle_http_replay_connection;

pub(crate) use request_headers::HeaderDifferenceReport;

use traffic_protocol_http::{
    headers::HeaderSnapshot,
    recorded::{
        BodyCapture as RecordedBodyCapture, RecordedExchange as RecordedHttpMessage, decode_body,
    },
    response::response_headers_for_payload,
    uri::uri_path_only,
};

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct RecordedHttpExchange {
    #[serde(flatten)]
    native: RecordedHttpMessage,
    #[serde(skip)]
    response_evidence: Option<crate::dependency_index::RecordRef>,
    #[serde(skip)]
    protected_request_headers: BTreeSet<String>,
    #[serde(skip)]
    stream_delivery: Option<MatchedHttpExchangeReport>,
    #[serde(skip)]
    materialized_proxy_failure: bool,
    #[serde(skip)]
    cleanup_authorized: bool,
    #[serde(skip)]
    lifecycle_stop: Option<Arc<std::sync::atomic::AtomicBool>>,
    #[serde(default)]
    discovered_tcp_targets: Vec<DiscoveredTcpTarget>,
}

use traffic_protocol_http::recorded::HttpScheme as HttpReplayScheme;

#[derive(Debug, Clone, PartialEq, Eq)]
struct HttpDependencyIdentity {
    scheme: HttpReplayScheme,
    target: TargetKey,
}

#[derive(Debug, Clone)]
pub(crate) struct ReplayHttpExchange {
    source: ReplaySource,
    case_id: Option<String>,
    identity: HttpDependencyIdentity,
    record: RecordedHttpExchange,
    status: crate::replay::ReplayExchangeStatus,
    shared_origin: Option<cross_case::SharedOrigin>,
    lifecycle_prefix: Option<Arc<crate::http::termination::PrefixDelivery>>,
    time_copy_delivery: Option<contracts::time_copies::PreparedRead>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct RecordedTcpGatewayConnection {
    domain: Option<String>,
    fake_addr: String,
    client_to_server_bytes: u64,
    server_to_client_bytes: u64,
    error: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct ReplayHttpBlackhole {
    case_id: String,
    target: TargetKey,
    consumed: bool,
}

enum HttpReplayMatchError {
    ClientTerminated(Box<termination::PendingHttpTermination>),
    ServerTerminated(Box<termination::PendingHttpTermination>),
    Blackhole,
    BadGateway(String),
}

mod upstream_failure;

#[derive(Debug, Default)]
pub(crate) struct HttpReplayEvents {
    pub(crate) cancelled: BTreeMap<usize, cancelled::Audit>,
    pub(crate) global_report: crate::replay::report::global_evidence::regular_usage::Usage,
    pub(crate) dirty_case_ids: BTreeSet<String>,
    pub(crate) matched_count: usize,
    pub(crate) matched: Vec<MatchedHttpExchangeReport>,
    pub(crate) matched_details: SuccessDetailBudget,
    pub(crate) unmatched: Vec<HttpRequestReport>,
    pub(crate) unsupported: Vec<HttpRequestReport>,
    pub(crate) header_mismatches: Vec<HeaderDifferenceReport>,
    pub(crate) header_observations: Vec<HeaderDifferenceReport>,
    pub(crate) header_observation_count: usize,
}

impl HttpReplayEvents {
    pub(super) fn case_has_runtime_failure(&self, case: &str) -> bool {
        self.unmatched
            .iter()
            .chain(&self.unsupported)
            .any(|event| event.case_id.as_deref() == Some(case))
    }
}

pub(crate) fn case_exchange_index(exchanges: &[ReplayHttpExchange]) -> CaseExchangeIndex {
    let mut index = CaseExchangeIndex::default();
    extend_case_exchange_index(&mut index, exchanges, 0);
    index
}

pub(crate) fn extend_case_exchange_index(
    index: &mut CaseExchangeIndex,
    exchanges: &[ReplayHttpExchange],
    start: usize,
) {
    for (position, exchange) in exchanges.iter().enumerate().skip(start) {
        index.register(exchange.source, exchange.case_id.as_deref(), position);
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct MatchedHttpExchangeReport {
    pub(crate) case_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    shared_origin: Option<cross_case::SharedOrigin>,
    source: ReplaySource,
    index: usize,
    scheme: HttpReplayScheme,
    target: TargetKey,
    method: String,
    uri: String,
    status: Option<u16>,
    outcome: crate::DependencyExchangeOutcome,
    target_event_index: usize,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct HttpRequestReport {
    pub(crate) case_id: Option<String>,
    scheme: HttpReplayScheme,
    target: TargetKey,
    method: String,
    uri: String,
    reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_observation_id: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    body_comparisons: Vec<Value>,
    omitted_body_comparisons: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    unordered_json: Option<unordered::evidence::OrderEvidence>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RecordedHttpExchangeSummary {
    source: ReplaySource,
    source_http_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    shared_origin: Option<cross_case::SharedOrigin>,
    index: usize,
    pub(crate) case_id: Option<String>,
    scheme: HttpReplayScheme,
    target: TargetKey,
    method: String,
    uri: String,
    status: Option<u16>,
}

pub(crate) fn register_http_exchange(
    record: RecordedHttpExchange,
    source: ReplaySource,
    case_id: Option<&str>,
    exchanges: &mut Vec<ReplayHttpExchange>,
    targets: &mut BTreeMap<TargetKey, ReplayTarget>,
) -> Result<()> {
    for discovered in &record.discovered_tcp_targets {
        let protocol = match discovered.protocol.as_str() {
            "auto" => ReplayProtocol::Auto,
            "http" => ReplayProtocol::Http,
            "https" => ReplayProtocol::Https,

            "redis" => ReplayProtocol::Redis,

            other => {
                return Err(anyhow!(
                    "http_exchange {} advertises unsupported TCP protocol {other:?}",
                    record.native.uri
                ));
            }
        };
        register_replay_target_at(
            targets,
            &TargetKey {
                host: crate::replay::normalize_host(&discovered.alias),
                port: discovered.port,
            },
            protocol,
            Some(discovered.advertised_ip),
        )?;
    }
    if record.cleanup_authorized {
        lifecycle::validate_record(&record)?;
    } else {
        termination::validate_record(&record)?;
    }
    let stream_mime = record
        .native
        .response_headers
        .as_ref()
        .and_then(|headers| {
            headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        })
        .and_then(|(_, values)| values.first())
        .map(|value| {
            value
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
        });
    anyhow::ensure!(
        record.native.response_stream.is_some()
            || !matches!(
                stream_mime.as_deref(),
                Some("text/event-stream" | "application/x-ndjson" | "application/ndjson")
            ),
        "recorded HTTP streaming dependency has no chunk timing evidence; re-record this case"
    );
    if let Some(stream) = &record.native.response_stream {
        let body = record
            .native
            .response_body
            .as_ref()
            .context("HTTP stream has no recorded payload")?;
        // Global indexes retain byte-length metadata while deferring payload
        // bytes. Validate their shape without loading every Global response;
        // materialization and delivery validate the actual payload on demand.
        let payload_len = if record.response_evidence.is_some() {
            body.stored_len
                .context("deferred HTTP stream has no stored payload length; re-record this case")?
        } else {
            decode_body(body)?.len()
        };
        if record.cleanup_authorized {
            stream.validate_prefix(payload_len)?;
        } else {
            stream.validate(payload_len)?;
            anyhow::ensure!(
                record.native.error.is_none(),
                "HTTP stream contains a capture error"
            );
        }
    }
    let identity = identity_from_record(&record)?;
    let protocol = match identity.scheme {
        HttpReplayScheme::Http => ReplayProtocol::Http,
        HttpReplayScheme::Https => ReplayProtocol::Https,
    };
    register_replay_target(targets, &identity.target, protocol)?;
    if record.native.request_body.truncated {
        return Err(anyhow!(
            "http_exchange {} {} has a truncated request body",
            record.native.method,
            record.native.uri
        ));
    }
    if record
        .native
        .response_body
        .as_ref()
        .is_some_and(|body| body.truncated)
    {
        return Err(anyhow!(
            "http_exchange {} {} has a truncated response body",
            record.native.method,
            record.native.uri
        ));
    }
    exchanges.push(ReplayHttpExchange {
        source,
        case_id: case_id.map(ToOwned::to_owned),
        identity,
        record,
        status: crate::replay::ReplayExchangeStatus::Available,
        shared_origin: None,
        lifecycle_prefix: None,
        time_copy_delivery: None,
    });
    Ok(())
}

pub(crate) fn register_tcp_connection_blackhole(
    record: RecordedTcpGatewayConnection,
    source: ReplaySource,
    case_id: Option<&str>,
    blackholes: &mut Vec<ReplayHttpBlackhole>,
    targets: &mut BTreeMap<TargetKey, ReplayTarget>,
) -> Result<()> {
    if source != ReplaySource::Case
        || record.error.is_some()
        || record.client_to_server_bytes != 0
        || record.server_to_client_bytes != 0
    {
        return Ok(());
    }
    let (Some(case_id), Some(domain)) = (case_id, record.domain.as_deref()) else {
        return Ok(());
    };
    let fake_addr = record.fake_addr.parse::<SocketAddr>().with_context(|| {
        format!(
            "invalid fake address for zero-byte TCP connection {domain}: {}",
            record.fake_addr
        )
    })?;
    let target = TargetKey {
        host: crate::replay::normalize_host(domain),
        port: fake_addr.port(),
    };
    register_replay_target(targets, &target, ReplayProtocol::Auto)?;
    blackholes.push(ReplayHttpBlackhole {
        case_id: case_id.to_string(),
        target,
        consumed: false,
    });
    Ok(())
}

pub(crate) fn observe_recorded_policy_exchanges(
    policy: &mut ReplayPolicyRuntime,
    exchanges: &[ReplayHttpExchange],
) {
    for exchange in exchanges
        .iter()
        .filter(|exchange| exchange.source == ReplaySource::Case)
    {
        policy.observe_recorded_http_exchange(
            exchange.case_id.as_deref(),
            &exchange.identity.target,
            &exchange.record.native.method,
            &exchange.record.native.uri,
        );
    }
}

fn identity_from_record(record: &RecordedHttpExchange) -> Result<HttpDependencyIdentity> {
    let (scheme, target) = record.native.identity()?;
    Ok(HttpDependencyIdentity { scheme, target })
}

impl ReplayState {
    #[cfg(test)]
    pub(super) fn http_case_is_dirty(&self, case: &str) -> bool {
        case_is_dirty(
            &self.protocols.http_exchanges,
            &self.protocols.http_case_exchange_index,
            &self.protocols.http_ingress,
            &self.protocols.http_events,
            self.protocols.allowed_unused_http.as_ref(),
            case,
        )
    }

    fn claim_http_blackhole(&mut self, target: &TargetKey, method: &Method, uri: &Uri) -> bool {
        let Some(active_case_id) = self.active_case_id.as_deref() else {
            return false;
        };
        let Some(blackhole) = self.protocols.http_blackholes.iter_mut().find(|blackhole| {
            !blackhole.consumed
                && blackhole.case_id == active_case_id
                && blackhole.target == *target
        }) else {
            return false;
        };
        blackhole.consumed = true;
        info!(
            case_id = active_case_id,
            host = %target.host,
            port = target.port,
            method = %method,
            uri = %uri_path_only(&uri.to_string()),
            "replaying recorded zero-byte TCP dependency as an open connection with no response"
        );
        true
    }

    fn bind_last_unmatched_http_observation(&mut self, id: Option<uuid::Uuid>) {
        if let Some(report) = self.protocols.http_events.unmatched.last_mut() {
            report.target_observation_id = id.map(|id| {
                crate::policy_evidence::target_observation_id(
                    &id.to_string(),
                    crate::policy::Surface::DependencyRequest,
                    crate::policy_evidence::TargetRole::IndependentTargetObservation,
                )
            });
        }
    }

    fn record_unmatched_http(
        &mut self,
        scheme: HttpReplayScheme,
        target: &TargetKey,
        method: &Method,
        uri: &Uri,
        reason: String,
    ) {
        self.record_unmatched_http_for(
            self.active_case_id.clone(),
            scheme,
            target,
            method,
            uri,
            reason,
        );
    }

    fn record_unmatched_http_for(
        &mut self,
        case_id: Option<String>,
        scheme: HttpReplayScheme,
        target: &TargetKey,
        method: &Method,
        uri: &Uri,
        reason: String,
    ) {
        if let Some(case_id) = &case_id {
            self.protocols
                .http_events
                .dirty_case_ids
                .insert(case_id.clone());
        }
        self.protocols
            .http_events
            .unmatched
            .push(HttpRequestReport {
                case_id,
                scheme,
                target: target.clone(),
                method: method.to_string(),
                uri: uri_path_only(&uri.to_string()),
                reason,
                target_observation_id: None,
                body_comparisons: Vec::new(),
                omitted_body_comparisons: 0,
                request_fingerprint: None,
                unordered_json: Some(Default::default()),
            });
    }

    pub(super) fn unused_http_iter(
        &self,
        source: ReplaySource,
        allowed: bool,
    ) -> impl Iterator<Item = RecordedHttpExchangeSummary> + '_ {
        self.protocols
            .http_exchanges
            .iter()
            .enumerate()
            .filter(move |(index, exchange)| {
                let in_scope = if source.is_run_owned() {
                    exchange.available_in_run_pool()
                } else {
                    exchange.source == ReplaySource::Case
                        && exchange
                            .case_id
                            .as_ref()
                            .is_some_and(|case| self.cases.contains_key(case))
                };
                if !in_scope || exchange.status.is_covered() {
                    return false;
                }
                let is_allowed = source == ReplaySource::Case
                    && (self.protocols.http_events.cancelled.contains_key(index)
                        || self
                            .protocols
                            .allowed_unused_http
                            .as_ref()
                            .is_some_and(|config| {
                                config.hosts.contains(&exchange.identity.target.host)
                            }));
                is_allowed == allowed
            })
            .map(move |(index, exchange)| RecordedHttpExchangeSummary {
                source: exchange.source,
                source_http_id: exchange.record.native.id.clone(),
                shared_origin: exchange.shared_origin.clone(),
                index,
                case_id: exchange.case_id.clone(),
                scheme: exchange.identity.scheme,
                target: exchange.identity.target.clone(),
                method: exchange.record.native.method.clone(),
                uri: uri_path_only(&exchange.record.native.uri),
                status: exchange.record.native.response_status,
            })
    }
    pub(crate) fn unused_http_exchanges(
        &self,
        source: ReplaySource,
        allowed: bool,
    ) -> Vec<RecordedHttpExchangeSummary> {
        self.unused_http_iter(source, allowed)
            .take(if source.is_run_owned() {
                100
            } else {
                usize::MAX
            })
            .collect()
    }
}

impl ReplayHttpExchange {
    fn available_in_run_pool(&self) -> bool {
        self.source.is_run_owned() || self.shared_origin.is_some()
    }
    fn is_repeatable_preflight_probe(&self) -> bool {
        self.source.is_run_owned()
            && self.record.native.outcome == crate::DependencyExchangeOutcome::Response
            && self
                .record
                .native
                .capture
                .as_ref()
                .and_then(|capture| capture.initialization_unit())
                .is_some_and(|unit| {
                    matches!(
                        unit,
                        "preflight_probe/java_truststore" | "preflight_probe/system_network"
                    )
                })
    }
}

fn http_request_comparison(
    exchange: &ReplayHttpExchange,
    method: &Method,
    uri: &Uri,
    body: &[u8],
    ignored_query_params: &[String],
) -> (Option<String>, Option<Vec<u8>>) {
    traffic_protocol_http::request_contract::compare_request(
        &exchange.record.native,
        method,
        uri,
        body,
        ignored_query_params,
        bodies_match,
    )
}

fn active_http_case_matches(active_case_id: Option<&str>, exchange: &ReplayHttpExchange) -> bool {
    match exchange.source {
        ReplaySource::Startup | ReplaySource::Process => true,
        ReplaySource::Case => {
            exchange.shared_origin.is_some() || exchange.case_id.as_deref() == active_case_id
        }
        ReplaySource::Unattributed => false,
    }
}

use traffic_protocol_http::request_contract::host_matches_target;
pub(crate) use traffic_protocol_http::request_contract::uri_mismatch_reason;

fn bodies_match(recorded: &[u8], actual: &[u8]) -> bool {
    match (
        serde_json::from_slice::<Value>(recorded),
        serde_json::from_slice::<Value>(actual),
    ) {
        (Ok(recorded), Ok(actual)) => recorded == actual,
        _ => recorded == actual,
    }
}

fn error_response(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(message.to_string())));
    *response.status_mut() = status;
    response
}

#[cfg(test)]
#[path = "http_tests.rs"]
pub(crate) mod tests;

#[cfg(test)]
#[path = "http/cross_case/tests.rs"]
mod cross_case_tests;

pub(crate) fn release_consumed_payloads(
    exchanges: &mut [ReplayHttpExchange],
    cases: &BTreeMap<String, crate::replay::ReplayCase>,
) {
    for exchange in exchanges {
        if exchange.source == ReplaySource::Case
            && exchange.status.is_consumed()
            && !exchange.is_repeatable_preflight_probe()
            && exchange.case_id.as_ref().is_some_and(|id| {
                cases
                    .get(id)
                    .is_some_and(|case| case.status == crate::replay::ReplayCaseStatus::Ended)
            })
        {
            exchange.record.native.request_body.data = String::new();
            if let Some(body) = &mut exchange.record.native.response_body {
                body.data = String::new();
            }
        }
    }
}
