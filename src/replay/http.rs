pub(in crate::replay) mod cancelled;
pub(in crate::replay) mod candidates;
pub(in crate::replay) mod contracts;
pub(crate) mod diagnosis;
mod matching;
pub(in crate::replay) mod multipart;
mod report_inventory;
pub(super) use report_inventory::visit_global_report_range as visit_global_report_rows;
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
use hyper::header::{CONNECTION, CONTENT_LENGTH, HOST, TRANSFER_ENCODING};
use hyper::http::uri::Authority;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;
use tracing::info;
use url::form_urlencoded;

use super::{
    CaseExchangeIndex, DependencyRuleDecision, HttpPolicyContext, MitmCa, ReplayPolicyRuntime,
    ReplayProtocol, ReplaySource, ReplayState, ReplayTarget, SuccessDetailBudget, TargetKey,
    push_success_detail, register_replay_target, register_replay_target_at,
};
use crate::DiscoveredTcpTarget;

pub(crate) mod cross_case;
mod evidence;
mod identity;
pub(in crate::replay) mod ingress;
pub(in crate::replay) mod input_timing;
mod lifecycle;
mod recording;
pub(super) use evidence::register_global_exchange;
pub(in crate::replay) mod request_headers;
mod selector;
mod stream_delivery;
mod tail;
mod termination;
mod transport;
pub(crate) mod unordered;
pub(super) use transport::handle_http_replay_connection;

type HeaderSnapshot = BTreeMap<String, Vec<String>>;
pub(super) use request_headers::HeaderDifferenceReport;

#[derive(Debug, Clone, Deserialize)]
pub(super) struct RecordedHttpExchange {
    #[serde(default)]
    id: Option<String>,
    #[serde(skip)]
    response_evidence: Option<crate::dependency_index::RecordRef>,
    scheme: String,
    #[serde(default)]
    outcome: crate::DependencyExchangeOutcome,
    #[serde(default)]
    timestamp: Option<chrono::DateTime<Utc>>,
    #[serde(default)]
    request_started_at: Option<chrono::DateTime<Utc>>,
    // Untrusted optional timing evidence must not prevent ordinary HTTP matching.
    #[serde(default)]
    duration_ms: Option<serde_json::Value>,
    method: String,
    uri: String,
    authority: Option<String>,
    request_body: RecordedBodyCapture,
    #[serde(default)]
    request_headers: HeaderSnapshot,
    #[serde(skip)]
    protected_request_headers: BTreeSet<String>,
    response_status: Option<u16>,
    response_headers: Option<HeaderSnapshot>,
    response_body: Option<RecordedBodyCapture>,
    #[serde(default)]
    response_stream: Option<crate::http::stream::ResponseStream>,
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
    #[serde(default)]
    capture: Option<crate::dependency::observation::CaptureMetadata>,
    error: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct RecordedBodyCapture {
    encoding: String,
    truncated: bool,
    #[serde(default)]
    stored_len: Option<usize>,
    data: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum HttpReplayScheme {
    Http,
    Https,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HttpDependencyIdentity {
    scheme: HttpReplayScheme,
    target: TargetKey,
}

#[derive(Debug, Clone)]
pub(super) struct ReplayHttpExchange {
    source: ReplaySource,
    case_id: Option<String>,
    identity: HttpDependencyIdentity,
    record: RecordedHttpExchange,
    status: super::ReplayExchangeStatus,
    shared_origin: Option<cross_case::SharedOrigin>,
    lifecycle_prefix: Option<Arc<crate::http::termination::PrefixDelivery>>,
    time_copy_delivery: Option<contracts::time_copies::PreparedRead>,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct RecordedTcpGatewayConnection {
    domain: Option<String>,
    fake_addr: String,
    client_to_server_bytes: u64,
    server_to_client_bytes: u64,
    error: Option<String>,
}

#[derive(Debug, Clone)]
pub(super) struct ReplayHttpBlackhole {
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
pub(super) struct HttpReplayEvents {
    pub(super) cancelled: BTreeMap<usize, cancelled::Audit>,
    pub(super) global_report: crate::replay::report::global_evidence::regular_usage::Usage,
    pub(super) dirty_case_ids: BTreeSet<String>,
    pub(super) matched_count: usize,
    pub(super) matched: Vec<MatchedHttpExchangeReport>,
    pub(super) matched_details: SuccessDetailBudget,
    pub(super) unmatched: Vec<HttpRequestReport>,
    pub(super) unsupported: Vec<HttpRequestReport>,
    pub(super) header_mismatches: Vec<HeaderDifferenceReport>,
    pub(super) header_observations: Vec<HeaderDifferenceReport>,
    pub(super) header_observation_count: usize,
}

impl HttpReplayEvents {
    pub(super) fn case_has_runtime_failure(&self, case: &str) -> bool {
        self.unmatched
            .iter()
            .chain(&self.unsupported)
            .any(|event| event.case_id.as_deref() == Some(case))
    }
}

pub(super) fn case_exchange_index(exchanges: &[ReplayHttpExchange]) -> CaseExchangeIndex {
    let mut index = CaseExchangeIndex::default();
    extend_case_exchange_index(&mut index, exchanges, 0);
    index
}

pub(super) fn extend_case_exchange_index(
    index: &mut CaseExchangeIndex,
    exchanges: &[ReplayHttpExchange],
    start: usize,
) {
    for (position, exchange) in exchanges.iter().enumerate().skip(start) {
        index.register(exchange.source, exchange.case_id.as_deref(), position);
    }
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct MatchedHttpExchangeReport {
    pub(super) case_id: Option<String>,
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
pub(super) struct HttpRequestReport {
    pub(super) case_id: Option<String>,
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
pub(super) struct RecordedHttpExchangeSummary {
    source: ReplaySource,
    source_http_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    shared_origin: Option<cross_case::SharedOrigin>,
    index: usize,
    pub(super) case_id: Option<String>,
    scheme: HttpReplayScheme,
    target: TargetKey,
    method: String,
    uri: String,
    status: Option<u16>,
}

pub(super) fn register_http_exchange(
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
            "motan" => ReplayProtocol::Motan,
            "redis" => ReplayProtocol::Redis,
            "memcached" => ReplayProtocol::Memcached,
            other => {
                return Err(anyhow!(
                    "http_exchange {} advertises unsupported TCP protocol {other:?}",
                    record.uri
                ));
            }
        };
        register_replay_target_at(
            targets,
            &TargetKey {
                host: super::normalize_host(&discovered.alias),
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
        record.response_stream.is_some()
            || !matches!(
                stream_mime.as_deref(),
                Some("text/event-stream" | "application/x-ndjson" | "application/ndjson")
            ),
        "recorded HTTP streaming dependency has no chunk timing evidence; re-record this case"
    );
    if let Some(stream) = &record.response_stream {
        let body = record
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
                record.error.is_none(),
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
    if record.request_body.truncated {
        return Err(anyhow!(
            "http_exchange {} {} has a truncated request body",
            record.method,
            record.uri
        ));
    }
    if record
        .response_body
        .as_ref()
        .is_some_and(|body| body.truncated)
    {
        return Err(anyhow!(
            "http_exchange {} {} has a truncated response body",
            record.method,
            record.uri
        ));
    }
    exchanges.push(ReplayHttpExchange {
        source,
        case_id: case_id.map(ToOwned::to_owned),
        identity,
        record,
        status: super::ReplayExchangeStatus::Available,
        shared_origin: None,
        lifecycle_prefix: None,
        time_copy_delivery: None,
    });
    Ok(())
}

pub(super) fn register_tcp_connection_blackhole(
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
        host: super::normalize_host(domain),
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

pub(super) fn observe_recorded_policy_exchanges(
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
            &exchange.record.method,
            &exchange.record.uri,
        );
    }
}

fn identity_from_record(record: &RecordedHttpExchange) -> Result<HttpDependencyIdentity> {
    let scheme = normalize_scheme(&record.scheme)?;
    let authority = record
        .authority
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow!("http_exchange {} has no authority", record.uri))?
        .parse::<Authority>()
        .with_context(|| format!("invalid recorded HTTP authority for {}", record.uri))?;
    let port = authority.port_u16().unwrap_or(match scheme {
        HttpReplayScheme::Http => 80,
        HttpReplayScheme::Https => 443,
    });
    Ok(HttpDependencyIdentity {
        scheme,
        target: TargetKey {
            host: super::normalize_host(authority.host()),
            port,
        },
    })
}

fn normalize_scheme(value: &str) -> Result<HttpReplayScheme> {
    match value.trim().to_ascii_lowercase().as_str() {
        "http" | "fake_ip_http" | "http_gateway" => Ok(HttpReplayScheme::Http),
        "https" | "fake_ip_https" => Ok(HttpReplayScheme::Https),
        other => Err(anyhow!("unsupported recorded HTTP scheme {other}")),
    }
}

impl ReplayState {
    pub(super) fn http_case_is_dirty(&self, case_id: &str) -> bool {
        self.http_ingress.case_failed(case_id)
            || self.http_events.dirty_case_ids.contains(case_id)
            || self.http_case_exchange_index.any(case_id, |index| {
                self.http_exchanges.get(index).is_some_and(|exchange| {
                    let allowed = self.allowed_unused_http.as_ref().is_some_and(|config| {
                        config.hosts.contains(&exchange.identity.target.host)
                    });
                    !exchange.status.is_consumed()
                        && !allowed
                        && !self.permits_cancelled_http_omission(index)
                })
            })
    }

    fn claim_http_blackhole(&mut self, target: &TargetKey, method: &Method, uri: &Uri) -> bool {
        let Some(active_case_id) = self.active_case_id.as_deref() else {
            return false;
        };
        let Some(blackhole) = self.http_blackholes.iter_mut().find(|blackhole| {
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
        if let Some(report) = self.http_events.unmatched.last_mut() {
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
            self.http_events.dirty_case_ids.insert(case_id.clone());
        }
        self.http_events.unmatched.push(HttpRequestReport {
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
        self.http_exchanges
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
                if !in_scope || exchange.status.is_consumed() {
                    return false;
                }
                let is_allowed = source == ReplaySource::Case
                    && (self.http_events.cancelled.contains_key(index)
                        || self.allowed_unused_http.as_ref().is_some_and(|config| {
                            config.hosts.contains(&exchange.identity.target.host)
                        }));
                is_allowed == allowed
            })
            .map(move |(index, exchange)| RecordedHttpExchangeSummary {
                source: exchange.source,
                source_http_id: exchange.record.id.clone(),
                shared_origin: exchange.shared_origin.clone(),
                index,
                case_id: exchange.case_id.clone(),
                scheme: exchange.identity.scheme,
                target: exchange.identity.target.clone(),
                method: exchange.record.method.clone(),
                uri: uri_path_only(&exchange.record.uri),
                status: exchange.record.response_status,
            })
    }
    pub(super) fn unused_http_exchanges(
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
            && self.record.outcome == crate::DependencyExchangeOutcome::Response
            && self
                .record
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

/// Keep the already decoded body only when multipart may use it next.
fn http_request_comparison(
    exchange: &ReplayHttpExchange,
    method: &Method,
    uri: &Uri,
    body: &[u8],
    ignored_query_params: &[String],
) -> (Option<String>, Option<Vec<u8>>) {
    if !exchange.record.method.eq_ignore_ascii_case(method.as_str()) {
        return (
            Some(format!(
                "HTTP method mismatch: recorded {} actual {}",
                exchange.record.method, method
            )),
            None,
        );
    }
    if let Some(reason) =
        uri_mismatch_reason(&exchange.record.uri, &uri.to_string(), ignored_query_params)
    {
        return (Some(reason), None);
    }
    match decode_body(&exchange.record.request_body) {
        Ok(recorded_body) => {
            let mismatch = (!bodies_match(&recorded_body, body))
                .then(|| "HTTP request body did not match the recorded body".to_string());
            let multipart_body = (!exchange.record.request_body.truncated
                && multipart::supports_headers(&exchange.record.request_headers))
            .then_some(recorded_body);
            (mismatch, multipart_body)
        }
        Err(error) => (
            Some(format!("failed to decode recorded request body: {error}")),
            None,
        ),
    }
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

fn host_matches_target(host: &str, target: &TargetKey) -> bool {
    let Ok(authority) = host.parse::<Authority>() else {
        return false;
    };
    super::normalize_host(authority.host()) == target.host
        && authority.port_u16().unwrap_or(target.port) == target.port
}

fn normalize_uri(value: &str, ignored_query_params: &[String]) -> (String, Vec<(String, String)>) {
    let parsed = value.parse::<Uri>().ok();
    let path = parsed
        .as_ref()
        .map(|uri| uri.path())
        .unwrap_or_else(|| value.split('?').next().unwrap_or(value));
    let raw_query = parsed
        .as_ref()
        .and_then(Uri::query)
        .or_else(|| value.split_once('?').map(|(_, query)| query))
        .unwrap_or_default();
    let mut query = form_urlencoded::parse(raw_query.as_bytes())
        .filter(|(key, _)| {
            !ignored_query_params
                .iter()
                .any(|ignored| ignored.eq_ignore_ascii_case(key))
        })
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    query.sort();
    (path.to_string(), query)
}

fn uri_path_only(value: &str) -> String {
    value
        .parse::<Uri>()
        .ok()
        .map(|uri| uri.path().to_string())
        .unwrap_or_else(|| value.split('?').next().unwrap_or(value).to_string())
}

pub(in crate::replay) fn uri_mismatch_reason(
    recorded: &str,
    actual: &str,
    ignored_query_params: &[String],
) -> Option<String> {
    let (recorded_path, recorded_query) = normalize_uri(recorded, ignored_query_params);
    let (actual_path, actual_query) = normalize_uri(actual, ignored_query_params);
    if recorded_path != actual_path {
        return Some("HTTP path did not match the recorded request".to_string());
    }

    let ignored_count_differences = ignored_query_params
        .iter()
        .filter_map(|ignored| {
            let recorded_count = query_param_count(recorded, ignored);
            let actual_count = query_param_count(actual, ignored);
            (recorded_count != actual_count)
                .then(|| format!("{ignored} (recorded {recorded_count}, actual {actual_count})"))
        })
        .collect::<Vec<_>>();
    if !ignored_count_differences.is_empty() {
        return Some(format!(
            "HTTP ignored query parameter presence differed: {}",
            ignored_count_differences.join(", ")
        ));
    }

    if recorded_query == actual_query {
        return None;
    }

    let recorded_keys = query_key_counts(&recorded_query);
    let actual_keys = query_key_counts(&actual_query);
    if recorded_keys != actual_keys {
        let differing_keys = recorded_keys
            .keys()
            .chain(actual_keys.keys())
            .filter(|key| recorded_keys.get(*key) != actual_keys.get(*key))
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        return Some(format!(
            "HTTP stable query parameter names or counts differed: {}",
            differing_keys.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }

    let differing_value_keys = recorded_keys
        .keys()
        .filter(|key| query_values(&recorded_query, key) != query_values(&actual_query, key))
        .cloned()
        .collect::<Vec<_>>();
    Some(format!(
        "HTTP stable query parameter values differed for: {}",
        differing_value_keys.join(", ")
    ))
}

fn query_key_counts(query: &[(String, String)]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for (key, _) in query {
        *counts.entry(key.clone()).or_default() += 1;
    }
    counts
}

fn query_values(query: &[(String, String)], key: &str) -> Vec<String> {
    query
        .iter()
        .filter(|(query_key, _)| query_key == key)
        .map(|(_, value)| value.clone())
        .collect()
}

fn query_param_count(uri: &str, key: &str) -> usize {
    let parsed = uri.parse::<Uri>().ok();
    let query = parsed
        .as_ref()
        .and_then(Uri::query)
        .or_else(|| uri.split_once('?').map(|(_, query)| query))
        .unwrap_or_default();
    form_urlencoded::parse(query.as_bytes())
        .filter(|(part_key, _)| part_key.eq_ignore_ascii_case(key))
        .count()
}

fn bodies_match(recorded: &[u8], actual: &[u8]) -> bool {
    match (
        serde_json::from_slice::<Value>(recorded),
        serde_json::from_slice::<Value>(actual),
    ) {
        (Ok(recorded), Ok(actual)) => recorded == actual,
        _ => recorded == actual,
    }
}

fn decode_body(body: &RecordedBodyCapture) -> Result<Vec<u8>> {
    if body.truncated {
        return Err(anyhow!("recorded HTTP body is truncated"));
    }
    match body.encoding.as_str() {
        "utf8" => Ok(body.data.as_bytes().to_vec()),
        "base64" => STANDARD
            .decode(&body.data)
            .context("failed to decode recorded HTTP body base64"),
        other => Err(anyhow!("unsupported recorded HTTP body encoding {other}")),
    }
}

fn response_from_record(record: RecordedHttpExchange) -> Result<Response<Full<Bytes>>> {
    let status = record
        .response_status
        .and_then(|status| StatusCode::from_u16(status).ok())
        .context("recorded HTTP response has no valid status")?;
    let body = record
        .response_body
        .as_ref()
        .map(decode_body)
        .transpose()?
        .unwrap_or_default();
    let body_length = body.len();
    let mut response = Response::new(Full::new(Bytes::from(body)));
    *response.status_mut() = status;
    *response.headers_mut() =
        response_headers_for_payload(record.response_headers.as_ref(), body_length, Utc::now());
    Ok(response)
}

fn response_headers_for_payload(
    headers: Option<&HeaderSnapshot>,
    body_length: usize,
    delivered_at: chrono::DateTime<Utc>,
) -> hyper::HeaderMap {
    let mut output = hyper::HeaderMap::new();
    if let Some(headers) = headers {
        for (name, values) in headers {
            if is_hop_by_hop_header(name) {
                continue;
            }
            let Ok(name) = hyper::header::HeaderName::from_bytes(name.as_bytes()) else {
                continue;
            };
            for value in values {
                if let Ok(value) = hyper::header::HeaderValue::from_str(value) {
                    output.append(name.clone(), value);
                }
            }
        }
    }
    output.insert(
        CONTENT_LENGTH,
        hyper::header::HeaderValue::from(body_length),
    );
    if !output.contains_key(hyper::header::DATE) {
        output.insert(
            hyper::header::DATE,
            hyper::header::HeaderValue::from_str(
                &delivered_at.format("%a, %d %b %Y %H:%M:%S GMT").to_string(),
            )
            .expect("UTC HTTP dates are valid header values"),
        );
    }
    output
}

fn is_hop_by_hop_header(name: &str) -> bool {
    name.eq_ignore_ascii_case(CONNECTION.as_str())
        || name.eq_ignore_ascii_case(CONTENT_LENGTH.as_str())
        || name.eq_ignore_ascii_case(TRANSFER_ENCODING.as_str())
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case("proxy-connection")
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

pub(super) fn release_consumed_payloads(
    exchanges: &mut [ReplayHttpExchange],
    cases: &BTreeMap<String, super::ReplayCase>,
) {
    for exchange in exchanges {
        if exchange.source == ReplaySource::Case
            && exchange.status.is_consumed()
            && !exchange.is_repeatable_preflight_probe()
            && exchange.case_id.as_ref().is_some_and(|id| {
                cases
                    .get(id)
                    .is_some_and(|case| case.status == super::ReplayCaseStatus::Ended)
            })
        {
            exchange.record.request_body.data = String::new();
            if let Some(body) = &mut exchange.record.response_body {
                body.data = String::new();
            }
        }
    }
}

impl ReplayState {
    pub(in crate::replay) fn http_case_in_flight_diagnostic(&self) -> serde_json::Value {
        let pending = self.http_exchanges.iter().enumerate().filter(|(_, e)| {
            e.source == ReplaySource::Case
                && matches!(
                    e.status,
                    super::ReplayExchangeStatus::Responding
                        | super::ReplayExchangeStatus::AwaitingClientTermination
                )
        });
        let count = pending.clone().count();
        let references = pending
            .take(4)
            .map(|(index, e)| {
                serde_json::json!({"index":index, "case_id":e.case_id,
                "exchange_id":e.record.id, "status":format!("{:?}", e.status)})
            })
            .collect::<Vec<_>>();
        serde_json::json!({"count":count, "references":references,
            "omitted":count.saturating_sub(4)})
    }

    pub(in crate::replay) fn http_has_case_in_flight(&self) -> bool {
        self.http_ingress
            .has_case_pending(self.active_case_id.as_deref())
            || self.http_exchanges.iter().any(|e| {
                e.source == ReplaySource::Case
                    && matches!(
                        e.status,
                        super::ReplayExchangeStatus::Responding
                            | super::ReplayExchangeStatus::AwaitingClientTermination
                    )
            })
    }

    pub(in crate::replay) fn http_has_in_flight(&self) -> bool {
        self.http_ingress.has_pending()
            || self.http_exchanges.iter().any(|e| {
                matches!(
                    e.status,
                    super::ReplayExchangeStatus::Responding
                        | super::ReplayExchangeStatus::AwaitingClientTermination
                )
            })
    }
}

/// Native protocol probes remain available; business initialization closes once.
pub(in crate::replay) fn startup_counts(
    exchanges: &mut [ReplayHttpExchange],
    close: bool,
) -> super::startup::Counts {
    let mut counts = super::startup::Counts::default();
    for exchange in exchanges {
        let mandatory = !exchange.is_repeatable_preflight_probe();
        counts.observe(exchange.source, &mut exchange.status, mandatory, close);
    }
    counts
}
