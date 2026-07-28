use std::collections::BTreeMap;
use std::convert::Infallible;
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
use url::form_urlencoded;

use super::{
    HttpPolicyContext, MitmCa, PolicyDecision, ReplayPolicyRuntime, ReplayProtocol,
    ReplayReportWriter, ReplaySource, ReplayState, ReplayTarget, TargetKey, push_success_detail,
    register_replay_target, register_replay_target_at,
};
use crate::DiscoveredTcpTarget;

type HeaderSnapshot = BTreeMap<String, Vec<String>>;

#[derive(Debug, Clone, Deserialize)]
pub(super) struct RecordedHttpExchange {
    scheme: String,
    method: String,
    uri: String,
    authority: Option<String>,
    request_body: RecordedBodyCapture,
    response_status: Option<u16>,
    response_headers: Option<HeaderSnapshot>,
    response_body: Option<RecordedBodyCapture>,
    #[serde(default)]
    discovered_tcp_targets: Vec<DiscoveredTcpTarget>,
    error: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct RecordedBodyCapture {
    encoding: String,
    truncated: bool,
    data: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
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
    consumed: bool,
}

#[derive(Debug, Default)]
pub(super) struct HttpReplayEvents {
    pub(super) matched_count: usize,
    pub(super) matched: Vec<MatchedHttpExchangeReport>,
    pub(super) unmatched: Vec<HttpRequestReport>,
    pub(super) unsupported: Vec<HttpRequestReport>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct MatchedHttpExchangeReport {
    pub(super) case_id: Option<String>,
    source: ReplaySource,
    index: usize,
    scheme: HttpReplayScheme,
    target: TargetKey,
    method: String,
    uri: String,
    status: u16,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct HttpRequestReport {
    pub(super) case_id: Option<String>,
    scheme: HttpReplayScheme,
    target: TargetKey,
    method: String,
    uri: String,
    reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct RecordedHttpExchangeSummary {
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
            "motan" => ReplayProtocol::Motan,
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

pub(super) async fn handle_http_replay_connection(
    stream: TcpStream,
    _peer_addr: std::net::SocketAddr,
    target: ReplayTarget,
    state: Arc<Mutex<ReplayState>>,
    report_writer: ReplayReportWriter,
    ca: Arc<MitmCa>,
) -> Result<()> {
    match target.protocol {
        ReplayProtocol::Http => serve_http_io(stream, target, state, report_writer).await,
        ReplayProtocol::Https => {
            let server_config = ca.server_config_for_host(&target.host)?;
            let tls = TlsAcceptor::from(server_config)
                .accept(stream)
                .await
                .with_context(|| {
                    format!("HTTPS replay TLS handshake failed for {}", target.host)
                })?;
            serve_http_io(tls, target, state, report_writer).await
        }
        ReplayProtocol::Mysql
        | ReplayProtocol::Redis
        | ReplayProtocol::Memcached
        | ReplayProtocol::Kafka
        | ReplayProtocol::Motan => Err(anyhow!("HTTP replay received a non-HTTP target")),
    }
}

async fn serve_http_io<T>(
    io: T,
    target: ReplayTarget,
    state: Arc<Mutex<ReplayState>>,
    report_writer: ReplayReportWriter,
) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |request| {
        handle_http_request(
            request,
            target.clone(),
            state.clone(),
            report_writer.clone(),
        )
    });
    hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(io), service)
        .await
        .context("failed to serve HTTP replay connection")
}

async fn handle_http_request(
    request: Request<Incoming>,
    target: ReplayTarget,
    state: Arc<Mutex<ReplayState>>,
    report_writer: ReplayReportWriter,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let host = request
        .headers()
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let body = match request.into_body().collect().await {
        Ok(body) => body.to_bytes(),
        Err(error) => {
            return Ok(error_response(
                StatusCode::BAD_GATEWAY,
                &format!("failed to read replay request body: {error}"),
            ));
        }
    };
    let scheme = match target.protocol {
        ReplayProtocol::Https => HttpReplayScheme::Https,
        _ => HttpReplayScheme::Http,
    };
    let target_key = TargetKey {
        host: target.host,
        port: target.port,
    };
    let matched = {
        let mut state = state.lock().await;
        state.match_http_request(scheme, &target_key, &method, &uri, host.as_deref(), &body)
    };
    let response = match matched {
        Ok(record) => response_from_record(record),
        Err(reason) => Ok(error_response(StatusCode::BAD_GATEWAY, &reason)),
    }
    .unwrap_or_else(|error| error_response(StatusCode::BAD_GATEWAY, &error.to_string()));
    report_writer.request();
    Ok(response)
}

impl ReplayState {
    fn match_http_request(
        &mut self,
        scheme: HttpReplayScheme,
        target: &TargetKey,
        method: &Method,
        uri: &Uri,
        host: Option<&str>,
        body: &[u8],
    ) -> std::result::Result<RecordedHttpExchange, String> {
        let active_case_id = self.active_case_id.clone();
        if let Some(host) = host
            && !host_matches_target(host, target)
        {
            let reason = format!(
                "HTTP Host header does not match replay target {}",
                target.host
            );
            self.record_unmatched_http(scheme, target, method, uri, reason.clone());
            return Err(reason);
        }

        let mut matching_index = None;
        let mut matching_policy_decision = PolicyDecision::default();
        let mut closest_mismatch = None;
        'sources: for source in [ReplaySource::Case, ReplaySource::Global] {
            for (index, exchange) in self.http_exchanges.iter().enumerate() {
                if exchange.consumed
                    || exchange.source != source
                    || !active_http_case_matches(active_case_id.as_deref(), exchange)
                    || exchange.identity.scheme != scheme
                    || exchange.identity.target != *target
                {
                    continue;
                }
                let policy_decision = if let Some(policy) = &self.replay_policy {
                    match policy.preview_http(
                        &HttpPolicyContext {
                            case_id: active_case_id.as_deref(),
                            target,
                            method: method.as_str(),
                            recorded_uri: &exchange.record.uri,
                            actual_uri: &uri.to_string(),
                        },
                        Utc::now(),
                    ) {
                        Ok(decision) => decision,
                        Err(reason) => {
                            closest_mismatch.get_or_insert(reason);
                            continue;
                        }
                    }
                } else {
                    PolicyDecision::default()
                };
                let mut ignored_query_params = self.http_ignore_query_params.clone();
                ignored_query_params.extend(policy_decision.dynamic_query_params.iter().cloned());
                let mismatch = http_request_mismatch_reason(
                    exchange,
                    method,
                    uri,
                    body,
                    &ignored_query_params,
                );
                if let Some(reason) = mismatch {
                    closest_mismatch.get_or_insert(reason);
                    continue;
                }
                matching_index = Some(index);
                matching_policy_decision = policy_decision;
                break 'sources;
            }
        }
        let Some(index) = matching_index else {
            let reason = closest_mismatch.unwrap_or_else(|| {
                "no recorded HTTP exchange matched the active case and target".to_string()
            });
            self.record_unmatched_http(scheme, target, method, uri, reason.clone());
            return Err(reason);
        };
        let exchange = self.http_exchanges[index].clone();
        if exchange.record.error.is_some() || exchange.record.response_status.is_none() {
            self.http_exchanges[index].consumed = true;
            let reason = "recorded HTTP exchange contains an upstream error that replay v1 cannot synthesize"
                .to_string();
            self.http_events.unsupported.push(HttpRequestReport {
                case_id: exchange.case_id,
                scheme,
                target: target.clone(),
                method: method.to_string(),
                uri: uri_path_only(&uri.to_string()),
                reason: reason.clone(),
            });
            return Err(reason);
        }

        self.http_exchanges[index].consumed = true;
        if let Some(policy) = &mut self.replay_policy {
            policy.commit(active_case_id.as_deref(), matching_policy_decision);
        }
        push_success_detail(
            &mut self.http_events.matched_count,
            &mut self.http_events.matched,
            MatchedHttpExchangeReport {
                case_id: exchange.case_id,
                source: exchange.source,
                index,
                scheme,
                target: target.clone(),
                method: method.to_string(),
                uri: uri_path_only(&uri.to_string()),
                status: exchange.record.response_status.unwrap_or_default(),
            },
        );
        Ok(exchange.record)
    }

    fn record_unmatched_http(
        &mut self,
        scheme: HttpReplayScheme,
        target: &TargetKey,
        method: &Method,
        uri: &Uri,
        reason: String,
    ) {
        self.http_events.unmatched.push(HttpRequestReport {
            case_id: self.active_case_id.clone(),
            scheme,
            target: target.clone(),
            method: method.to_string(),
            uri: uri_path_only(&uri.to_string()),
            reason,
        });
    }

    pub(super) fn unused_http_exchanges(
        &self,
        source: ReplaySource,
        allowed: bool,
    ) -> Vec<RecordedHttpExchangeSummary> {
        self.http_exchanges
            .iter()
            .enumerate()
            .filter(|(_, exchange)| {
                if exchange.source != source || exchange.consumed {
                    return false;
                }
                let is_allowed = source == ReplaySource::Case
                    && self.allowed_unused_http.as_ref().is_some_and(|config| {
                        config.hosts.contains(&exchange.identity.target.host)
                    });
                is_allowed == allowed
            })
            .map(|(index, exchange)| RecordedHttpExchangeSummary {
                index,
                case_id: exchange.case_id.clone(),
                scheme: exchange.identity.scheme,
                target: exchange.identity.target.clone(),
                method: exchange.record.method.clone(),
                uri: uri_path_only(&exchange.record.uri),
                status: exchange.record.response_status,
            })
            .collect()
    }
}

fn http_request_mismatch_reason(
    exchange: &ReplayHttpExchange,
    method: &Method,
    uri: &Uri,
    body: &[u8],
    ignored_query_params: &[String],
) -> Option<String> {
    if !exchange.record.method.eq_ignore_ascii_case(method.as_str()) {
        return Some(format!(
            "HTTP method mismatch: recorded {} actual {}",
            exchange.record.method, method
        ));
    }
    if let Some(reason) =
        uri_mismatch_reason(&exchange.record.uri, &uri.to_string(), ignored_query_params)
    {
        return Some(reason);
    }
    match decode_body(&exchange.record.request_body) {
        Ok(recorded_body) if bodies_match(&recorded_body, body) => None,
        Ok(_) => Some("HTTP request body did not match the recorded body".to_string()),
        Err(error) => Some(format!("failed to decode recorded request body: {error}")),
    }
}

fn active_http_case_matches(active_case_id: Option<&str>, exchange: &ReplayHttpExchange) -> bool {
    match exchange.source {
        ReplaySource::Global => true,
        ReplaySource::Case => exchange.case_id.as_deref() == active_case_id,
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

fn uri_mismatch_reason(
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
    let mut response = Response::new(Full::new(Bytes::from(body)));
    *response.status_mut() = status;
    if let Some(headers) = record.response_headers {
        for (name, values) in headers {
            if is_hop_by_hop_header(&name) {
                continue;
            }
            let Ok(name) = hyper::header::HeaderName::from_bytes(name.as_bytes()) else {
                continue;
            };
            for value in values {
                if let Ok(value) = hyper::header::HeaderValue::from_str(&value) {
                    response.headers_mut().append(name.clone(), value);
                }
            }
        }
    }
    Ok(response)
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
mod tests;
