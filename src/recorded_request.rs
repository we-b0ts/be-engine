use std::collections::BTreeMap;
use std::path::Path;
use std::str::FromStr as _;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::header::{HeaderName, HeaderValue};
use hyper::{Method, Request, StatusCode, Uri};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use serde::Deserialize;

use crate::http::response_headers;
use crate::recorder::HeaderMapSnapshot;

type HttpClient = Client<HttpConnector, Full<Bytes>>;

#[derive(Debug, Deserialize)]
struct RecordedRequest {
    method: String,
    uri: String,
    headers: BTreeMap<String, Vec<String>>,
    body: RecordedBody,
}

#[derive(Debug, Deserialize)]
struct RecordedBody {
    encoding: String,
    data: String,
    truncated: bool,
}

pub(crate) struct RecordedHttpClient {
    client: HttpClient,
    origin: String,
    request_timeout: Duration,
    max_response_bytes: usize,
    preserve_host: bool,
    request_rules: Option<Arc<crate::request_rules::RequestRuleRuntime>>,
}

pub(crate) struct RecordedHttpResponse {
    pub(crate) request_sent_at: chrono::DateTime<chrono::Utc>,
    pub(crate) request_rules: Vec<crate::request_rules::RequestRuleObservation>,
    pub(crate) request_headers: HeaderMapSnapshot,
    pub(crate) status: StatusCode,
    pub(crate) headers: HeaderMapSnapshot,
    pub(crate) body: Bytes,
}

impl RecordedHttpClient {
    pub(crate) fn new(
        origin: String,
        request_timeout: Duration,
        max_response_bytes: usize,
    ) -> Self {
        let mut connector = HttpConnector::new();
        connector.enforce_http(true);
        Self {
            client: Client::builder(TokioExecutor::new()).build(connector),
            origin,
            request_timeout,
            max_response_bytes,
            preserve_host: false,
            request_rules: None,
        }
    }

    pub(crate) fn new_recording_input(
        origin: String,
        request_timeout: Duration,
        max_response_bytes: usize,
    ) -> Self {
        Self {
            preserve_host: true,
            ..Self::new(origin, request_timeout, max_response_bytes)
        }
    }

    pub(crate) fn with_request_rules(mut self, root: &Path, policy: &Path) -> Result<Self> {
        self.request_rules = Some(Arc::new(crate::request_rules::RequestRuleRuntime::load(
            root, policy,
        )?));
        Ok(self)
    }

    pub(crate) fn with_request_rule_runtime(
        mut self,
        request_rules: Arc<crate::request_rules::RequestRuleRuntime>,
    ) -> Self {
        self.request_rules = Some(request_rules);
        self
    }

    pub(crate) async fn send(&self, request_path: &Path) -> Result<RecordedHttpResponse> {
        let request_label = request_path.display().to_string();
        let request_path = request_path.to_path_buf();
        let bytes = tokio::task::spawn_blocking(move || {
            crate::request_headers::load_request_file(&request_path)
        })
        .await
        .context("recorded request loader task failed")??;
        self.send_bytes(&bytes, &request_label).await
    }

    pub(crate) async fn send_bytes(
        &self,
        bytes: &[u8],
        request_label: &str,
    ) -> Result<RecordedHttpResponse> {
        let mut value: serde_json::Value = serde_json::from_slice(bytes)
            .with_context(|| format!("invalid recorded request {request_label}"))?;
        let request_sent_at = chrono::Utc::now();
        let request_rules = self
            .request_rules
            .as_ref()
            .map(|rules| rules.apply(&mut value, request_sent_at))
            .transpose()?
            .unwrap_or_default();
        let recorded: RecordedRequest =
            serde_json::from_value(value).context("invalid recorded request shape")?;
        let request = build_request(&self.origin, &recorded, self.preserve_host)?;
        let request_headers = response_headers::snapshot_request_context(request.headers());
        tokio::time::timeout(self.request_timeout, async {
            let response = self
                .client
                .request(request)
                .await
                .context("recorded HTTP request failed")?;
            let status = response.status();
            let headers = response_headers::snapshot_standard(response.headers());
            let body = collect_limited(response.into_body(), self.max_response_bytes).await?;
            Ok::<_, anyhow::Error>(RecordedHttpResponse {
                request_sent_at,
                request_rules,
                request_headers,
                status,
                headers,
                body,
            })
        })
        .await
        .context("recorded HTTP request timed out")?
    }
}

fn build_request(
    origin: &str,
    recorded: &RecordedRequest,
    preserve_host: bool,
) -> Result<Request<Full<Bytes>>> {
    let method = Method::from_bytes(recorded.method.as_bytes())
        .with_context(|| format!("invalid recorded HTTP method {:?}", recorded.method))?;
    let uri = target_uri(origin, &recorded.uri)?;
    let mut builder = Request::builder().method(method).uri(uri);
    let headers = builder
        .headers_mut()
        .context("failed to initialize recorded HTTP request headers")?;
    for (name, values) in &recorded.headers {
        if is_hop_by_hop(name)
            || name.eq_ignore_ascii_case("accept-encoding")
            || (!preserve_host && name.eq_ignore_ascii_case("host"))
        {
            continue;
        }
        let name = HeaderName::from_str(name)
            .with_context(|| format!("invalid recorded HTTP header name {name:?}"))?;
        for value in values {
            headers.append(
                name.clone(),
                HeaderValue::from_str(value)
                    .with_context(|| format!("invalid value for recorded HTTP header {name}"))?,
            );
        }
    }
    Ok(builder.body(Full::new(Bytes::from(decode_body(&recorded.body)?)))?)
}

pub(crate) fn target_uri(origin: &str, recorded_uri: &str) -> Result<Uri> {
    let origin = Uri::from_str(origin).context("invalid HTTP request origin")?;
    let recorded = Uri::from_str(recorded_uri).context("invalid recorded request URI")?;
    let path_and_query = recorded
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    ensure!(
        path_and_query.starts_with('/'),
        "recorded request URI must have an absolute path"
    );
    Uri::builder()
        .scheme(
            origin
                .scheme()
                .context("HTTP request origin has no scheme")?
                .clone(),
        )
        .authority(
            origin
                .authority()
                .context("HTTP request origin has no authority")?
                .clone(),
        )
        .path_and_query(path_and_query)
        .build()
        .context("failed to build recorded request URI")
}

fn decode_body(body: &RecordedBody) -> Result<Vec<u8>> {
    ensure!(!body.truncated, "recorded request body is truncated");
    match body.encoding.as_str() {
        "utf8" => Ok(body.data.as_bytes().to_vec()),
        "base64" => STANDARD
            .decode(&body.data)
            .context("recorded request body contains invalid base64"),
        encoding => bail!("unsupported recorded request body encoding {encoding:?}"),
    }
}

async fn collect_limited(mut body: hyper::body::Incoming, limit: usize) -> Result<Bytes> {
    let mut collected = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.context("failed to read recorded HTTP response body")?;
        if let Ok(data) = frame.into_data() {
            ensure!(
                collected.len().saturating_add(data.len()) <= limit,
                "recorded HTTP response body exceeds configured limit of {limit} bytes"
            );
            collected.extend_from_slice(&data);
        }
    }
    Ok(Bytes::from(collected))
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "content-length"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retargets_absolute_and_relative_recorded_uris() {
        assert_eq!(
            target_uri("http://127.0.0.1:8081", "/api/users?id=1")
                .unwrap()
                .to_string(),
            "http://127.0.0.1:8081/api/users?id=1"
        );
        assert_eq!(
            target_uri(
                "http://127.0.0.1:8081",
                "https://source.test/api/users?id=1",
            )
            .unwrap()
            .to_string(),
            "http://127.0.0.1:8081/api/users?id=1"
        );
    }

    #[test]
    fn rejects_truncated_and_unknown_request_body_encodings() {
        assert!(
            decode_body(&RecordedBody {
                encoding: "utf8".to_string(),
                data: String::new(),
                truncated: true,
            })
            .is_err()
        );
        assert!(
            decode_body(&RecordedBody {
                encoding: "hex".to_string(),
                data: String::new(),
                truncated: false,
            })
            .is_err()
        );
    }

    #[test]
    fn strips_connection_specific_and_encoding_headers() {
        let recorded = RecordedRequest {
            method: "POST".to_string(),
            uri: "/api".to_string(),
            headers: BTreeMap::from([
                ("host".to_string(), vec!["source".to_string()]),
                ("accept-encoding".to_string(), vec!["gzip".to_string()]),
                ("x-request-id".to_string(), vec!["one".to_string()]),
            ]),
            body: RecordedBody {
                encoding: "utf8".to_string(),
                data: "body".to_string(),
                truncated: false,
            },
        };
        let request = build_request("http://127.0.0.1:8081", &recorded, false).unwrap();

        assert!(!request.headers().contains_key("host"));
        assert!(!request.headers().contains_key("accept-encoding"));
        assert_eq!(request.headers()["x-request-id"], "one");

        let recording_request = build_request("http://127.0.0.1:8081", &recorded, true).unwrap();
        assert_eq!(recording_request.headers()["host"], "source");
    }
}
