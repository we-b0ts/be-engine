use std::collections::BTreeMap;
use std::path::Path;
use std::str::FromStr as _;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::header::{HeaderName, HeaderValue};
use hyper::{Method, Request, Uri};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use serde::{Deserialize, Serialize};

use super::model::ResolvedProjectConfig;
use super::store;

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

#[derive(Debug, Serialize)]
struct ActualResponse {
    version: u8,
    status: u16,
    body: CapturedBody,
}

#[derive(Debug, Serialize)]
struct CapturedBody {
    encoding: &'static str,
    data: String,
    truncated: bool,
}

pub(super) async fn wait_until_ready(config: &ResolvedProjectConfig) -> Result<()> {
    let client = client();
    let readiness_uri = target_uri(&config.target_http_origin, &config.target_readiness_path)?;
    let deadline = tokio::time::Instant::now() + config.target_startup_timeout;
    loop {
        let request = Request::builder()
            .method(Method::GET)
            .uri(readiness_uri.clone())
            .body(Full::new(Bytes::new()))?;
        let last_error = match tokio::time::timeout(Duration::from_secs(2), client.request(request))
            .await
        {
            Ok(Ok(response)) if response.status().as_u16() == config.target_readiness_status => {
                return Ok(());
            }
            Ok(Ok(response)) => format!("HTTP {}", response.status()),
            Ok(Err(error)) => error.to_string(),
            Err(_) => "probe timed out".to_string(),
        };
        if tokio::time::Instant::now() >= deadline {
            bail!(
                "target did not become ready at {} with status {} within {:?}: {}",
                readiness_uri,
                config.target_readiness_status,
                config.target_startup_timeout,
                last_error
            );
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

pub(super) async fn capture_case(
    config: &ResolvedProjectConfig,
    request_path: &Path,
    actual_response_path: &Path,
) -> Result<()> {
    let bytes = tokio::fs::read(request_path)
        .await
        .with_context(|| format!("failed to read recorded request {}", request_path.display()))?;
    let recorded: RecordedRequest = serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid recorded request {}", request_path.display()))?;
    let request = build_request(config, &recorded)?;
    let response = tokio::time::timeout(config.target_request_timeout, async {
        let response = client()
            .request(request)
            .await
            .context("target HTTP request failed")?;
        let status = response.status();
        let body = collect_limited(response.into_body(), config.target_max_response_bytes).await?;
        Ok::<_, anyhow::Error>((status, body))
    })
    .await
    .context("target HTTP request timed out")??;
    let (encoding, data) = match std::str::from_utf8(&response.1) {
        Ok(text) => ("utf8", text.to_owned()),
        Err(_) => ("base64", STANDARD.encode(&response.1)),
    };
    store::write_json(
        actual_response_path,
        &ActualResponse {
            version: 1,
            status: response.0.as_u16(),
            body: CapturedBody {
                encoding,
                data,
                truncated: false,
            },
        },
    )
}

fn client() -> HttpClient {
    let mut connector = HttpConnector::new();
    connector.enforce_http(true);
    Client::builder(TokioExecutor::new()).build(connector)
}

fn build_request(
    config: &ResolvedProjectConfig,
    recorded: &RecordedRequest,
) -> Result<Request<Full<Bytes>>> {
    let method = Method::from_bytes(recorded.method.as_bytes())
        .with_context(|| format!("invalid recorded HTTP method {:?}", recorded.method))?;
    let uri = target_uri(&config.target_http_origin, &recorded.uri)?;
    let mut builder = Request::builder().method(method).uri(uri);
    let headers = builder
        .headers_mut()
        .context("failed to initialize target request headers")?;
    for (name, values) in &recorded.headers {
        if is_hop_by_hop(name) || name.eq_ignore_ascii_case("accept-encoding") {
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

fn target_uri(origin: &str, recorded_uri: &str) -> Result<Uri> {
    let origin = Uri::from_str(origin).context("invalid target HTTP origin")?;
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
                .context("target HTTP origin has no scheme")?
                .clone(),
        )
        .authority(
            origin
                .authority()
                .context("target HTTP origin has no authority")?
                .clone(),
        )
        .path_and_query(path_and_query)
        .build()
        .context("failed to build target request URI")
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
        let frame = frame.context("failed to read target HTTP response body")?;
        if let Ok(data) = frame.into_data() {
            ensure!(
                collected.len().saturating_add(data.len()) <= limit,
                "target HTTP response body exceeds configured limit of {limit} bytes"
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
            | "host"
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
            target_uri("http://127.0.0.1:8081", "http://source/api/users?id=1")
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
        let config = ResolvedProjectConfig {
            project_cli: "project-cli".into(),
            target_boot_dir: ".traffic-e2e/boot".into(),
            target_http_origin: "http://127.0.0.1:8081".to_string(),
            target_port: 8081,
            target_readiness_path: "/healthz".to_string(),
            target_readiness_status: 404,
            target_startup_timeout: Duration::from_secs(1),
            target_request_timeout: Duration::from_secs(1),
            target_max_response_bytes: 1024,
            source_container: "source".to_string(),
            breeze_container: Some("breeze".to_string()),
            replay_policy: "verification.yaml".into(),
            replay_startup_timeout: Duration::from_secs(1),
            pr_base: "dev-migration".to_string(),
            recorder_config: "recorder.toml".into(),
            recording_rule: "record-api".to_string(),
            runner_owned_response_assertions: true,
        };
        let request = build_request(
            &config,
            &RecordedRequest {
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
            },
        )
        .unwrap();

        assert!(!request.headers().contains_key("host"));
        assert!(!request.headers().contains_key("accept-encoding"));
        assert_eq!(request.headers()["x-request-id"], "one");
    }
}
