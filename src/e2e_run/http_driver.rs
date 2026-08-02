use std::path::Path;
use std::time::Duration;

use anyhow::{Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use http_body_util::Full;
use hyper::{Method, Request};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use serde::Serialize;

use super::model::ResolvedProjectConfig;
use super::store;
use crate::recorded_request::{RecordedHttpClient, target_uri};

type HttpClient = Client<HttpConnector, Full<Bytes>>;

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
    let response = RecordedHttpClient::new(
        config.target_http_origin.clone(),
        config.target_request_timeout,
        config.target_max_response_bytes,
    )
    .send(request_path)
    .await?;
    let (encoding, data) = match std::str::from_utf8(&response.body) {
        Ok(text) => ("utf8", text.to_owned()),
        Err(_) => ("base64", STANDARD.encode(&response.body)),
    };
    store::write_json(
        actual_response_path,
        &ActualResponse {
            version: 1,
            status: response.status.as_u16(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_readiness_uri_is_retargeted() {
        assert_eq!(
            target_uri("http://127.0.0.1:8081", "/healthz")
                .unwrap()
                .to_string(),
            "http://127.0.0.1:8081/healthz"
        );
    }
}
