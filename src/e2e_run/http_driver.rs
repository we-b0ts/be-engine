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
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

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
    let request_bytes = tokio::fs::read(request_path).await?;
    let kind: RequestKind = serde_json::from_slice(&request_bytes)?;
    if kind.protocol_version.is_some() {
        return capture_motan_case(config, kind, actual_response_path).await;
    }
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

#[derive(Deserialize)]
struct RequestKind {
    #[serde(default)]
    protocol_version: Option<String>,
    #[serde(default)]
    frame: Option<RecordedFrame>,
}

#[derive(Deserialize)]
struct RecordedFrame {
    encoding: String,
    data: String,
    truncated: bool,
}

async fn capture_motan_case(
    config: &ResolvedProjectConfig,
    request: RequestKind,
    actual_response_path: &Path,
) -> Result<()> {
    let upstream = config
        .target_motan_upstream
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("Motan case requires a configured target Motan endpoint"))?;
    let frame = request
        .frame
        .ok_or_else(|| anyhow::anyhow!("Motan request has no frame"))?;
    if frame.truncated {
        bail!("Motan request frame is truncated");
    }
    let raw = match frame.encoding.as_str() {
        "utf8" => frame.data.into_bytes(),
        "base64" => STANDARD.decode(frame.data)?,
        encoding => bail!("unsupported Motan request encoding {encoding:?}"),
    };
    let limits = motan_protocol::Limits::default();
    let motan_protocol::DecodeStatus::Complete(request) =
        motan_protocol::decode_frame(&raw, limits)?
    else {
        bail!("Motan request frame is incomplete");
    };
    let operation = async {
        let mut stream = TcpStream::connect(upstream).await?;
        stream.write_all(&raw).await?;
        if request.flags.oneway() {
            return Ok((204, Vec::new()));
        }
        let mut decoder = motan_protocol::FrameDecoder::new(limits)?;
        let response = loop {
            if let Some(frame) = decoder.decode()? {
                break frame;
            }
            let read = stream.read_buf(decoder.buffer_mut()).await?;
            if read == 0 {
                bail!("target closed before returning a Motan response");
            }
        };
        if response.request_id != request.request_id || response.version != request.version {
            bail!("target returned a mismatched Motan response frame");
        }
        let status = match response.response_kind() {
            Some(motan_protocol::ResponseKind::Normal) => 200,
            Some(motan_protocol::ResponseKind::Value) => 201,
            Some(motan_protocol::ResponseKind::Void) => 204,
            Some(motan_protocol::ResponseKind::Attachment) => 206,
            Some(motan_protocol::ResponseKind::Exception) => 500,
            Some(motan_protocol::ResponseKind::Other(_)) | None => 520,
        };
        Ok::<_, anyhow::Error>((status, response.raw().to_vec()))
    };
    let (status, body) = tokio::time::timeout(config.target_request_timeout, operation)
        .await
        .map_err(|_| anyhow::anyhow!("target Motan request timed out"))??;
    let (encoding, data) = match std::str::from_utf8(&body) {
        Ok(text) => ("utf8", text.to_owned()),
        Err(_) => ("base64", STANDARD.encode(&body)),
    };
    store::write_json(
        actual_response_path,
        &ActualResponse {
            version: 1,
            status,
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
