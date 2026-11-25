//! HTTP observations and content verification for one exchange.

use std::{collections::BTreeMap, path::Path};

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::{Buf as _, BytesMut};
use chrono::{DateTime, Utc};
use http_body_util::BodyExt;
use hyper::{HeaderMap, body::Incoming, header};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::primary_protocol::assertion::{ResponseAssertionOptions, ResponseAssertionRuntime};

use super::{Connection, Opened};

pub(super) type Headers = BTreeMap<String, Vec<String>>;

pub(super) struct Response {
    expected: Value,
    source_body: Vec<u8>,
    target_headers: Headers,
    target_status: u16,
    target_headers_at: DateTime<Utc>,
    actual_body: BytesMut,
    incoming: Incoming,
    _connection: Connection,
    streaming: bool,
    limit: usize,
    seen_target_bytes: usize,
    seen_source_bytes: usize,
    last_part: Option<u64>,
}

impl Response {
    pub(super) fn begin(expected: Value, opened: Opened, limit: usize) -> Result<Self> {
        let (parts, incoming) = opened.response.into_parts();
        let source_headers: Headers = serde_json::from_value(expected["headers"].clone())
            .context("recorded primary response headers are unavailable")?;
        let streaming = source_headers
            .get(header::CONTENT_TYPE.as_str())
            .into_iter()
            .flatten()
            .any(|value| {
                matches!(
                    value
                        .split(';')
                        .next()
                        .unwrap_or_default()
                        .trim()
                        .to_ascii_lowercase()
                        .as_str(),
                    "text/event-stream" | "application/x-ndjson" | "application/ndjson"
                )
            });
        Ok(Self {
            expected,
            source_body: Vec::new(),
            target_headers: snapshot_headers(&parts.headers),
            target_status: parts.status.as_u16(),
            incoming,
            _connection: opened.connection,
            target_headers_at: Utc::now(),
            actual_body: BytesMut::new(),
            streaming,
            limit,
            seen_target_bytes: 0,
            seen_source_bytes: 0,
            last_part: None,
        })
    }

    pub(super) async fn part(&mut self, part: u64, expected: &[u8]) -> Result<()> {
        ensure!(
            self.last_part
                .map_or(part <= 1, |previous| previous.checked_add(1) == Some(part)),
            "invalid primary HTTP body part order"
        );
        self.last_part = Some(part);
        self.seen_source_bytes = self.seen_source_bytes.saturating_add(expected.len());
        ensure!(
            self.seen_source_bytes <= self.limit,
            "recorded primary HTTP body exceeds the response budget"
        );
        if self.streaming {
            while self.actual_body.len() < expected.len() {
                ensure!(
                    self.data().await?,
                    "Target primary stream ended before a recorded body part"
                );
            }
            ensure!(
                &self.actual_body[..expected.len()] == expected,
                "Target primary stream body differs at recorded part {part}"
            );
            self.actual_body.advance(expected.len());
        } else {
            if !expected.is_empty() && self.seen_target_bytes == 0 {
                ensure!(
                    self.data().await?,
                    "Target primary response ended before a recorded body part"
                );
            }
            self.source_body.extend_from_slice(expected);
        }
        Ok(())
    }

    async fn data(&mut self) -> Result<bool> {
        let Some(frame) = self
            .incoming
            .frame()
            .await
            .transpose()
            .context("Target primary HTTP receive failed")?
        else {
            return Ok(false);
        };
        let data = frame
            .into_data()
            .ok()
            .context("Target sent HTTP trailers where data was expected")?;
        self.seen_target_bytes = self.seen_target_bytes.saturating_add(data.len());
        ensure!(
            self.seen_target_bytes <= self.limit,
            "Target primary HTTP body exceeds the response budget"
        );
        self.actual_body.extend_from_slice(&data);
        Ok(true)
    }

    pub(super) async fn trailers(&mut self, expected: Value) -> Result<()> {
        let expected: Headers =
            serde_json::from_value(expected).context("invalid recorded HTTP trailers")?;
        let actual = loop {
            let frame = self
                .incoming
                .frame()
                .await
                .transpose()?
                .context("Target did not send recorded HTTP trailers")?;
            match frame.into_trailers() {
                Ok(trailers) => break trailers,
                Err(frame) => {
                    let data = frame
                        .into_data()
                        .ok()
                        .context("unsupported Target HTTP frame")?;
                    ensure!(
                        !self.streaming || data.is_empty(),
                        "Target sent extra HTTP stream data before trailers"
                    );
                    self.seen_target_bytes = self.seen_target_bytes.saturating_add(data.len());
                    ensure!(
                        self.seen_target_bytes <= self.limit,
                        "Target primary HTTP body exceeds the response budget"
                    );
                    self.actual_body.extend_from_slice(&data);
                }
            }
        };
        ensure!(
            snapshot_headers(&actual) == expected,
            "Target primary HTTP trailers differ"
        );
        Ok(())
    }

    pub(super) async fn end(&mut self) -> Result<()> {
        while self.data().await? {
            ensure!(
                !self.streaming || self.actual_body.is_empty(),
                "Target sent extra primary stream data"
            );
        }
        ensure!(
            !self.streaming || self.actual_body.is_empty(),
            "Target sent extra primary stream data"
        );
        Ok(())
    }

    pub(super) async fn expect_reset(&mut self) -> Result<()> {
        ensure!(
            self.actual_body.is_empty(),
            "Target sent extra body data before the recorded reset"
        );
        ensure!(
            matches!(self.incoming.frame().await, Some(Err(_))),
            "Target did not reset the primary response as recorded"
        );
        Ok(())
    }

    pub(super) fn verify_headers(&self, verification: Verification<'_>) -> Result<()> {
        self.assert(verification, true)
    }

    pub(super) fn verify(mut self, verification: Verification<'_>) -> Result<()> {
        if !self.streaming {
            let source_headers: Headers = serde_json::from_value(self.expected["headers"].clone())?;
            self.source_body = decoded_body(&self.source_body, &source_headers, self.limit)?;
            self.actual_body = BytesMut::from(
                decoded_body(&self.actual_body, &self.target_headers, self.limit)?.as_slice(),
            );
        }
        self.expected["body"] = capture_body(&self.source_body);
        self.assert(verification, false)
    }

    fn assert(&self, verification: Verification<'_>, headers_only: bool) -> Result<()> {
        let Verification {
            id,
            request,
            request_headers,
            request_sent_at,
            source,
            policy,
            assertions,
        } = verification;
        let body = if headers_only {
            &[]
        } else {
            &self.actual_body[..]
        };
        let target = json!({
            "version": 1, "status": self.target_status, "headers": self.target_headers,
            "body": capture_body(body), "request_headers": request_headers,
            "request_sent_at": request_sent_at, "response_completed_at": self.target_headers_at,
        });
        let options = ResponseAssertionOptions {
            case_id: id.to_string(),
            request: source.to_owned(),
            expected_response: source.to_owned(),
            actual_response: source.to_owned(),
            policy: policy.to_owned(),
        };
        let (request, source, target) = (
            serde_json::to_vec(request)?,
            serde_json::to_vec(&self.expected)?,
            serde_json::to_vec(&target)?,
        );
        let proof = if headers_only {
            assertions.assert_recorded_response_headers(options, &request, &source, &target)?
        } else {
            assertions.assert_recorded_response(
                options,
                &request,
                &source,
                &target,
                &Default::default(),
            )?
        };
        let differences = proof.differences.len();
        ensure!(
            proof.passed,
            "Target primary HTTP response differs ({differences} differences)"
        );
        Ok(())
    }
}

pub(super) struct Verification<'a> {
    pub(super) id: Uuid,
    pub(super) request: &'a Value,
    pub(super) request_headers: &'a Headers,
    pub(super) request_sent_at: DateTime<Utc>,
    pub(super) source: &'a Path,
    pub(super) policy: &'a Path,
    pub(super) assertions: &'a ResponseAssertionRuntime,
}

fn decoded_body(bytes: &[u8], headers: &Headers, limit: usize) -> Result<Vec<u8>> {
    let Some(encoding) = headers.get(header::CONTENT_ENCODING.as_str()) else {
        return Ok(bytes.to_vec());
    };
    let body = traffic_engine_verification::http::content_encoding::decode(
        bytes,
        &encoding.join(","),
        limit,
    )?;
    ensure!(
        !body.truncated,
        "decoded primary HTTP body exceeds the response budget"
    );
    Ok(body.body)
}

fn capture_body(bytes: &[u8]) -> Value {
    json!({"encoding": "base64", "data": STANDARD.encode(bytes), "truncated": false})
}

pub(super) fn snapshot_headers(headers: &HeaderMap) -> Headers {
    let mut result = Headers::new();
    for (name, value) in headers {
        result.entry(name.as_str().into()).or_default().push(
            value
                .to_str()
                .map_or_else(|_| STANDARD.encode(value.as_bytes()), str::to_owned),
        );
    }
    result
}
