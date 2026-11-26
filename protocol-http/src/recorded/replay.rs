//! Native stored-response completeness, cancellation and proxy-failure semantics.
use super::{BodyCapture, RecordedExchange, decode_body};
use crate::headers::HeaderSnapshot;
use anyhow::{Context, Result, anyhow};
use hyper::StatusCode;
use serde_json::Value;

const ENGINE_CLEANUP: &str =
    "HTTP dependency response ended during engine cleanup before capture completed";

impl RecordedExchange {
    pub fn validate_termination(&self, response_deferred: bool) -> Result<()> {
        if self.outcome == traffic_model::DependencyExchangeOutcome::NoResponse {
            return Err(anyhow!(
                "HTTP does not support a protocol-level no_response outcome"
            ));
        }
        if !self.outcome.is_client_terminated() && !self.outcome.is_server_terminated() {
            anyhow::ensure!(
                self.outcome.termination().is_none(),
                "HTTP engine-owned termination is not replayable peer evidence"
            );
            return Ok(());
        }
        if let Some(end) = self.outcome.termination() {
            use traffic_model::{TerminationKind, TerminationScope};
            anyhow::ensure!(
                matches!(
                    (end.kind, end.scope),
                    (TerminationKind::Eof, TerminationScope::WriteHalf)
                        | (TerminationKind::Reset, TerminationScope::Connection)
                ),
                "HTTP/1 replay requires an observed write-half EOF or connection reset; stream-local cancellation is unsupported"
            );
        }
        anyhow::ensure!(
            self.error.is_none(),
            "HTTP client termination contains an upstream/capture error"
        );
        if let Some(stream) = &self.response_stream {
            anyhow::ensure!(
                stream.version == 2 && self.outcome.termination().is_some(),
                "HTTP cancelled response prefixes require version-2 termination evidence; re-record this case"
            );
            anyhow::ensure!(
                self.response_status.is_some() && self.response_headers.is_some(),
                "HTTP cancelled response prefix has no response headers"
            );
            anyhow::ensure!(
                stream.trailers.is_none(),
                "HTTP cancelled response prefix cannot contain terminal trailers"
            );
            let body = self
                .response_body
                .as_ref()
                .context("HTTP cancelled response prefix has no payload")?;
            let payload_len = if response_deferred {
                body.stored_len
                    .context("deferred HTTP cancelled stream has no payload length")?
            } else {
                decode_body(body)?.len()
            };
            stream.validate(payload_len)?;
            anyhow::ensure!(
                self.duration_ms.as_ref().and_then(Value::as_u64) == Some(stream.end_ms),
                "HTTP cancelled stream duration and termination time disagree"
            );
        } else {
            anyhow::ensure!(
                self.response_status.is_none() && self.response_headers.is_none(),
                "HTTP client termination contains response headers"
            );
            anyhow::ensure!(
                self.response_body
                    .as_ref()
                    .map(decode_body)
                    .transpose()?
                    .is_none_or(|body| body.is_empty()),
                "HTTP client termination contains response bytes"
            );
        }
        anyhow::ensure!(
            self.duration_ms.as_ref().and_then(Value::as_u64).is_some(),
            "HTTP client termination requires an integer duration_ms"
        );
        Ok(())
    }
    pub fn validate_cleanup(&self, response_deferred: bool) -> Result<()> {
        anyhow::ensure!(
            !self.request_body.truncated,
            "async HTTP cleanup request was truncated"
        );
        anyhow::ensure!(
            self.duration_ms
                .as_ref()
                .and_then(Value::as_u64)
                .is_some_and(|value| value <= 86_400_000),
            "async HTTP cleanup needs bounded request timing"
        );
        anyhow::ensure!(
            self.outcome != traffic_model::DependencyExchangeOutcome::NoResponse,
            "HTTP cleanup cannot claim a protocol no-response command"
        );
        anyhow::ensure!(
            self.outcome
                .termination()
                .is_none_or(|end| end.side != traffic_model::TerminationSide::Engine),
            "async cleanup preserves Source evidence instead of inventing engine peer outcomes"
        );
        if let Some(stream) = &self.response_stream {
            anyhow::ensure!(
                stream.version == 2,
                "async HTTP cleanup prefix requires flushed-prefix evidence version 2"
            );
            anyhow::ensure!(
                self.response_status.is_some() && self.response_headers.is_some(),
                "async HTTP cleanup prefix has no headers"
            );
            anyhow::ensure!(
                stream.trailers.is_none(),
                "async HTTP cleanup cannot contain response EOF trailers"
            );
            anyhow::ensure!(
                self.error
                    .as_deref()
                    .is_none_or(|error| error == ENGINE_CLEANUP),
                "async HTTP cleanup prefix contains an independent capture error"
            );
            let body = self
                .response_body
                .as_ref()
                .context("async HTTP cleanup prefix has no payload")?;
            anyhow::ensure!(!body.truncated, "async HTTP cleanup prefix was truncated");
            let payload_len = if response_deferred {
                body.stored_len
                    .context("deferred HTTP cleanup prefix has no length")?
            } else {
                decode_body(body)?.len()
            };
            stream.validate_prefix(payload_len)?;
            anyhow::ensure!(
                self.duration_ms.as_ref().and_then(Value::as_u64) == Some(stream.end_ms),
                "async HTTP cleanup duration disagrees with its captured prefix"
            );
        } else {
            anyhow::ensure!(
                self.response_status.is_none() && self.response_headers.is_none(),
                "async HTTP cleanup without stream evidence cannot claim response headers"
            );
            anyhow::ensure!(
                self.response_body
                    .as_ref()
                    .map(decode_body)
                    .transpose()?
                    .is_none_or(|bytes| bytes.is_empty()),
                "async HTTP cleanup has untracked response bytes"
            );
            anyhow::ensure!(
                self.outcome.termination().is_some() || self.is_proxy_failure(),
                "async HTTP cleanup has no incomplete transport evidence"
            );
        }
        Ok(())
    }
    pub fn is_proxy_failure(&self) -> bool {
        self.outcome == traffic_model::DependencyExchangeOutcome::Response
            && self
                .error
                .as_ref()
                .is_some_and(|error| !error.is_empty() && error.len() <= 65_536)
            && self.response_status.is_none()
            && self.response_headers.is_none()
            && self.response_body.is_none()
            && self.response_stream.is_none()
            && self
                .duration_ms
                .as_ref()
                .and_then(Value::as_u64)
                .is_some_and(|duration| duration <= 86_400_000)
    }

    pub fn materialize_proxy_failure(&mut self) {
        debug_assert!(
            self.is_proxy_failure(),
            "only validated recording-proxy failures can be materialized"
        );
        let error = self
            .error
            .as_ref()
            .expect("validated HTTP upstream failure");
        // proxy::http::record_http_error returns these bytes to Source. They are a
        // dependency delivery, never an independently generated Target request.
        self.response_status = Some(StatusCode::BAD_GATEWAY.as_u16());
        self.response_headers = Some(HeaderSnapshot::new());
        self.response_body = Some(BodyCapture {
            encoding: "utf8".into(),
            data: error.clone(),
            truncated: false,
            stored_len: Some(error.len()),
        });
        let at_ms = self
            .duration_ms
            .as_ref()
            .and_then(Value::as_u64)
            .expect("validated duration");
        self.response_stream = Some(crate::stream::ResponseStream {
            version: 2,
            headers_ms: at_ms,
            chunks: vec![crate::stream::ResponseChunk {
                at_ms,
                start: 0,
                end: error.len(),
            }],
            end_ms: at_ms,
            complete: true,
            stopped_at_source_exit: false,
            trailers: None,
        });
    }
    pub fn validate_payloads(
        &self,
        cleanup_authorized: bool,
        response_deferred: bool,
    ) -> Result<()> {
        let stream_mime = self
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
            self.response_stream.is_some()
                || !matches!(
                    stream_mime.as_deref(),
                    Some("text/event-stream" | "application/x-ndjson" | "application/ndjson")
                ),
            "recorded HTTP streaming dependency has no chunk timing evidence; re-record this case"
        );
        if let Some(stream) = &self.response_stream {
            let body = self
                .response_body
                .as_ref()
                .context("HTTP stream has no recorded payload")?;
            // Global indexes retain byte-length metadata while deferring payload
            // bytes. Validate their shape without loading every Global response;
            // materialization and delivery validate the actual payload on demand.
            let payload_len = if response_deferred {
                body.stored_len.context(
                    "deferred HTTP stream has no stored payload length; re-record this case",
                )?
            } else {
                decode_body(body)?.len()
            };
            if cleanup_authorized {
                stream.validate_prefix(payload_len)?;
            } else {
                stream.validate(payload_len)?;
                anyhow::ensure!(self.error.is_none(), "HTTP stream contains a capture error");
            }
        }
        if self.request_body.truncated {
            return Err(anyhow!(
                "http_exchange {} {} has a truncated request body",
                self.method,
                self.uri
            ));
        }
        if self
            .response_body
            .as_ref()
            .is_some_and(|body| body.truncated)
        {
            return Err(anyhow!(
                "http_exchange {} {} has a truncated response body",
                self.method,
                self.uri
            ));
        }
        Ok(())
    }
}
