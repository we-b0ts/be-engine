//! Bounded, incremental HTTP dependency capture with body-lifetime ownership.

use crate::http::forward::{HostHeaderPolicy, append_end_to_end_headers};
use crate::http::{
    rewrite::{self, RewriteInput},
    termination::ClientTermination,
};
use crate::recorder::{HttpExchangeEvent, RecorderEvent, redact_headers};
use crate::{AppState, active_case::DependencyTargets};
use bytes::Bytes;
use chrono::Utc;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::{HeaderMap, Method, Response, StatusCode, Uri, body::Incoming};
use std::time::Instant;
type ProxyBody = BoxBody<Bytes, std::io::Error>;
use crate::http::stream::{ResponseChunk, ResponseStream};
use crate::recorder::CaseInvalidation;
use http_body::{Body, Frame};
use std::{
    pin::Pin,
    task::{Context as TaskContext, Poll},
};

pub(crate) struct CaptureContext {
    pub state: AppState,
    pub targets: DependencyTargets,
    pub event: HttpExchangeEvent,
    pub started: Instant,
    pub termination: ClientTermination,
}

pub(crate) fn is_stream(headers: &HeaderMap) -> bool {
    headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|value| {
            matches!(
                value
                    .split(';')
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .to_ascii_lowercase()
                    .as_str(),
                "text/event-stream"
                    | "application/x-ndjson"
                    | "application/ndjson"
                    | "application/octet-stream"
            )
        })
}

pub(crate) fn response(
    upstream: Response<Incoming>,
    mut context: CaptureContext,
) -> Response<ProxyBody> {
    let (mut parts, body) = upstream.into_parts();
    context.event.response_status = Some(parts.status.as_u16());
    context.event.response_headers = Some(redact_headers(
        &parts.headers,
        &context.state.config().recording.redact_headers,
    ));
    let method = Method::from_bytes(context.event.method.as_bytes()).expect("captured method");
    let uri = context.event.uri.parse::<Uri>().expect("captured URI");
    let input = RewriteInput {
        method: &method,
        uri: &uri,
        authority: context.event.authority.as_deref(),
        status: parts.status,
        headers: &parts.headers,
        body: &[],
    };
    let rewrite = &context.state.config().http_response_rewrite;
    let requires_rewrite = rewrite.is_enabled()
        && rewrite
            .rules
            .iter()
            .any(|rule| rewrite::matches(rule, &input));
    let mut capture = Capture::new(context);
    if requires_rewrite {
        capture.finish(false, Some("HTTP response rewrite requires a complete body and cannot be applied to a dependency stream".into()));
        return simple_response(
            StatusCode::BAD_GATEWAY,
            "streaming dependency response requires an incompatible complete-body rewrite",
        );
    }
    let mut headers = HeaderMap::new();
    append_end_to_end_headers(&parts.headers, &mut headers, HostHeaderPolicy::Preserve);
    // EOF is part of this stream's evidence, even when the upstream knew length.
    headers.remove(hyper::header::CONTENT_LENGTH);
    parts.headers = headers;
    Response::from_parts(parts, CaptureBody { body, capture }.boxed())
}

struct Capture {
    context: CaptureContext,
    payload: Vec<u8>,
    received: usize,
    stream: ResponseStream,
    error: Option<String>,
    finished: bool,
}

impl Capture {
    fn new(context: CaptureContext) -> Self {
        let headers_ms = context.started.elapsed().as_millis().min(u64::MAX as u128) as u64;
        Self {
            context,
            payload: Vec::new(),
            received: 0,
            stream: ResponseStream {
                version: 1,
                headers_ms,
                chunks: Vec::new(),
                end_ms: headers_ms,
                complete: false,
                trailers: None,
            },
            error: None,
            finished: false,
        }
    }

    fn bytes(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        self.received = self.received.saturating_add(bytes.len());
        let limit = self.context.state.config().recording.max_body_bytes;
        if self.error.is_some() {
            return;
        }
        if self.received > limit || self.stream.chunks.len() >= 10_000 {
            self.error =
                Some("HTTP dependency stream exceeded its byte or chunk capture limit".into());
            self.invalidate(self.error.as_deref().unwrap());
            return;
        }
        let start = self.payload.len();
        self.payload.extend_from_slice(bytes);
        self.stream.chunks.push(ResponseChunk {
            at_ms: self
                .context
                .started
                .elapsed()
                .as_millis()
                .min(u64::MAX as u128) as u64,
            start,
            end: self.payload.len(),
        });
    }

    fn invalidate(&self, error: &str) {
        for (case, _) in &self.context.targets.cases {
            self.context.state.invalidate_active_case(
                case.id,
                CaseInvalidation::new("http_stream_capture_incomplete", error),
            );
        }
    }

    fn finish(&mut self, eof: bool, error: Option<String>) {
        if self.finished {
            return;
        }
        self.finished = true;
        self.error = self.error.take().or(error);
        self.stream.complete = eof && self.error.is_none();
        self.stream.end_ms = self
            .context
            .started
            .elapsed()
            .as_millis()
            .min(u64::MAX as u128) as u64;
        let mut event = self.context.event.clone();
        event.timestamp = Utc::now();
        event.duration_ms = self.context.started.elapsed().as_millis();
        event.response_body = Some(crate::recorder::capture_body_with_original_len(
            &self.payload,
            self.received,
        ));
        event.response_stream = Some(self.stream.clone());
        event.error = self.error.clone();
        if !self.stream.complete {
            let reason = event
                .error
                .as_deref()
                .unwrap_or("HTTP dependency stream ended without complete EOF evidence");
            self.invalidate(reason);
        }
        self.context.state.record_event_for_targets(
            RecorderEvent::HttpExchange(event),
            self.context.targets.clone(),
        );
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let error = if self.context.termination.observed_at().is_some() {
            "HTTP dependency client terminated after response headers; partial stream replay is unsupported"
        } else {
            "HTTP dependency response body was dropped before EOF"
        };
        self.finish(false, Some(error.into()));
    }
}

struct CaptureBody {
    body: Incoming,
    capture: Capture,
}

impl Body for CaptureBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        match Pin::new(&mut this.body).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(bytes) = frame.data_ref() {
                    this.capture.bytes(bytes);
                }
                if let Some(trailers) = frame.trailers_ref() {
                    this.capture.stream.trailers = Some(redact_headers(
                        trailers,
                        &this.capture.context.state.config().recording.redact_headers,
                    ));
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(None) => {
                this.capture.finish(true, None);
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(error))) => {
                this.capture.finish(
                    false,
                    Some(format!("HTTP dependency stream read failed: {error}")),
                );
                Poll::Ready(Some(Err(std::io::Error::other(error))))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

fn simple_response(status: StatusCode, body: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .body(
            Full::new(Bytes::copy_from_slice(body.as_bytes()))
                .map_err(|never: std::convert::Infallible| match never {})
                .boxed(),
        )
        .expect("static response")
}
