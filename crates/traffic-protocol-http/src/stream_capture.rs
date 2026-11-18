//! Bounded, incremental HTTP dependency capture with body-lifetime ownership.

use crate::body_capture::redact_headers;
use crate::forward::{HostHeaderPolicy, append_end_to_end_headers};
use bytes::Bytes;
use chrono::Utc;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::{HeaderMap, Response, StatusCode, body::Incoming};
type ProxyBody = BoxBody<Bytes, std::io::Error>;
use crate::stream::{ResponseChunk, ResponseStream};
use crate::termination::PrefixDelivery;
use http_body::{Body, Frame};
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
};

pub trait StreamHost: Send + Sync {
    fn activity(&self);
    fn source_stop_requested(&self) -> bool;
    fn output(&self, output: traffic_model::trace::OutputKind);
    fn finish(&self, event: crate::events::HttpExchangeEvent);
    fn invalidate(
        &self,
        reason: &str,
        elapsed_ms: u128,
        native: serde_json::Value,
        recover_after_drain: bool,
    );
}

pub struct CaptureContext {
    pub host: Arc<dyn StreamHost>,
    pub event: crate::events::HttpExchangeEvent,
    pub started: std::time::Instant,
    pub termination: crate::termination::ClientTermination,
    pub max_body_bytes: usize,
    pub redact_headers: Vec<String>,
    pub drain_timeout: std::time::Duration,
    pub requires_complete_body_rewrite: bool,
}
impl CaptureContext {
    fn accepts_server(&self, observed: traffic_protocol::transport::ObservedTermination) -> bool {
        !self.termination.engine_stopped()
            && self
                .termination
                .cancelled_at()
                .is_none_or(|client| client > observed.at)
    }
}

pub fn is_stream(headers: &HeaderMap) -> bool {
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

pub fn response(upstream: Response<Incoming>, mut context: CaptureContext) -> Response<ProxyBody> {
    let upstream_termination = upstream
        .extensions()
        .get::<crate::client::UpstreamTermination>()
        .cloned();
    let (mut parts, body) = upstream.into_parts();
    context.event.response_status = Some(parts.status.as_u16());
    context.event.response_headers = Some(redact_headers(&parts.headers, &context.redact_headers));
    let requires_rewrite = context.requires_complete_body_rewrite;
    let mut capture = Capture::new(context);
    capture.upstream = upstream_termination;
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
    Response::from_parts(
        parts,
        CaptureBody {
            body,
            capture,
            ending: None,
        }
        .boxed(),
    )
}

pub struct Capture {
    context: CaptureContext,
    payload: Vec<u8>,
    received: usize,
    stream: ResponseStream,
    error: Option<String>,
    finished: bool,
    upstream: Option<crate::client::UpstreamTermination>,
    prefix: Arc<PrefixDelivery>,
}

impl Capture {
    pub fn new(context: CaptureContext) -> Self {
        let prefix = Arc::new(PrefixDelivery::new(context.termination.delivery()));
        prefix.queued();
        let headers_ms = context.started.elapsed().as_millis().min(u64::MAX as u128) as u64;
        Self {
            context,
            payload: Vec::new(),
            received: 0,
            stream: ResponseStream {
                version: 2,
                headers_ms,
                chunks: Vec::new(),
                end_ms: headers_ms,
                complete: false,
                trailers: None,
            },
            error: None,
            finished: false,
            upstream: None,
            prefix,
        }
    }

    pub fn bytes(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        self.context.host.activity();
        self.received = self.received.saturating_add(bytes.len());
        let limit = self.context.max_body_bytes;
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
        self.prefix.queued();
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
        let native = serde_json::json!({
            "version":1,"exchange_id":self.context.event.id,
            "client":self.context.termination.diagnosis(self.context.started),
            "server":crate::termination::observed_since(self.upstream.as_ref().and_then(|upstream| upstream.observed_since(self.context.started)), self.context.started),
            "body_complete":self.stream.complete,"prefix_flushed":self.prefix.is_complete(),
            "received_bytes":self.received,"captured_bytes":self.payload.len(),"chunks":self.stream.chunks.len()
        });
        let client = &self.context.termination;
        let transport_ended = client
            .cancelled()
            .is_some_and(|end| end.at >= self.context.started)
            || client.has_transport_failure_since(self.context.started);
        self.context.host.invalidate(
            error,
            self.context.started.elapsed().as_millis(),
            native,
            !client.engine_stopped() && transport_ended,
        );
    }

    fn server_end(&self) -> Option<traffic_protocol::transport::ObservedTermination> {
        self.upstream
            .as_ref()?
            .observed_since(self.context.started)
            .filter(|observed| self.context.accepts_server(*observed))
    }

    pub fn finish(&mut self, eof: bool, error: Option<String>) {
        if self.finished {
            return;
        }
        self.finished = true;
        // Closing a connection-delimited response during engine cleanup can
        // look like ordinary body EOF to Hyper. It cannot certify completion.
        let engine_stopped = self.context.termination.engine_stopped();
        let capture_error = self.error.take();
        // Body drop alone is not proof of cancellation. Only the independently
        // observed downstream termination can complete a cancelled capture.
        let client = (!eof)
            .then(|| self.context.termination.cancelled())
            .flatten();
        let server = (!eof && capture_error.is_none())
            .then(|| self.server_end())
            .flatten()
            .filter(|observed| self.context.accepts_server(*observed));
        let terminated = server.or(client);
        let source_stop = engine_stopped
            && capture_error.is_none()
            && self.prefix.is_complete()
            && self.context.host.source_stop_requested();
        self.error = capture_error.or_else(|| {
            engine_stopped.then(|| {
                "HTTP dependency response ended during engine cleanup before capture completed".into()
            })
        }).or(error);
        if server.is_none()
            && client.is_some()
            && !self.prefix.is_complete()
            && self.error.is_none()
        {
            self.error =
                Some("HTTP response prefix was not flushed before client cancellation".into());
        }
        if let Some(observed) = server {
            match self.prefix.is_complete().then(|| {
                self.context
                    .termination
                    .propagate_server(observed.termination)
            }) {
                None => {
                    self.error = Some(
                        "HTTP response prefix was not flushed before server termination".into(),
                    )
                }
                Some(Ok(())) => self.error = None,
                Some(Err(error)) => {
                    self.error = Some(format!(
                        "failed to forward HTTP server termination: {error}"
                    ))
                }
            }
        }
        let duration = terminated.map_or_else(
            || self.context.started.elapsed(),
            |observed| observed.at.saturating_duration_since(self.context.started),
        );
        self.stream.complete =
            !engine_stopped && (eof || terminated.is_some()) && self.error.is_none();
        self.stream.end_ms = duration.as_millis().min(u64::MAX as u128) as u64;
        let mut event = self.context.event.clone();
        event.timestamp = Utc::now();
        event.duration_ms = duration.as_millis();
        if let Some(observed) = terminated {
            event.timestamp = traffic_protocol::transport::observed_wall_time(observed.at);
            event.outcome =
                traffic_model::DependencyExchangeOutcome::Terminated(observed.termination);
            if self.error.is_none() {
                self.context
                    .host
                    .output(traffic_model::trace::OutputKind::Terminated {
                        termination: observed.termination,
                    });
            }
        } else if source_stop {
            self.context
                .host
                .output(traffic_model::trace::OutputKind::TargetStop);
        }
        event.response_body = Some(traffic_model::capture::capture_body_with_original_len(
            &self.payload,
            self.received,
        ));
        event.response_stream = Some(self.stream.clone());
        event.error = self.error.clone();
        if !self.stream.complete && !source_stop {
            let reason = event.error.as_deref().unwrap_or(
                "HTTP dependency stream ended without EOF or observed client termination",
            );
            self.invalidate(reason);
        }
        self.context.host.finish(event);
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let error = if self.context.termination.cancelled_at().is_some() {
            None
        } else {
            Some("HTTP dependency response body was dropped before EOF without observed client termination".into())
        };
        self.finish(false, error);
    }
}

pub struct CaptureBody {
    body: Incoming,
    capture: Capture,
    ending: Option<PendingServerEnd>,
}

impl CaptureBody {
    pub fn new(body: Incoming, capture: Capture) -> Self {
        Self {
            body,
            capture,
            ending: None,
        }
    }
    pub fn prefix_is_complete(&self) -> bool {
        self.capture.prefix.is_complete()
    }
    pub fn finish(&mut self, eof: bool, error: Option<String>) {
        self.capture.finish(eof, error);
    }
}

struct PendingServerEnd {
    flush: Pin<Box<dyn Future<Output = std::io::Result<()>> + Send + Sync>>,
    error: Option<std::io::Error>,
}

impl Body for CaptureBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        if let Some(ending) = &mut this.ending {
            match ending.flush.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => {
                    let error = ending.error.take().expect("pending upstream termination");
                    this.ending = None;
                    if let Err(flush_error) = result {
                        this.capture.error = Some(flush_error.to_string());
                    }
                    this.capture.finish(false, Some(error.to_string()));
                    return Poll::Ready(Some(Err(error)));
                }
            }
        }
        match Pin::new(&mut this.body).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(bytes) = frame.data_ref() {
                    this.capture.bytes(bytes);
                }
                if let Some(trailers) = frame.trailers_ref() {
                    this.capture.stream.trailers = Some(redact_headers(
                        trailers,
                        &this.capture.context.redact_headers,
                    ));
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(None) => {
                this.capture.finish(true, None);
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(error))) => {
                if this.capture.error.is_none() && this.capture.server_end().is_some() {
                    let prefix = this.capture.prefix.clone();
                    let budget = this.capture.context.drain_timeout;
                    this.ending = Some(PendingServerEnd {
                        flush: Box::pin(async move {
                            tokio::time::timeout(budget, prefix.wait()).await.map_err(|_| std::io::Error::other("HTTP response prefix flush exceeded dependency cleanup budget"))
                        }),
                        error: Some(std::io::Error::other(error)),
                    });
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
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
