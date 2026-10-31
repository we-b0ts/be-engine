//! Deliver dependency streams with recorded timing or compressed successful gaps.

use super::*;
pub(super) mod full_delivery;
use crate::http::stream::ResponseStream;
use crate::http::termination::PrefixDelivery;
use http_body::{Body, Frame};
use http_body_util::combinators::BoxBody;
use std::{
    future::Future,
    pin::Pin,
    task::{Context as TaskContext, Poll},
};

pub(super) type DeliveryBody = BoxBody<Bytes, std::io::Error>;

pub(super) fn ordinary(response: Response<Full<Bytes>>) -> Response<DeliveryBody> {
    response.map(|body| body.map_err(|never: Infallible| match never {}).boxed())
}

pub(super) async fn response(
    mut record: RecordedHttpExchange,
    started: tokio::time::Instant,
    state: Arc<Mutex<ReplayState>>,
    client_prefix: Option<Arc<PrefixDelivery>>,
    server_close: Option<termination::ServerClose>,
    ordinary_delivery: full_delivery::Transport,
) -> Result<Response<DeliveryBody>> {
    let completion = DeliveryCompletion {
        state: state.clone(),
        detail: record.stream_delivery.take(),
    };
    let Some(stream) = &record.response_stream else {
        return Ok(full_delivery::response(
            response_from_record(record)?,
            completion,
            ordinary_delivery,
        ));
    };
    let payload = Bytes::from(decode_body(
        record
            .response_body
            .as_ref()
            .context("stream payload missing")?,
    )?);
    if record.lifecycle_stop.is_some() {
        stream.validate_prefix(payload.len())?;
    } else {
        stream.validate(payload.len())?;
    }
    let status = record
        .response_status
        .and_then(|s| StatusCode::from_u16(s).ok())
        .context("stream response status missing")?;
    let mut stream = stream.clone();
    if state.lock().await.http_stream_timing == crate::replay::ReplayHttpStreamTiming::Fast
        && stream.complete
        && status.is_success()
        && record.lifecycle_stop.is_none()
        && client_prefix.is_none()
        && server_close.is_none()
    {
        stream.headers_ms = 0;
        stream.end_ms = 0;
        for chunk in &mut stream.chunks {
            chunk.at_ms = 0;
        }
    }
    tokio::time::sleep_until(started + std::time::Duration::from_millis(stream.headers_ms)).await;
    let payload_len = payload.len();
    let mut body = TimedBody::new(payload, stream, started);
    body.completion = Some(completion);
    body.client_prefix = client_prefix;
    body.server_close = server_close;
    body.length_delimited = record.materialized_proxy_failure;
    if body.length_delimited {
        anyhow::ensure!(
            body.stream.trailers.is_none()
                && body
                    .stream
                    .chunks
                    .last()
                    .is_some_and(|chunk| chunk.at_ms == body.stream.end_ms),
            "HTTP length-delimited failure must end with its final recorded payload frame"
        );
    }
    if body.stream.chunks.is_empty()
        && let Some(delivered) = &body.client_prefix
    {
        delivered.queued();
    }
    let mut response = Response::new(body.boxed());
    *response.status_mut() = status;
    *response.headers_mut() =
        response_headers_for_payload(record.response_headers.as_ref(), 0, Utc::now());
    if record.materialized_proxy_failure {
        // The recording proxy's generated failure uses a Full body with its
        // exact length. Timed delivery must retain that ordinary framing.
        response.headers_mut().insert(
            CONTENT_LENGTH,
            hyper::header::HeaderValue::from(payload_len),
        );
    } else {
        response.headers_mut().remove(CONTENT_LENGTH);
    }
    Ok(response)
}

struct TimedBody {
    payload: Bytes,
    stream: ResponseStream,
    next: usize,
    started: tokio::time::Instant,
    timer: Pin<Box<tokio::time::Sleep>>,
    finished: bool,
    length_delimited: bool,
    completion: Option<DeliveryCompletion>,
    client_prefix: Option<Arc<PrefixDelivery>>,
    server_close: Option<termination::ServerClose>,
}

impl TimedBody {
    fn new(payload: Bytes, stream: ResponseStream, started: tokio::time::Instant) -> Self {
        let at_ms = stream
            .chunks
            .first()
            .map_or(stream.end_ms, |chunk| chunk.at_ms);
        Self {
            payload,
            stream,
            next: 0,
            started,
            timer: Box::pin(tokio::time::sleep_until(
                started + std::time::Duration::from_millis(at_ms),
            )),
            finished: false,
            length_delimited: false,
            completion: None,
            client_prefix: None,
            server_close: None,
        }
    }
}

impl Body for TimedBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        if this.next == this.stream.chunks.len()
            && let Some(prefix) = &this.client_prefix
        {
            if this.server_close.is_some() {
                if this.timer.as_mut().poll(cx).is_pending() {
                    return Poll::Pending;
                }
                this.server_close
                    .take()
                    .expect("server close")
                    .after_prefix(prefix.clone());
            }
            // No synthetic EOF: Target must independently produce its recorded
            // cancellation. The connection owner applies the bounded deadline.
            return Poll::Pending;
        }
        if this.finished {
            if let Some(completion) = &mut this.completion {
                completion.finish(Ok(()));
            }
            return Poll::Ready(None);
        }
        if this.timer.as_mut().poll(cx).is_pending() {
            return Poll::Pending;
        }
        if let Some(chunk) = this.stream.chunks.get(this.next) {
            let bytes = this.payload.slice(chunk.start..chunk.end);
            this.next += 1;
            if this.next == this.stream.chunks.len()
                && let Some(delivered) = &this.client_prefix
            {
                delivered.queued();
            }
            let next_ms = this
                .stream
                .chunks
                .get(this.next)
                .map_or(this.stream.end_ms, |chunk| chunk.at_ms);
            this.timer
                .as_mut()
                .reset(this.started + std::time::Duration::from_millis(next_ms));
            if this.length_delimited && this.next == this.stream.chunks.len() {
                // Hyper completes Content-Length framing after the last data
                // frame and can drop Body without asking for another EOF poll.
                this.finished = true;
                if let Some(completion) = &mut this.completion {
                    completion.finish(Ok(()));
                }
            }
            return Poll::Ready(Some(Ok(Frame::data(bytes))));
        }
        this.finished = true;
        if let Some(trailers) = this.stream.trailers.take() {
            let mut headers = hyper::HeaderMap::new();
            for (name, values) in trailers {
                let name = hyper::header::HeaderName::from_bytes(name.as_bytes())
                    .map_err(std::io::Error::other)?;
                for value in values {
                    headers.append(name.clone(), value.parse().map_err(std::io::Error::other)?);
                }
            }
            return Poll::Ready(Some(Ok(Frame::trailers(headers))));
        }
        if let Some(completion) = &mut this.completion {
            completion.finish(Ok(()));
        }
        Poll::Ready(None)
    }
}

struct DeliveryCompletion {
    state: Arc<Mutex<ReplayState>>,
    detail: Option<MatchedHttpExchangeReport>,
}

impl DeliveryCompletion {
    async fn apply(&mut self, result: Result<()>) {
        if let Some(detail) = self.detail.take() {
            self.state.lock().await.finish_http_response(detail, result);
        }
    }
    fn finish(&mut self, result: Result<()>) {
        let Some(detail) = self.detail.take() else {
            return;
        };
        let state = self.state.clone();
        tokio::spawn(async move {
            state.lock().await.finish_http_response(detail, result);
        });
    }
}

impl Drop for DeliveryCompletion {
    fn drop(&mut self) {
        self.finish(Err(anyhow!(
            "Target HTTP dependency body was dropped before complete delivery"
        )));
    }
}

#[cfg(test)]
mod tests;
