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
    mut started: tokio::time::Instant,
    state: Arc<Mutex<ReplayState>>,
    client_prefix: Option<Arc<PrefixDelivery>>,
    server_close: Option<termination::ServerClose>,
    ordinary_delivery: full_delivery::Transport,
) -> Result<Response<DeliveryBody>> {
    let mut completion = DeliveryCompletion {
        state: state.clone(),
        detail: record.stream_delivery.take(),
        cancellation: None,
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
    let mut input_timing = super::input_timing::bind(
        &state,
        completion.detail.as_ref(),
        ordinary_delivery.progress.clone(),
    )
    .await?;
    if let (Some(bound), Some(observation)) = (&input_timing, ordinary_delivery.observation) {
        completion.cancellation = Some(super::cancelled::Observation::new(
            bound.timeline.clone(),
            observation,
            stream.chunks.len(),
            bound.schedule.prefix_chunks,
        ));
    }
    let (timing, interval_cap_ms) = {
        let replay = state.lock().await;
        (
            replay.stream_timing.unwrap_or_default(),
            replay.stream_interval_cap_ms,
        )
    };
    if let Some(bound) = &mut input_timing {
        anyhow::ensure!(
            stream.chunks.len() == bound.schedule.chunks_ms.len(),
            "HTTP input stream framing changed"
        );
        started = bound.started;
        stream.headers_ms = bound.schedule.headers_ms;
        for (chunk, at) in stream.chunks.iter_mut().zip(&bound.schedule.chunks_ms) {
            chunk.at_ms = *at;
        }
        stream.end_ms = bound.schedule.end_ms;
        if bound.schedule.headers_after_close {
            bound.wait_release().await?;
        }
    } else if timing == crate::replay::ReplayStreamTiming::Fast
        && record.outcome.is_server_terminated()
    {
        cap_stream_intervals(&mut stream, 0);
    } else if timing == crate::replay::ReplayStreamTiming::Fast
        && stream.complete
        && record.lifecycle_stop.is_none()
        && client_prefix.is_none()
        && server_close.is_none()
    {
        cap_stream_intervals(&mut stream, interval_cap_ms);
    }
    tokio::time::sleep_until(started + std::time::Duration::from_millis(stream.headers_ms)).await;
    if let Some(bound) = &input_timing
        && bound.schedule.prefix_chunks == 0
        && bound.schedule.prefix_required
    {
        bound.prefix.queued();
    }
    let payload_len = payload.len();
    let mut body = TimedBody::new(payload, stream, started);
    body.completion = Some(completion);
    body.client_prefix = client_prefix;
    body.server_close = server_close;
    body.length_delimited = record.materialized_proxy_failure;
    body.input_timing = input_timing;
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

fn cap_stream_intervals(stream: &mut ResponseStream, interval_cap_ms: u64) {
    let mut previous_source_ms = stream.headers_ms;
    let mut delivered_ms = stream.headers_ms.min(interval_cap_ms);
    stream.headers_ms = delivered_ms;
    for chunk in &mut stream.chunks {
        delivered_ms += (chunk.at_ms - previous_source_ms).min(interval_cap_ms);
        previous_source_ms = chunk.at_ms;
        chunk.at_ms = delivered_ms;
    }
    stream.end_ms = delivered_ms + (stream.end_ms - previous_source_ms).min(interval_cap_ms);
}

struct TimedBody {
    payload: Bytes,
    stream: ResponseStream,
    next: usize,
    started: tokio::time::Instant,
    timer: Pin<Box<tokio::time::Sleep>>,
    finished: bool,
    length_delimited: bool,
    input_timing: Option<crate::replay::control::http_input_timing::BoundStream>,
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
            input_timing: None,
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
        if let Some(bound) = &mut this.input_timing {
            let after_close = this.next >= bound.schedule.prefix_chunks
                && (this.next < this.stream.chunks.len() || bound.schedule.end_after_close);
            if after_close {
                match bound.poll_release(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => {
                        return Poll::Ready(Some(Err(std::io::Error::other(error))));
                    }
                    Poll::Ready(Ok(())) => {}
                }
            }
        }
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
            if let Some(cancellation) = this
                .completion
                .as_mut()
                .and_then(|c| c.cancellation.as_mut())
            {
                cancellation.queued_chunks = this.next;
            }
            if let Some(bound) = &this.input_timing
                && this.next == bound.schedule.prefix_chunks
                && bound.schedule.prefix_required
            {
                bound.prefix.queued();
            }
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
    cancellation: Option<super::cancelled::Observation>,
}

impl DeliveryCompletion {
    async fn apply(&mut self, result: Result<()>) {
        if let Some(detail) = self.detail.take() {
            Self::commit(self.state.clone(), detail, result).await;
        }
    }
    async fn commit(
        state: Arc<Mutex<ReplayState>>,
        detail: MatchedHttpExchangeReport,
        mut result: Result<()>,
    ) {
        let claim = state
            .lock()
            .await
            .http_sequence_claims
            .get(&detail.index)
            .cloned();
        if result.is_ok()
            && let Some(claim) = claim
        {
            result = claim
                .wait_complete(tokio::time::Instant::now() + std::time::Duration::from_secs(30))
                .await;
        }
        state.lock().await.finish_http_response(detail, result);
    }
    fn finish(&mut self, result: Result<()>) {
        let Some(detail) = self.detail.take() else {
            return;
        };
        let state = self.state.clone();
        tokio::spawn(async move {
            Self::commit(state, detail, result).await;
        });
    }
}

impl Drop for DeliveryCompletion {
    fn drop(&mut self) {
        if let (Some(cancellation), Some(detail)) = (self.cancellation.take(), self.detail.as_ref())
        {
            let detail = detail.clone();
            self.detail = None;
            super::cancelled::finish(self.state.clone(), detail, cancellation);
            return;
        }
        self.finish(Err(anyhow!(
            "Target HTTP dependency body was dropped before complete delivery"
        )));
    }
}

#[cfg(test)]
mod tests;
