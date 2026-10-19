//! Preserve recorded header, chunk and EOF delays for dependency streams.

use super::*;
use crate::http::stream::ResponseStream;
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
) -> Result<Response<DeliveryBody>> {
    let completion = DeliveryCompletion {
        state,
        detail: record.stream_delivery.take(),
    };
    let Some(stream) = &record.response_stream else {
        return Ok(ordinary(response_from_record(record)?));
    };
    let payload = Bytes::from(decode_body(
        record
            .response_body
            .as_ref()
            .context("stream payload missing")?,
    )?);
    stream.validate(payload.len())?;
    let status = record
        .response_status
        .and_then(|s| StatusCode::from_u16(s).ok())
        .context("stream response status missing")?;
    tokio::time::sleep_until(started + std::time::Duration::from_millis(stream.headers_ms)).await;
    let mut body = TimedBody::new(payload, stream.clone(), started);
    body.completion = Some(completion);
    let mut response = Response::new(body.boxed());
    *response.status_mut() = status;
    *response.headers_mut() =
        response_headers_for_payload(record.response_headers.as_ref(), 0, Utc::now());
    response.headers_mut().remove(CONTENT_LENGTH);
    Ok(response)
}

struct TimedBody {
    payload: Bytes,
    stream: ResponseStream,
    next: usize,
    started: tokio::time::Instant,
    timer: Pin<Box<tokio::time::Sleep>>,
    finished: bool,
    completion: Option<DeliveryCompletion>,
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
            completion: None,
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
            let next_ms = this
                .stream
                .chunks
                .get(this.next)
                .map_or(this.stream.end_ms, |chunk| chunk.at_ms);
            this.timer
                .as_mut()
                .reset(this.started + std::time::Duration::from_millis(next_ms));
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
            "Target HTTP dependency stream was dropped before its recorded EOF"
        )));
    }
}

#[cfg(test)]
mod tests;
