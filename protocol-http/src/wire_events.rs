//! Framework response boundaries are committed by the actual HTTP writer's flush.
use super::termination::{ClientTermination, DeliveryProgress, FlushReceipt};
use crate::stream_capture::RecordedStream;
use std::sync::Arc;

pub trait CaptureWire: Send + Sync {
    fn wire_terminal(&self) -> bool;
    fn reserve(&self, kind: OutputKind) -> FlushReceipt;
    fn failed(&self, termination: Option<traffic_model::DependencyTermination>);
}
use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use http_body_util::{BodyExt, combinators::BoxBody};
use hyper::Response;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use traffic_model::trace::OutputKind;

type WireBody = BoxBody<Bytes, std::io::Error>;
type Gate = Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + Sync>>;

#[cfg(test)]
mod tests;

#[derive(Clone)]
enum Observer {
    Record(Arc<dyn CaptureWire>, ClientTermination),
    #[allow(dead_code)]
    Replay(traffic_replay::SequenceClaim),
}

impl Observer {
    fn receipt(&self, kind: OutputKind) -> FlushReceipt {
        match self {
            Self::Record(capture, _) => capture.reserve(kind),
            Self::Replay(claim) => {
                let delivered = claim.clone();
                let failed = claim.clone();
                FlushReceipt::new(
                    move || {
                        if delivered.publish().is_err() {
                            delivered.fail();
                        }
                    },
                    move || failed.fail(),
                )
            }
        }
    }

    fn failed(&self) {
        match self {
            Self::Record(capture, termination) => {
                if capture.wire_terminal() {
                    return;
                }
                capture.failed(
                    termination
                        .connection_observation()
                        .peer_snapshot()
                        .map(|ended| ended.termination),
                );
            }
            Self::Replay(claim) => {
                let termination = claim.reserved_kind().is_some_and(|kind| {
                    matches!(
                        kind,
                        traffic_replay::EventKind::ClientTermination
                            | traffic_replay::EventKind::ServerTermination
                            | traffic_replay::EventKind::TargetStop
                    )
                });
                if !termination {
                    claim.fail();
                }
            }
        }
    }

    fn gate(&self, after: Option<u64>) -> Option<Gate> {
        match self {
            Self::Record(..) => None,
            Self::Replay(claim) => {
                let claim = claim.clone();
                Some(Box::pin(async move {
                    claim
                        .wait_body_delivery_after(
                            tokio::time::Instant::now() + std::time::Duration::from_secs(30),
                            after,
                        )
                        .await
                }))
            }
        }
    }
}

struct ObservedBody {
    last_event: Option<u64>,
    inner: Option<WireBody>,
    recorded_stream: Option<RecordedStream>,
    observer: Observer,
    progress: DeliveryProgress,
    gate: Option<Gate>,
    finished: bool,
    queued: bool,
    granular: bool,
}

impl ObservedBody {
    fn new(
        inner: WireBody,
        observer: Observer,
        progress: DeliveryProgress,
        recorded_stream: Option<RecordedStream>,
    ) -> Self {
        let empty = inner.is_end_stream();
        let granular = match &observer {
            Observer::Record(..) => true,
            Observer::Replay(claim) => matches!(
                claim.reserved_kind(),
                Some(
                    traffic_replay::EventKind::ResponseHeaders
                        | traffic_replay::EventKind::ResponsePart
                )
            ),
        };
        let headers = match &observer {
            Observer::Record(..) => !empty,
            Observer::Replay(claim) => {
                claim.reserved_kind() == Some(traffic_replay::EventKind::ResponseHeaders)
            }
        };
        let body = Self {
            last_event: None,
            inner: Some(inner),
            recorded_stream,
            observer,
            progress,
            gate: None,
            finished: empty,
            queued: empty,
            granular,
        };
        if headers {
            body.observe_flush(OutputKind::Headers);
        }
        if empty {
            body.observe_flush(OutputKind::End);
        }
        body
    }

    fn observe_flush(&self, kind: OutputKind) {
        let mut receipt = self.observer.receipt(kind);
        if matches!(kind, OutputKind::Headers | OutputKind::Part)
            && let Some(stream) = &self.recorded_stream
        {
            receipt = receipt.with_timestamp(stream.0.clone());
        }
        self.progress.observe_flush(receipt);
    }
}

impl Body for ObservedBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        if this.finished {
            return Poll::Ready(None);
        }
        if !this.queued {
            this.gate = this
                .granular
                .then(|| this.observer.gate(this.last_event))
                .flatten();
            this.queued = true;
        }
        if let Some(gate) = &mut this.gate {
            match gate.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => {
                    this.observer.failed();
                    this.finished = true;
                    return Poll::Ready(Some(Err(std::io::Error::other(error))));
                }
                Poll::Ready(Ok(())) => this.gate = None,
            }
        }
        let inner = this.inner.as_mut().expect("live response body");
        let frame = match Pin::new(&mut *inner).poll_frame(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(frame) => frame,
        };
        match &frame {
            Some(Err(_)) => {
                this.observer.failed();
                this.finished = true;
            }
            _ => {
                if let Observer::Replay(claim) = &this.observer {
                    this.last_event = claim.reserved_event().map(|event| event.sequence);
                }
                this.finished = frame.is_none() || inner.is_end_stream();
                let kind = if this.finished {
                    OutputKind::End
                } else {
                    OutputKind::Part
                };
                if this.granular || this.finished {
                    this.observe_flush(kind);
                }
            }
        }
        this.queued = this.finished;
        Poll::Ready(frame)
    }

    fn is_end_stream(&self) -> bool {
        self.finished
            || self
                .inner
                .as_ref()
                .expect("live response body")
                .is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.inner.as_ref().expect("live response body").size_hint()
    }
}

impl Drop for ObservedBody {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        if self.recorded_stream.is_some() {
            // The shutdown marker can arrive during drop. Settle Session
            // stream evidence before reporting generic delivery failure.
            drop(self.inner.take());
        }
        self.observer.failed();
    }
}

pub fn record(
    mut response: Response<WireBody>,
    capture: Option<Arc<dyn CaptureWire>>,
    termination: ClientTermination,
) -> Response<WireBody> {
    let Some(capture) = capture else {
        return response;
    };
    if capture.wire_terminal() {
        return response;
    }
    let progress = termination.delivery();
    let recorded_stream = response.extensions_mut().remove::<RecordedStream>();
    response.map(|body| {
        ObservedBody::new(
            body,
            Observer::Record(capture, termination),
            progress,
            recorded_stream,
        )
        .boxed()
    })
}

#[allow(dead_code)]
pub fn replay(
    response: Response<WireBody>,
    claim: Option<traffic_replay::SequenceClaim>,
    progress: DeliveryProgress,
) -> Response<WireBody> {
    let Some(claim) = claim else {
        return response;
    };
    response.map(|body| ObservedBody::new(body, Observer::Replay(claim), progress, None).boxed())
}
