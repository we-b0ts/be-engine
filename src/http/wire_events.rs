//! Framework response boundaries are committed by the actual HTTP writer's flush.
use super::termination::{ClientTermination, DeliveryProgress, FlushReceipt};
use crate::recorder::ledger::CaptureReservation;
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
    Record(CaptureReservation, ClientTermination),
    Replay(traffic_replay::SequenceClaim),
}

impl Observer {
    fn receipt(&self, kind: OutputKind) -> FlushReceipt {
        match self {
            Self::Record(capture, _) => {
                let reserved = capture.prepare_output(kind);
                let failed = capture.clone();
                FlushReceipt::new(
                    move || {
                        if let Some(reserved) = reserved {
                            reserved.commit();
                        }
                    },
                    move || failed.delivery_failed(),
                )
            }
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
                if let Some(ended) = termination.connection_observation().peer_snapshot() {
                    capture.output(OutputKind::Terminated {
                        termination: ended.termination,
                    });
                } else {
                    capture.delivery_failed();
                }
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
    inner: WireBody,
    observer: Observer,
    progress: DeliveryProgress,
    gate: Option<Gate>,
    finished: bool,
    queued: bool,
    granular: bool,
}

impl ObservedBody {
    fn new(inner: WireBody, observer: Observer, progress: DeliveryProgress) -> Self {
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
        if headers {
            progress.observe_flush(observer.receipt(OutputKind::Headers));
        }
        if empty {
            progress.observe_flush(observer.receipt(OutputKind::End));
        }
        Self {
            last_event: None,
            inner,
            observer,
            progress,
            gate: None,
            finished: empty,
            queued: empty,
            granular,
        }
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
        let frame = match Pin::new(&mut this.inner).poll_frame(cx) {
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
                this.finished = frame.is_none() || this.inner.is_end_stream();
                let kind = if this.finished {
                    OutputKind::End
                } else {
                    OutputKind::Part
                };
                if this.granular || this.finished {
                    this.progress.observe_flush(this.observer.receipt(kind));
                }
            }
        }
        this.queued = this.finished;
        Poll::Ready(frame)
    }

    fn is_end_stream(&self) -> bool {
        self.finished || self.inner.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for ObservedBody {
    fn drop(&mut self) {
        if !self.finished {
            self.observer.failed();
        }
    }
}

pub(crate) fn record(
    response: Response<WireBody>,
    capture: Option<CaptureReservation>,
    termination: ClientTermination,
) -> Response<WireBody> {
    let Some(capture) = capture else {
        return response;
    };
    if capture.wire_terminal() {
        return response;
    }
    let progress = termination.delivery();
    response.map(|body| {
        ObservedBody::new(body, Observer::Record(capture, termination), progress).boxed()
    })
}

pub(crate) fn replay(
    response: Response<WireBody>,
    claim: Option<traffic_replay::SequenceClaim>,
    progress: DeliveryProgress,
) -> Response<WireBody> {
    let Some(claim) = claim else {
        return response;
    };
    response.map(|body| ObservedBody::new(body, Observer::Replay(claim), progress).boxed())
}
