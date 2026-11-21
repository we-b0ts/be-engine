//! Track the admitted primary response boundary at the gateway body.
use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt;
use hyper::Response;
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use traffic_model::trace::PrimaryBoundary;
use uuid::Uuid;

use super::transport::GatewayBody;
use crate::recorder::ledger::CaptureRegistry;

pub(super) fn track(
    response: Response<GatewayBody>,
    capture: CaptureRegistry,
    case: Uuid,
) -> Response<GatewayBody> {
    response.map(|body| {
        if body.is_end_stream() {
            capture.primary_boundary(case, PrimaryBoundary::ResponseEnd);
            body
        } else {
            PrimaryBody {
                inner: body,
                receipt: Some((capture, case)),
            }
            .boxed_unsync()
        }
    })
}

struct PrimaryBody {
    inner: GatewayBody,
    receipt: Option<(CaptureRegistry, Uuid)>,
}

impl Body for PrimaryBody {
    type Data = Bytes;
    type Error = anyhow::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let actual = Pin::new(&mut self.inner).poll_frame(cx);
        match &actual {
            Poll::Ready(Some(Err(_))) => {
                self.receipt.take();
            }
            Poll::Ready(None) | Poll::Ready(Some(Ok(_))) if self.inner.is_end_stream() => {
                if let Some((capture, case)) = self.receipt.take() {
                    capture.primary_boundary(case, PrimaryBoundary::ResponseEnd);
                }
            }
            _ => {}
        }
        actual
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
