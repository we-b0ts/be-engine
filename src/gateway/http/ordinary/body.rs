//! Forward finite HTTP frames without coupling Source ownership to body drop.
use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt;
use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Instant,
};
use tokio::sync::mpsc;
use uuid::Uuid;

use super::super::transport::GatewayBody;
use crate::AppState;

pub(super) fn channel(
    state: AppState,
    case_id: Option<Uuid>,
    started: Instant,
    length: Option<u64>,
) -> (
    mpsc::Sender<anyhow::Result<Frame<Bytes>>>,
    GatewayBody,
    Arc<AtomicBool>,
) {
    let (sender, receiver) = mpsc::channel(8);
    let failed = Arc::new(AtomicBool::new(false));
    let body = ForwardBody {
        receiver,
        state,
        case_id,
        started,
        remaining: length,
        complete: length == Some(0),
        failed: failed.clone(),
    };
    (sender, body.boxed_unsync(), failed)
}

struct ForwardBody {
    receiver: mpsc::Receiver<anyhow::Result<Frame<Bytes>>>,
    state: AppState,
    case_id: Option<Uuid>,
    started: Instant,
    remaining: Option<u64>,
    complete: bool,
    failed: Arc<AtomicBool>,
}

impl Body for ForwardBody {
    type Data = Bytes;
    type Error = anyhow::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let frame = self.receiver.poll_recv(cx);
        match &frame {
            Poll::Ready(Some(Ok(frame))) => {
                if let (Some(remaining), Some(data)) = (&mut self.remaining, frame.data_ref()) {
                    *remaining = remaining.saturating_sub(data.len() as u64);
                    self.complete = *remaining == 0;
                }
            }
            Poll::Ready(None) => {
                let incomplete = self.failed.load(Ordering::Acquire) && !self.complete;
                self.complete = true;
                if incomplete {
                    return Poll::Ready(Some(Err(anyhow::anyhow!(
                        "gateway upstream response body is incomplete"
                    ))));
                }
            }
            _ => {}
        }
        frame
    }

    fn is_end_stream(&self) -> bool {
        self.complete
            || !self.failed.load(Ordering::Acquire)
                && self.receiver.is_closed()
                && self.receiver.is_empty()
    }

    fn size_hint(&self) -> SizeHint {
        self.remaining
            .map_or_else(SizeHint::default, SizeHint::with_exact)
    }
}

impl Drop for ForwardBody {
    fn drop(&mut self) {
        if !self.is_end_stream()
            && !self.failed.load(Ordering::Acquire)
            && let Some(case_id) = self.case_id
        {
            super::super::lifecycle::downstream_disconnected(&self.state, case_id, self.started);
        }
    }
}
