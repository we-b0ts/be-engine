//! A bounded channel forwards frames while the recorder owns the transport.

use bytes::Bytes;
use hyper::body::Frame;
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::sync::mpsc;

pub(super) struct LiveBody(pub(super) mpsc::Receiver<Result<Frame<Bytes>, anyhow::Error>>);

impl http_body::Body for LiveBody {
    type Data = Bytes;
    type Error = anyhow::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, anyhow::Error>>> {
        self.0.poll_recv(cx)
    }
}
