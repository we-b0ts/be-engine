//! Observe downstream connection termination without closing it on the client's behalf.
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::watch;

#[derive(Clone)]
pub(crate) struct ClientTermination(watch::Sender<Option<Instant>>);

impl Default for ClientTermination {
    fn default() -> Self {
        Self(watch::channel(None).0)
    }
}

impl ClientTermination {
    pub(crate) fn observed_at(&self) -> Option<Instant> {
        *self.0.borrow()
    }

    fn observe(&self) {
        self.0.send_if_modified(|value| {
            if value.is_some() {
                return false;
            }
            *value = Some(Instant::now());
            true
        });
    }
}

pub(crate) struct ObservedClientIo<T> {
    inner: T,
    termination: ClientTermination,
}

impl<T> ObservedClientIo<T> {
    pub(crate) fn new(inner: T, termination: ClientTermination) -> Self {
        Self { inner, termination }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for ObservedClientIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let has_capacity = buf.remaining() > 0;
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        match &result {
            Poll::Ready(Ok(())) if has_capacity && buf.filled().len() == before => {
                self.termination.observe();
            }
            Poll::Ready(Err(error)) if connection_ended(error) => self.termination.observe(),
            _ => {}
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for ObservedClientIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Err(error)) = &result
            && connection_ended(error)
        {
            self.termination.observe();
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn connection_ended(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::NotConnected
            | io::ErrorKind::UnexpectedEof
    )
}
