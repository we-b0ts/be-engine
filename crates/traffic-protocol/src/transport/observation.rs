use super::{ConnectionTermination, TerminationSide};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Observe bytes before a protocol decoder can turn EOF into a parse error.
pub struct ObservedIo<T> {
    inner: T,
    termination: ConnectionTermination,
    side: TerminationSide,
    bytes_read: u64,
    frame_capture: Option<FrameCapture>,
}

struct FrameCapture {
    bytes: Vec<u8>,
    limit: usize,
    truncated: bool,
}

impl<T> ObservedIo<T> {
    pub fn new(inner: T, termination: ConnectionTermination, side: TerminationSide) -> Self {
        Self {
            inner,
            termination,
            side,
            bytes_read: 0,
            frame_capture: None,
        }
    }
    pub fn get_ref(&self) -> &T {
        &self.inner
    }
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }
    pub fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    /// Retain the current decoder input so an interrupted frame can still be
    /// forwarded before its observed FIN/RST. This does not certify replayable
    /// framing, and callers must reject evidence when this bound is exceeded.
    pub fn begin_capture(&mut self, max_bytes: usize) {
        let capture = self.frame_capture.get_or_insert_with(|| FrameCapture {
            bytes: Vec::new(),
            limit: max_bytes,
            truncated: false,
        });
        capture.bytes.clear();
        capture.limit = max_bytes;
        capture.truncated = false;
    }

    pub fn captured(&self) -> &[u8] {
        self.frame_capture
            .as_ref()
            .map_or(&[], |capture| capture.bytes.as_slice())
    }

    #[cfg(test)]
    pub fn capture_truncated(&self) -> bool {
        self.frame_capture
            .as_ref()
            .is_some_and(|capture| capture.truncated)
    }

    pub(super) fn stop_capture(&mut self) {
        self.frame_capture = None;
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for ObservedIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let has_capacity = buf.remaining() > 0;
        let capture_remaining = self
            .frame_capture
            .as_ref()
            .map(|capture| capture.limit.saturating_sub(capture.bytes.len()));
        if has_capacity && capture_remaining == Some(0) {
            self.frame_capture
                .as_mut()
                .expect("enabled frame capture")
                .truncated = true;
            // Fail before consuming uncapturable bytes. Raw fallback can disable
            // the tap and forward them; a capture bound is not a peer EOF.
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "decoder input reached its transparent forwarding capture bound",
            )));
        }
        let result = if let Some(limit) = capture_remaining.filter(|limit| *limit < buf.remaining())
        {
            let mut bounded = ReadBuf::new(buf.initialize_unfilled_to(limit));
            let result = Pin::new(&mut self.inner).poll_read(cx, &mut bounded);
            let count = bounded.filled().len();
            buf.advance(count);
            result
        } else {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        };
        match &result {
            Poll::Ready(Ok(())) if has_capacity && before == buf.filled().len() => {
                self.termination.observe_eof(self.side)
            }
            Poll::Ready(Ok(())) => {
                self.bytes_read = self
                    .bytes_read
                    .saturating_add((buf.filled().len() - before) as u64);
                if let Some(capture) = &mut self.frame_capture {
                    let bytes = &buf.filled()[before..];
                    capture.bytes.extend_from_slice(bytes);
                }
            }
            Poll::Ready(Err(error)) => {
                self.termination.observe_io_error(self.side, error);
            }
            _ => {}
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for ObservedIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Err(error)) = &result {
            self.termination.observe_io_error(self.side, error);
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn interrupted_decoder_keeps_its_prefix_and_physical_eof() {
        let (mut peer, stream) = tokio::io::duplex(16);
        peer.write_all(b"abc").await.unwrap();
        peer.shutdown().await.unwrap();
        let termination = ConnectionTermination::default();
        let mut observed = ObservedIo::new(stream, termination.clone(), TerminationSide::Server);
        observed.begin_capture(8);
        let error = observed.read_exact(&mut [0; 8]).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(observed.captured(), b"abc");
        assert!(!observed.capture_truncated());
        assert_eq!(
            termination.peer_snapshot().unwrap().termination.side,
            TerminationSide::Server
        );
    }

    #[tokio::test]
    async fn frame_capture_is_optional_bounded_and_reset_between_frames() {
        let (mut peer, stream) = tokio::io::duplex(16);
        peer.write_all(b"abcdefgh").await.unwrap();
        let mut observed = ObservedIo::new(
            stream,
            ConnectionTermination::default(),
            TerminationSide::Server,
        );
        observed.read_exact(&mut [0; 2]).await.unwrap();
        assert!(observed.captured().is_empty());
        observed.begin_capture(2);
        let error = observed.read_exact(&mut [0; 4]).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(observed.captured(), b"cd");
        assert!(observed.capture_truncated());
        observed.stop_capture();
        let mut uncaptured = [0; 2];
        observed.read_exact(&mut uncaptured).await.unwrap();
        assert_eq!(&uncaptured, b"ef");
        observed.begin_capture(2);
        observed.read_exact(&mut [0; 2]).await.unwrap();
        assert_eq!(observed.captured(), b"gh");
        assert!(!observed.capture_truncated());
    }
}
