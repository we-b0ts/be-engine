//! Raw client peer facts and bounded framing state below the WebSocket decoder.
use super::model::ClientTransportEnd;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FrameViolation {
    ReservedBits,
    UnknownOpcode,
    MaskRequired,
    FragmentedControl,
    OversizedControl,
    InvalidCloseLength,
    NoncanonicalLength,
    InvalidLength,
    UnexpectedContinuation,
    InterruptedFragment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FrameBoundary {
    Complete,
    Header,
    Payload,
    Fragmented,
    Invalid(FrameViolation),
}

#[derive(Debug, Clone, Default)]
pub(crate) struct FrameObservation(Arc<Mutex<Observation>>);

#[derive(Debug, Default)]
struct Observation {
    framing: Framing,
    end: Option<(ClientTransportEnd, Instant)>,
    engine_cleanup: bool,
}

impl FrameObservation {
    pub(crate) fn termination(&self) -> Option<(ClientTransportEnd, Instant)> {
        self.0.lock().expect("WebSocket frame observation").end
    }

    pub(crate) fn complete_boundary(&self) -> bool {
        self.boundary() == FrameBoundary::Complete
    }

    fn boundary(&self) -> FrameBoundary {
        self.0
            .lock()
            .expect("WebSocket frame observation")
            .framing
            .boundary()
    }

    /// A later cleanup cannot erase a previously observed peer end. Cleanup
    /// initiated before any peer end cannot create a client termination input.
    pub(crate) fn begin_cleanup(&self) {
        self.0
            .lock()
            .expect("WebSocket frame observation")
            .engine_cleanup = true;
    }

    fn read(&self, bytes: &[u8], end: Option<ClientTransportEnd>, at: Instant) {
        let mut observation = self.0.lock().expect("WebSocket frame observation");
        if observation.end.is_some() || observation.engine_cleanup {
            return;
        }
        observation.framing.read(bytes);
        if let Some(end) = end {
            observation.end = Some((end, at));
        }
    }
}

/// Observe every raw byte, including decoder read-ahead, without retaining
/// payloads or resetting state when an individual message is returned.
pub(crate) struct FramedTransport<S> {
    inner: S,
    observation: FrameObservation,
}

impl<S> FramedTransport<S> {
    pub(crate) fn new(inner: S, require_mask: bool) -> (Self, FrameObservation) {
        let observation = FrameObservation::default();
        observation
            .0
            .lock()
            .expect("WebSocket frame observation")
            .framing
            .require_mask = require_mask;
        (
            Self {
                inner,
                observation: observation.clone(),
            },
            observation,
        )
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for FramedTransport<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let before = buf.filled().len();
        let capacity = buf.remaining() > 0;
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        let at = Instant::now();
        let end = match &result {
            Poll::Ready(Ok(())) if capacity && before == buf.filled().len() => {
                Some(ClientTransportEnd::Eof)
            }
            Poll::Ready(Err(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                ) =>
            {
                Some(ClientTransportEnd::Reset)
            }
            // TLS truncation or a failed write is not independently observed FIN.
            _ => None,
        };
        if matches!(result, Poll::Ready(_)) {
            self.observation.read(&buf.filled()[before..], end, at);
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FramedTransport<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[derive(Debug)]
struct Framing {
    header: [u8; 14],
    used: usize,
    needed: usize,
    remaining: u64,
    fragmented: bool,
    fragment_after: Option<bool>,
    require_mask: bool,
    invalid: Option<FrameViolation>,
}

impl Default for Framing {
    fn default() -> Self {
        Self {
            header: [0; 14],
            used: 0,
            needed: 2,
            remaining: 0,
            fragmented: false,
            fragment_after: None,
            require_mask: true,
            invalid: None,
        }
    }
}

impl Framing {
    fn boundary(&self) -> FrameBoundary {
        if let Some(invalid) = self.invalid {
            FrameBoundary::Invalid(invalid)
        } else if self.remaining > 0 {
            FrameBoundary::Payload
        } else if self.used > 0 {
            FrameBoundary::Header
        } else if self.fragmented {
            FrameBoundary::Fragmented
        } else {
            FrameBoundary::Complete
        }
    }

    fn read(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() && self.invalid.is_none() {
            if self.remaining > 0 {
                let take = usize::try_from(self.remaining)
                    .unwrap_or(usize::MAX)
                    .min(bytes.len());
                self.remaining -= take as u64;
                bytes = &bytes[take..];
                if self.remaining == 0 {
                    self.finish_frame();
                }
                continue;
            }
            let take = (self.needed - self.used).min(bytes.len());
            self.header[self.used..self.used + take].copy_from_slice(&bytes[..take]);
            self.used += take;
            bytes = &bytes[take..];
            if self.used < self.needed {
                continue;
            }
            if self.needed == 2 {
                if let Err(invalid) = self.prefix() {
                    self.invalid = Some(invalid);
                    continue;
                }
                if self.used < self.needed {
                    continue;
                }
            }
            match self.length() {
                Ok(length) => {
                    self.remaining = length;
                    if self.remaining == 0 {
                        self.finish_frame();
                    }
                }
                Err(invalid) => self.invalid = Some(invalid),
            }
        }
    }

    fn prefix(&mut self) -> Result<(), FrameViolation> {
        let first = self.header[0];
        let opcode = first & 0x0f;
        let fin = first & 0x80 != 0;
        if first & 0x70 != 0 {
            return Err(FrameViolation::ReservedBits);
        }
        if !matches!(opcode, 0 | 1 | 2 | 8 | 9 | 10) {
            return Err(FrameViolation::UnknownOpcode);
        }
        if self.require_mask && self.header[1] & 0x80 == 0 {
            return Err(FrameViolation::MaskRequired);
        }
        if opcode >= 8 {
            if !fin {
                return Err(FrameViolation::FragmentedControl);
            }
            if self.header[1] & 0x7f > 125 {
                return Err(FrameViolation::OversizedControl);
            }
            if opcode == 8 && self.header[1] & 0x7f == 1 {
                return Err(FrameViolation::InvalidCloseLength);
            }
        }
        self.fragment_after = match opcode {
            0 if !self.fragmented => return Err(FrameViolation::UnexpectedContinuation),
            0 if fin => Some(false),
            1 | 2 if self.fragmented => return Err(FrameViolation::InterruptedFragment),
            1 | 2 if !fin => Some(true),
            _ => None,
        };
        let extended = match self.header[1] & 0x7f {
            126 => 2,
            127 => 8,
            _ => 0,
        };
        self.needed = 2 + extended + if self.header[1] & 0x80 != 0 { 4 } else { 0 };
        Ok(())
    }

    fn length(&self) -> Result<u64, FrameViolation> {
        match self.header[1] & 0x7f {
            126 => {
                let length = u16::from_be_bytes([self.header[2], self.header[3]]);
                if length < 126 {
                    Err(FrameViolation::NoncanonicalLength)
                } else {
                    Ok(u64::from(length))
                }
            }
            127 => {
                let length = u64::from_be_bytes(
                    self.header[2..10]
                        .try_into()
                        .expect("bounded extended frame length"),
                );
                if length & (1 << 63) != 0 {
                    Err(FrameViolation::InvalidLength)
                } else if length < 65_536 {
                    Err(FrameViolation::NoncanonicalLength)
                } else {
                    Ok(length)
                }
            }
            length => Ok(u64::from(length)),
        }
    }

    fn finish_frame(&mut self) {
        if let Some(fragmented) = self.fragment_after.take() {
            self.fragmented = fragmented;
        }
        self.used = 0;
        self.needed = 2;
    }
}

#[cfg(test)]
mod tests;
