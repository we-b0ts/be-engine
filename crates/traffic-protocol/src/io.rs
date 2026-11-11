//! Framework-owned buffering, bounds and EOF behavior shared by native codecs.
use crate::EventHandler;
use crate::FrameDecoder;

struct NextFrame<Message>(Option<Message>);
impl<Message> EventHandler<Message> for NextFrame<Message> {
    fn on_event(&mut self, message: Message) -> Result<()> {
        ensure!(
            self.0.is_none(),
            "decoder emitted more than one frame per step"
        );
        self.0 = Some(message);
        Ok(())
    }
}
use anyhow::{Result, ensure};
use bytes::BytesMut;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Debug)]
pub struct BufferedReader<R> {
    pub inner: R,
    pub buffer: BytesMut,
    pub max_frame_bytes: usize,
}

impl<R> BufferedReader<R> {
    pub fn new(inner: R, max_frame_bytes: usize) -> Self {
        Self {
            inner,
            buffer: BytesMut::new(),
            max_frame_bytes,
        }
    }
}

pub async fn read_frame<R: AsyncRead + Unpin, P: FrameDecoder>(
    reader: &mut BufferedReader<R>,
    provider: &mut P,
) -> Result<Option<P::Frame>> {
    loop {
        ensure!(
            reader.buffer.len() <= reader.max_frame_bytes,
            "protocol frame exceeds the configured byte limit"
        );
        let mut next = NextFrame(None);
        provider.parse(&mut reader.buffer, &mut next)?;
        if let Some(frame) = next.0 {
            return Ok(Some(frame));
        }
        let remaining = reader.max_frame_bytes.saturating_sub(reader.buffer.len());
        ensure!(
            remaining != 0,
            "protocol frame exceeds the configured byte limit"
        );
        let read_size = provider.read_size(&reader.buffer)?.min(remaining);
        ensure!(read_size != 0, "protocol decoder requested no progress");
        let read = (&mut reader.inner)
            .take(read_size as u64)
            .read_buf(&mut reader.buffer)
            .await?;
        if read == 0 {
            if reader.buffer.is_empty() {
                return Ok(None);
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed with an incomplete protocol frame",
            )
            .into());
        }
    }
}

/// A bounded single frame with no read-ahead, suitable for native TLS upgrades.
pub async fn read_one<R: AsyncRead + Unpin + ?Sized, P: FrameDecoder>(
    reader: &mut R,
    provider: &mut P,
    max_frame_bytes: usize,
) -> Result<Option<P::Frame>> {
    let mut buffered = BufferedReader::new(reader, max_frame_bytes);
    let result = read_frame(&mut buffered, provider).await?;
    ensure!(
        buffered.buffer.is_empty(),
        "single-frame decoder retained read-ahead bytes"
    );
    Ok(result)
}
