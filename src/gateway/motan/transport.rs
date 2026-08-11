use std::time::Duration;

use anyhow::{Context, Result, bail};
use motan_protocol::{
    EmptyResponseDisposition, Frame, FrameDecoder, FrameRef, Limits, MessageKind,
    encode_empty_response, parse_frame_ref,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

pub(super) async fn read_frame<R>(
    reader: &mut R,
    decoder: &mut FrameDecoder,
    limits: Limits,
) -> Result<Option<Frame>>
where
    R: AsyncRead + Unpin,
{
    loop {
        if let Some(frame) = decoder.decode()? {
            return Ok(Some(frame));
        }
        if decoder.buffered_len() >= limits.max_frame_bytes {
            bail!(
                "Motan frame buffer reached configured limit {}",
                limits.max_frame_bytes
            );
        }
        let remaining = limits.max_frame_bytes - decoder.buffered_len();
        let read = reader
            .take(remaining as u64)
            .read_buf(decoder.buffer_mut())
            .await
            .context("failed to read Motan frame")?;
        if read == 0 {
            if decoder.buffered_len() == 0 {
                return Ok(None);
            }
            bail!("Motan connection ended with a partial frame");
        }
    }
}

pub(super) async fn forward_request(
    request: &Frame,
    upstream: &str,
    connect_timeout: Duration,
    request_timeout: Duration,
    limits: Limits,
) -> Result<Option<Frame>> {
    let mut stream = tokio::time::timeout(connect_timeout, TcpStream::connect(upstream))
        .await
        .with_context(|| format!("timed out connecting to Motan upstream {upstream}"))?
        .with_context(|| format!("failed to connect to Motan upstream {upstream}"))?;
    stream
        .set_nodelay(true)
        .context("failed to configure Motan upstream TCP_NODELAY")?;
    tokio::time::timeout(request_timeout, stream.write_all(request.raw()))
        .await
        .context("timed out writing Motan upstream request")?
        .context("failed to write Motan upstream request")?;
    if request.flags.oneway() {
        stream.shutdown().await.ok();
        return Ok(None);
    }

    let mut decoder = FrameDecoder::new(limits)?;
    let response = tokio::time::timeout(
        request_timeout,
        read_frame(&mut stream, &mut decoder, limits),
    )
    .await
    .context("timed out waiting for Motan upstream response")??
    .context("Motan upstream closed before returning a response")?;
    if response.kind != MessageKind::Response {
        bail!("Motan upstream returned a request frame");
    }
    if response.request_id != request.request_id {
        bail!(
            "Motan upstream response request id {} differs from request id {}",
            response.request_id,
            request.request_id
        );
    }
    if response.version != request.version {
        bail!(
            "Motan upstream response protocol {:?} differs from request protocol {:?}",
            response.version,
            request.version
        );
    }
    Ok(Some(response))
}

pub(super) async fn write_frame<W>(writer: &mut W, frame: &Frame) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer
        .write_all(frame.raw())
        .await
        .context("failed to write Motan downstream response")
}

pub(super) async fn write_fixed_response<W>(
    writer: &mut W,
    request: &Frame,
    limits: Limits,
) -> Result<EmptyResponseDisposition>
where
    W: AsyncWrite + Unpin,
{
    let request: FrameRef<'_> = parse_frame_ref(request.raw(), limits)?;
    let mut response = Vec::new();
    let disposition = encode_empty_response(request, &mut response, limits)?;
    if disposition == EmptyResponseDisposition::Written {
        writer
            .write_all(&response)
            .await
            .context("failed to write Motan fixed response")?;
    }
    Ok(disposition)
}
