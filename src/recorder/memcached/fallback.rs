use anyhow::Result;
use tokio::io::AsyncWrite;

use crate::AppState;
use crate::memcached::BufferedReader;
use crate::recorder::capture_health::{ConnectionCaptureHealth, RawTrafficDirection};

pub(super) async fn forward_buffer_and_copy<R, W>(
    reader: &mut BufferedReader<R>,
    writer: &mut W,
    prefix: Option<&[u8]>,
    capture_health: &ConnectionCaptureHealth,
    state: &AppState,
    direction: RawTrafficDirection,
) -> Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut copied = 0_u64;
    if let Some(prefix) = prefix {
        copied += capture_health
            .write_raw(state, direction, writer, prefix)
            .await?;
    }
    let buffered = reader.buffer.split().freeze();
    copied += capture_health
        .write_raw(state, direction, writer, &buffered)
        .await?;
    copied += capture_health
        .copy_raw(state, direction, &mut reader.inner, writer)
        .await?;
    Ok(copied)
}
