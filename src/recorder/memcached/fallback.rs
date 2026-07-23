use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use chrono::Utc;
use tokio::io::{self, AsyncWriteExt};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::AppState;
use crate::memcached::BufferedReader;
use crate::recorder::{ProxyErrorEvent, RecorderEvent};

use super::ConnectionContext;

pub(super) async fn activate_raw_fallback(
    raw_fallback: &AtomicBool,
    reason: &Mutex<Option<String>>,
    message: String,
    state: &AppState,
    context: &ConnectionContext,
) -> Result<()> {
    let first = !raw_fallback.swap(true, Ordering::AcqRel);
    let mut reason = reason.lock().await;
    reason.get_or_insert_with(|| message.clone());
    drop(reason);
    if first {
        let event = RecorderEvent::ProxyError(ProxyErrorEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            protocol: "memcached".to_string(),
            client_addr: context.client_addr.clone(),
            client_process: context.client_process.clone(),
            target: Some(context.target_addr.clone()),
            error: message,
        });
        state.record_event(event);
    }
    Ok(())
}

pub(super) async fn forward_buffer_and_copy<R, W>(
    reader: &mut BufferedReader<R>,
    writer: &mut W,
) -> Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let buffered = reader.buffer.split().freeze();
    writer.write_all(&buffered).await?;
    let copied = io::copy(&mut reader.inner, writer).await?;
    Ok(buffered.len() as u64 + copied)
}
