mod capture;
mod evidence;
use crate::dependency::termination::ConnectionTermination;
use anyhow::Result;
pub(super) use capture::{CapturedPush, capture};
pub(super) use evidence::record_subscription;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
pub(super) use traffic_protocol_redis::capture::Subscriptions;

pub(super) async fn write_push(
    client_write: &Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    termination: &ConnectionTermination,
    client_open: &mut bool,
    bytes: &mut u64,
    payload: &[u8],
) -> Result<bool> {
    if !*client_open {
        *client_open = false;
        return Ok(false);
    }
    match client_write.lock().await.write_all(payload).await {
        Ok(()) => {
            *bytes += payload.len() as u64;
            return Ok(true);
        }
        Err(error) if termination.observe_client_io_error(&error) => *client_open = false,
        Err(error) => return Err(error.into()),
    }
    Ok(false)
}
