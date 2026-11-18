//! RESP push forwarding shares the connection's ordered native writer.
use anyhow::Result;
use std::sync::Arc;
use tokio::{io::AsyncWriteExt, sync::Mutex};
use traffic_protocol::transport::ConnectionTermination;

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
