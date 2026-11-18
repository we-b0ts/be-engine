//! Independently confirm a peer end after a failed downstream write.
use crate::interaction::{model::EndReason, websocket_transport::FrameObservation};
use anyhow::{Context, Result, bail, ensure};
use futures_util::StreamExt;
use std::time::Duration;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::watch,
};
use tokio_tungstenite::{WebSocketStream, tungstenite::Error};

/// A write error cannot establish a client input. Ask the existing decoder for
/// exactly one next item, retaining its buffered bytes and framing state. New
/// input is never discarded in order to reach a later, more convenient EOF.
pub(super) async fn after_write_failure<S>(
    downstream: &mut WebSocketStream<S>,
    observed: &FrameObservation,
    closing: &mut watch::Receiver<Option<EndReason>>,
    timeout: Duration,
) -> Result<Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    ensure!(
        closing.borrow().is_none(),
        "case closed before client end read"
    );
    let item = tokio::select! {
        biased;
        _ = closing.changed() => bail!("case closed while awaiting client end read"),
        item = tokio::time::timeout(timeout, downstream.next()) =>
            item.context("client end read timed out after failed write")?,
    };
    ensure!(
        closing.borrow().is_none(),
        "case closed during client end read"
    );
    let error = match item {
        Some(Err(error)) if super::failure::client_lost(&error) => error,
        Some(Err(_)) => bail!("client end read returned a WebSocket decoding error"),
        Some(Ok(_)) => bail!("new client input followed failed downstream write"),
        None => bail!("client decoder ended without a transport end read"),
    };
    ensure!(
        observed.termination().is_some() && observed.complete_boundary(),
        "client end read lacks a complete framing boundary and real EOF/reset"
    );
    Ok(error)
}

#[cfg(test)]
mod tests;
