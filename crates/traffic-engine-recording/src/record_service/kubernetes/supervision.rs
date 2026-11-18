//! Publish one forwarding listener and propagate every unexpected child exit.

use std::{net::SocketAddr, time::Duration};

use anyhow::{Context, Result, anyhow};
use tokio::sync::{oneshot, watch};

use super::process::KubectlChild;

pub(super) async fn forward(
    child: KubectlChild,
    identity: String,
    ready: oneshot::Sender<SocketAddr>,
    stopped: watch::Receiver<bool>,
    startup_timeout: Duration,
) -> Result<()> {
    let mut ready = Some(ready);
    child
        .forward(
            identity,
            |address| {
                ready
                    .take()
                    .context("kubectl readiness was already published")?
                    .send(address)
                    .map_err(|_| anyhow!("kubectl port-forward readiness receiver closed"))
            },
            stopped,
            startup_timeout,
        )
        .await
}
