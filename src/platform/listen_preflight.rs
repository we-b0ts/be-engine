use std::net::SocketAddr;

use anyhow::{Context, Result};
use tokio::net::TcpListener;
use tokio::process::Command;

const MAX_LISTENER_DIAGNOSTIC_CHARS: usize = 512;

pub(super) async fn require_available(listen: SocketAddr) -> Result<()> {
    match TcpListener::bind(listen).await {
        Ok(listener) => {
            drop(listener);
            Ok(())
        }
        Err(error) => {
            let owner = listener_diagnostic(listen).await;
            let owner = owner.as_deref().unwrap_or("listener owner unavailable");
            Err(error).with_context(|| {
                format!(
                    "http_gateway.listen {listen} is unavailable before managed recording startup; {owner}"
                )
            })
        }
    }
}

async fn listener_diagnostic(listen: SocketAddr) -> Option<String> {
    let filter = format!("sport = :{}", listen.port());
    let output = Command::new("ss")
        .args(["-H", "-ltnp", &filter])
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(|line| line.chars().take(MAX_LISTENER_DIAGNOSTIC_CHARS).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_an_occupied_configured_listener() {
        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen = occupied.local_addr().unwrap();

        let error = require_available(listen).await.unwrap_err();
        let message = format!("{error:#}");

        assert!(message.contains(&format!("http_gateway.listen {listen}")));
        assert!(message.contains("before managed recording startup"));
        assert!(message.contains("Address already in use"));
    }

    #[tokio::test]
    async fn accepts_a_kernel_assigned_available_listener() {
        let listen = "127.0.0.1:0".parse().unwrap();
        require_available(listen).await.unwrap();
    }
}
