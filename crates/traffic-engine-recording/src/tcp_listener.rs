use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::TcpListener;
use tokio::process::Command;

const LISTENER_DIAGNOSTIC_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_LISTENER_DIAGNOSTIC_CHARS: usize = 512;

pub async fn bind_with_diagnostic(
    listen: SocketAddr,
    error_context: impl Into<String>,
) -> Result<TcpListener> {
    let error_context = error_context.into();
    match TcpListener::bind(listen).await {
        Ok(listener) => Ok(listener),
        Err(error) => {
            let owner = listener_diagnostic(listen)
                .await
                .unwrap_or_else(|| "listener owner unavailable".to_string());
            Err(error).with_context(|| format!("{error_context}; {owner}"))
        }
    }
}

async fn listener_diagnostic(listen: SocketAddr) -> Option<String> {
    let filter = format!("sport = :{}", listen.port());
    let output = tokio::time::timeout(
        LISTENER_DIAGNOSTIC_TIMEOUT,
        Command::new("ss").args(["-H", "-ltnp", &filter]).output(),
    )
    .await
    .ok()?
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
    async fn occupied_listener_preserves_bind_error_and_diagnostic() {
        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen = occupied.local_addr().unwrap();

        let error = bind_with_diagnostic(listen, format!("failed to bind test listener {listen}"))
            .await
            .unwrap_err();
        let message = format!("{error:#}");

        assert!(message.contains(&format!("failed to bind test listener {listen}")));
        assert!(message.contains("Address already in use"));
    }

    #[tokio::test]
    async fn available_listener_remains_owned_by_the_caller() {
        let listener = bind_with_diagnostic(
            "127.0.0.1:0".parse().unwrap(),
            "failed to bind test listener",
        )
        .await
        .unwrap();
        let listen = listener.local_addr().unwrap();

        let error = TcpListener::bind(listen).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
    }
}
