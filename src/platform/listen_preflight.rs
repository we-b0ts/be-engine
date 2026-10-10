use std::net::SocketAddr;

use anyhow::Result;

pub(super) async fn require_available(listen: SocketAddr) -> Result<()> {
    let listener = crate::tcp_listener::bind_with_diagnostic(
        listen,
        format!("http_gateway.listen {listen} is unavailable before managed recording startup"),
    )
    .await?;
    drop(listener);
    Ok(())
}

#[cfg(test)]
mod tests {
    use tokio::net::TcpListener;

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
