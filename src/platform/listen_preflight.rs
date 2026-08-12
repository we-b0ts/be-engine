use std::net::{IpAddr, Ipv4Addr, SocketAddr};

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

pub(super) fn managed_finite_comparison(
    enabled: bool,
    configured: SocketAddr,
) -> Option<SocketAddr> {
    enabled.then(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), configured.port()))
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

    #[test]
    fn finite_comparison_reuses_the_configured_port_on_loopback_only() {
        let configured = "0.0.0.0:4062".parse().unwrap();

        assert_eq!(
            managed_finite_comparison(true, configured),
            Some("127.0.0.1:4062".parse().unwrap())
        );
        assert_eq!(managed_finite_comparison(false, configured), None);
    }
}
