use anyhow::Result;

#[allow(dead_code)]
#[cfg(any(test, feature = "test-support"))]
pub async fn handle_http_replay_connection(
    stream: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    target: crate::replay::ReplayTarget,
    state: std::sync::Arc<tokio::sync::Mutex<super::ReplayState>>,
    _: std::sync::Arc<crate::MitmCa>,
) -> Result<()> {
    crate::replay::native::handle_connection(stream, peer, target, state).await
}

#[cfg(test)]
pub(crate) use super::http_test_support as tests;
