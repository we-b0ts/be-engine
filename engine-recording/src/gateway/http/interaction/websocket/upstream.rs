//! Preserve HTTP preread bytes and the real transport of an upgraded Source.
use super::*;
use crate::{dependency::termination::ConnectionControl, http::client::ObservedUpstream};

pub(super) async fn upgrade(
    upgraded: hyper::upgrade::Upgraded,
    config: tokio_tungstenite::tungstenite::protocol::WebSocketConfig,
) -> Result<(WebSocketStream<ObservedUpstream>, ConnectionControl)> {
    let parts = upgraded
        .downcast::<TokioIo<ObservedUpstream>>()
        .map_err(|_| anyhow::anyhow!("Source upgrade has no observed TCP transport"))?;
    let io = parts.io.into_inner();
    let control = io.connection_control()?;
    // Hyper may have received the Engine.IO OPEN in the HTTP 101 read. Dropping
    // this buffer would silently remove a genuine first Source observation.
    let socket = WebSocketStream::from_partially_read(
        io,
        parts.read_buf.to_vec(),
        Role::Client,
        Some(config),
    )
    .await;
    Ok((socket, control))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn upgraded_source_retains_open_received_with_the_http_101() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(tcp.read_u8().await.unwrap());
            }
            // One real socket write deliberately includes bytes beyond the
            // upgraded HTTP response. They belong to the WebSocket reader.
            tcp.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n\x81\x030{}")
                .await.unwrap();
            let mut byte = [0];
            assert_eq!(tcp.read(&mut byte).await.unwrap(), 0);
        });
        let request = Request::builder()
            .uri(format!(
                "http://{address}/socket.io/?EIO=4&transport=websocket"
            ))
            .header("connection", "upgrade")
            .header("upgrade", "websocket")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let mut response = crate::http::client::new_proxy_client()
            .request(request)
            .await
            .unwrap();
        let upgraded = hyper::upgrade::on(&mut response).await.unwrap();
        let (mut socket, control) = upgrade(upgraded, Default::default()).await.unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap(),
            Message::Text("0{}".into())
        );
        control.shutdown_write().unwrap();
        peer.await.unwrap();
    }
}
