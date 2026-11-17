use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap());
    let (client, accepted) = tokio::join!(client, listener.accept());
    (client.unwrap(), accepted.unwrap().0)
}

#[tokio::test]
async fn reset_closes_both_sides_without_touching_primary_or_reconnected_sockets() {
    let registry = DependencyConnections::default();
    let (mut downstream, mut client) = pair().await;
    let (mut upstream, mut server) = pair().await;
    let (mut primary, mut source) = pair().await;
    let guard = registry.register("mysql", &[&client, &upstream]).unwrap();
    let report = registry.reset_open_connections();
    assert_eq!(
        report.connections_by_protocol,
        BTreeMap::from([("mysql", 1)])
    );
    assert!(report.errors.is_empty());
    for socket in [&mut downstream, &mut client, &mut upstream, &mut server] {
        assert_eq!(socket.read(&mut [0]).await.unwrap(), 0);
    }
    let (mut reconnected, mut peer) = pair().await;
    let _new_guard = registry.register("redis", &[&reconnected]).unwrap();
    drop(guard);
    reconnected.write_all(b"new").await.unwrap();
    let mut bytes = [0; 3];
    peer.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"new");
    primary.write_all(b"http").await.unwrap();
    let mut bytes = [0; 4];
    source.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"http");
    assert_eq!(
        registry.reset_open_connections().connections_by_protocol,
        BTreeMap::from([("redis", 1)])
    );
}

#[tokio::test]
async fn dropped_connection_is_removed_and_http_transport_keeps_registration() {
    let registry = DependencyConnections::default();
    let (stream, _peer) = pair().await;
    let transport = DependencyIo::new(stream, &registry, "https").unwrap();
    assert_eq!(registry.0.lock().unwrap().len(), 1);
    drop(transport);
    assert!(
        registry
            .reset_open_connections()
            .connections_by_protocol
            .is_empty()
    );
}

#[tokio::test]
async fn recovery_marks_engine_origin_before_socket_eof_is_observed() {
    let registry = DependencyConnections::default();
    let (mut peer, stream) = pair().await;
    let termination = crate::dependency::termination::ConnectionTermination::default();
    let _guard = registry
        .register_observed("redis", &[&stream], &termination)
        .unwrap();
    termination.observe_client_eof();
    registry.reset_open_connections();
    assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
    termination.observe_server_eof();
    assert!(termination.engine_stopped());
    assert!(
        termination
            .outcome_since(std::time::Instant::now())
            .is_none()
    );
}
