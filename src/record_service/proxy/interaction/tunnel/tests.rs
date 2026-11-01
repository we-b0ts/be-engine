use super::*;
use std::time::Duration;
use tokio::net::TcpListener;

async fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let connected = TcpStream::connect(listener.local_addr().unwrap());
    let (connected, accepted) = tokio::join!(connected, listener.accept());
    (connected.unwrap(), accepted.unwrap().0)
}

#[tokio::test]
async fn prefetched_bytes_precede_tcp_input_and_real_fin_or_reset() {
    for reset in [false, true] {
        let (mut source, mut reader) = pair().await;
        let (mut destination, mut writer) = pair().await;
        let source_control = ConnectionControl::new(&source).unwrap();
        let destination_control = ConnectionControl::new(&writer).unwrap();
        let forwarding = tokio::spawn(async move {
            direction(
                Bytes::from_static(b"preread"),
                &mut reader,
                &mut writer,
                &destination_control,
            )
            .await
        });
        let mut prefix = [0; 7];
        destination.read_exact(&mut prefix).await.unwrap();
        assert_eq!(&prefix, b"preread");
        source.write_all(b"tail").await.unwrap();
        let mut tail = [0; 4];
        destination.read_exact(&mut tail).await.unwrap();
        assert_eq!(&tail, b"tail");
        if reset {
            source_control.reset().unwrap();
        } else {
            source_control.shutdown_write().unwrap();
        }
        let ended = tokio::time::timeout(Duration::from_secs(1), destination.read(&mut [0]))
            .await
            .unwrap();
        if reset {
            assert_eq!(ended.unwrap_err().kind(), io::ErrorKind::ConnectionReset);
        } else {
            assert_eq!(ended.unwrap(), 0);
        }
        forwarding.await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn a_failed_write_does_not_invent_a_peer_reset_or_fin() {
    let (_source, mut reader) = pair().await;
    let (mut destination, writer) = pair().await;
    let control = ConnectionControl::new(&writer).unwrap();
    let (mut failed_writer, rejected) = tokio::io::duplex(8);
    drop(rejected);
    let error = direction(
        Bytes::from_static(b"buffered"),
        &mut reader,
        &mut failed_writer,
        &control,
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    assert!(
        tokio::time::timeout(Duration::from_millis(35), destination.read(&mut [0]))
            .await
            .is_err(),
        "a write error did not independently observe a peer end"
    );
}
