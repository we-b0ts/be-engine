use super::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{Duration, timeout},
};

#[tokio::test]
async fn raw_observer_detects_reset_behind_buffered_bytes_without_consuming_them() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (mut server, _) = listener.accept().await.unwrap();
    let termination = ClientTermination::with_control(&server).unwrap();
    client.write_all(b"queued").await.unwrap();
    let observer = termination.clone();
    let observing = tokio::spawn(async move { observer.wait_for_cancellation().await });
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(!observing.is_finished());
    ConnectionControl::new(&client).unwrap().reset().unwrap();
    let error = timeout(Duration::from_secs(1), observing)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    assert_eq!(
        termination.cancelled().unwrap().termination.kind,
        TerminationKind::Reset
    );
    let mut payload = [0; 6];
    server.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"queued");
}
