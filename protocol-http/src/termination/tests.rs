use super::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{Duration, timeout},
};

#[tokio::test]
async fn a_reset_reported_only_by_flush_is_observed_before_body_release() {
    struct FlushReset;
    impl AsyncWrite for FlushReset {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(bytes.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    let termination = ClientTermination::default();
    let mut writer = ObservedClientIo::new(FlushReset, termination.clone());
    writer.write_all(b"prefix").await.unwrap();
    assert_eq!(
        writer.flush().await.unwrap_err().kind(),
        io::ErrorKind::ConnectionReset
    );
    assert_eq!(
        termination
            .cancelled()
            .expect("flush must retain peer reset")
            .termination
            .kind,
        TerminationKind::Reset
    );
}

#[tokio::test]
async fn a_reset_observed_after_client_fin_wakes_the_raw_observer() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let termination = ClientTermination::with_control(&server).unwrap();
    let observer = termination.clone();
    let observing = tokio::spawn(async move { observer.wait_for_cancellation().await });
    client.shutdown().await.unwrap();
    timeout(Duration::from_secs(1), async {
        while termination.observed().is_none() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        termination.cancelled().is_none(),
        "FIN must retain the response direction"
    );
    // A TLS/write observer can report reset after the raw reader saw FIN.
    // The first half-close must not hide that independent connection ending.
    termination
        .connection_observation()
        .observe_client_io_error(&io::ErrorKind::ConnectionReset.into());
    timeout(Duration::from_secs(1), observing)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        termination.observed().unwrap().termination.kind,
        TerminationKind::Eof
    );
    assert_eq!(
        termination.cancelled().unwrap().termination.kind,
        TerminationKind::Reset
    );
}

#[tokio::test]
async fn raw_transport_flush_cannot_certify_http_prefix_delivery() {
    let termination = ClientTermination::default();
    let prefix = PrefixDelivery::new(termination.delivery());
    prefix.queued();
    let (writer, _reader) = tokio::io::duplex(64);
    let mut writer = ObservedClientIo::transport(writer, termination.clone());
    writer.write_all(b"TLS bytes").await.unwrap();
    writer.flush().await.unwrap();
    assert!(!prefix.is_complete());
    let mut writer = ObservedClientIo::new(writer, termination);
    writer.flush().await.unwrap();
    assert!(prefix.is_complete());
}

#[test]
fn diagnostic_keeps_bounded_error_kinds_without_inventing_cancellation_or_retaining_text() {
    let termination = ClientTermination::default();
    let started = Instant::now();
    for _ in 0..100 {
        termination.observe_io_error(
            IoLayer::Http,
            IoOperation::Flush,
            &io::Error::new(
                io::ErrorKind::BrokenPipe,
                "private credential must not be retained",
            ),
        );
    }
    let diagnosis = termination.diagnosis(started);
    let errors = diagnosis["io_errors"].as_array().unwrap();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0]["kind"], "BrokenPipe");
    assert!(termination.cancelled().is_none());
    assert!(!diagnosis.to_string().contains("private credential"));
}

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
