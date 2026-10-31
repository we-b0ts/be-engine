use super::*;
use crate::{
    dependency::termination::ConnectionControl,
    interaction::{model::ClientTransportEnd, websocket_transport::FramedTransport},
};
use futures_util::SinkExt;
use std::{
    io,
    pin::Pin,
    task::{Context as TaskContext, Poll},
};
use tokio::io::{AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::{Message, protocol::Role};

const DEADLINE: Duration = Duration::from_secs(1);

async fn tcp() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peer = TcpStream::connect(listener.local_addr().unwrap());
    let (peer, accepted) = tokio::join!(peer, listener.accept());
    (peer.unwrap(), accepted.unwrap().0)
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn real_tcp_reset_write_failure_requires_an_independent_read() {
    let (peer, accepted) = tcp().await;
    let control = ConnectionControl::new(&peer).unwrap();
    let (stream, observed) = FramedTransport::new(accepted, true);
    let mut socket = WebSocketStream::from_raw_socket(stream, Role::Server, None).await;
    control.reset().unwrap();
    let error = tokio::time::timeout(DEADLINE, async {
        loop {
            if let Err(error) = socket.send(Message::Text("source output".into())).await {
                break error;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(super::super::failure::client_lost(&error));
    assert!(
        observed.termination().is_none(),
        "write error alone is not a peer fact"
    );
    let (_sender, mut closing) = watch::channel(None);
    after_write_failure(&mut socket, &observed, &mut closing, DEADLINE)
        .await
        .unwrap();
    // A failed syscall write can consume SO_ERROR. Preserve whatever the real
    // following read observes; never infer Reset from the earlier write error.
    assert!(observed.termination().is_some());
    assert!(observed.complete_boundary());
}

struct FailedWrites<S>(S);

impl<S: AsyncRead + Unpin> AsyncRead for FailedWrites<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl<S: Unpin> AsyncWrite for FailedWrites<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut TaskContext<'_>,
        _: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

async fn failed_writer<S: AsyncRead + Unpin>(
    inner: S,
) -> (
    WebSocketStream<FramedTransport<FailedWrites<S>>>,
    FrameObservation,
) {
    let (stream, observed) = FramedTransport::new(FailedWrites(inner), true);
    let mut socket = WebSocketStream::from_raw_socket(stream, Role::Server, None).await;
    assert!(
        socket
            .send(Message::Text("source output".into()))
            .await
            .is_err()
    );
    assert!(observed.termination().is_none());
    (socket, observed)
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn a_pending_real_tcp_reset_is_observed_only_by_the_read() {
    let (peer, accepted) = tcp().await;
    let control = ConnectionControl::new(&peer).unwrap();
    control.reset().unwrap();
    // Force a write error without consuming the socket's pending read error.
    let (mut socket, observed) = failed_writer(accepted).await;
    let (_sender, mut closing) = watch::channel(None);
    after_write_failure(&mut socket, &observed, &mut closing, DEADLINE)
        .await
        .unwrap();
    assert_eq!(observed.termination().unwrap().0, ClientTransportEnd::Reset);
}

#[tokio::test]
async fn a_real_fin_after_failed_write_requires_complete_framing() {
    for (bytes, allowed) in [
        (Vec::new(), true),
        (vec![0x81], false),
        (vec![0x01, 0x80, 0, 0, 0, 0], false),
    ] {
        let (mut peer, accepted) = tcp().await;
        peer.write_all(&bytes).await.unwrap();
        peer.shutdown().await.unwrap();
        let (mut socket, observed) = failed_writer(accepted).await;
        let (_sender, mut closing) = watch::channel(None);
        let result = after_write_failure(&mut socket, &observed, &mut closing, DEADLINE).await;
        assert_eq!(result.is_ok(), allowed);
        assert_eq!(observed.termination().unwrap().0, ClientTransportEnd::Eof);
        assert_eq!(observed.complete_boundary(), allowed);
    }
}

#[tokio::test]
async fn a_write_error_without_peer_end_times_out_without_a_terminal_input() {
    let (_peer, stream) = tokio::io::duplex(64);
    let (mut socket, observed) = failed_writer(stream).await;
    let (_sender, mut closing) = watch::channel(None);
    let result = after_write_failure(
        &mut socket,
        &observed,
        &mut closing,
        Duration::from_millis(20),
    )
    .await;
    assert!(result.unwrap_err().to_string().contains("timed out"));
    assert!(observed.termination().is_none());
}

#[tokio::test]
async fn new_data_close_or_invalid_frames_are_not_discarded_to_reach_eof() {
    for bytes in [
        vec![0x81, 0x81, 0, 0, 0, 0, b'x'],
        vec![0x88, 0x80, 0, 0, 0, 0],
        vec![0x81, 0], // An unmasked client frame is a decoder error.
    ] {
        let (mut peer, stream) = tokio::io::duplex(64);
        peer.write_all(&bytes).await.unwrap();
        peer.shutdown().await.unwrap();
        let (mut socket, observed) = failed_writer(stream).await;
        let (_sender, mut closing) = watch::channel(None);
        assert!(
            after_write_failure(&mut socket, &observed, &mut closing, DEADLINE)
                .await
                .is_err()
        );
        assert!(
            observed.termination().is_none(),
            "must stop at the first returned item"
        );
    }
}

struct TruncatedTls;
impl AsyncRead for TruncatedTls {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut TaskContext<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()))
    }
}

#[tokio::test]
async fn unexpected_eof_without_a_raw_peer_fact_remains_a_failure() {
    let (mut socket, observed) = failed_writer(TruncatedTls).await;
    let (_sender, mut closing) = watch::channel(None);
    assert!(
        after_write_failure(&mut socket, &observed, &mut closing, DEADLINE)
            .await
            .is_err()
    );
    assert!(observed.termination().is_none());
}

#[tokio::test]
async fn session_close_interrupts_the_read_without_certifying_peer_end() {
    let (_peer, stream) = tokio::io::duplex(64);
    let (mut socket, observed) = failed_writer(stream).await;
    let (sender, mut closing) = watch::channel(None);
    let close = async {
        tokio::task::yield_now().await;
        sender.send(Some(EndReason::MaxDuration)).unwrap();
    };
    let (result, ()) = tokio::join!(
        after_write_failure(&mut socket, &observed, &mut closing, DEADLINE),
        close
    );
    assert!(result.unwrap_err().to_string().contains("case closed"));
    assert!(observed.termination().is_none());
}
