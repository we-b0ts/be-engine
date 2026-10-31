use super::*;
use futures_util::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::{Message, protocol::Role};

fn frame(opcode: u8, fin: bool, payload: &[u8]) -> Vec<u8> {
    let mut header = vec![opcode | if fin { 0x80 } else { 0 }];
    match payload.len() {
        0..=125 => header.push(0x80 | payload.len() as u8),
        126..=65_535 => {
            header.push(0xfe);
            header.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
        _ => {
            header.push(0xff);
            header.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
    }
    let mask = [0x10, 0x20, 0x30, 0x40];
    header.extend_from_slice(&mask);
    header.extend(
        payload
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ mask[index % 4]),
    );
    header
}

#[test]
fn every_header_and_payload_cut_keeps_the_exact_boundary_with_constant_storage() {
    for length in [0, 1, 125, 126, 65_535, 65_536] {
        let wire = frame(2, true, &vec![0xa5; length]);
        let header = wire.len() - length;
        for cut in 1..wire.len() {
            if length > 126 && cut > header + 2 && cut + 2 < wire.len() {
                continue;
            }
            let mut parser = Framing::default();
            parser.read(&wire[..cut]);
            assert_eq!(
                parser.boundary(),
                if cut < header {
                    FrameBoundary::Header
                } else {
                    FrameBoundary::Payload
                },
                "length={length} cut={cut}"
            );
            parser.read(&wire[cut..]);
            assert_eq!(parser.boundary(), FrameBoundary::Complete);
            assert_eq!(parser.header.len(), 14);
        }
        let mut parser = Framing::default();
        for byte in &wire {
            parser.read(std::slice::from_ref(byte));
        }
        assert_eq!(parser.boundary(), FrameBoundary::Complete);
    }
}

#[test]
fn control_frames_do_not_complete_an_unfinished_fragmented_message() {
    let mut parser = Framing::default();
    parser.read(&frame(1, false, b"part"));
    assert_eq!(parser.boundary(), FrameBoundary::Fragmented);
    for control in [8, 9, 10] {
        parser.read(&frame(control, true, b""));
        assert_eq!(parser.boundary(), FrameBoundary::Fragmented);
    }
    parser.read(&frame(0, false, b"more"));
    assert_eq!(parser.boundary(), FrameBoundary::Fragmented);
    parser.read(&frame(0, true, b"end"));
    assert_eq!(parser.boundary(), FrameBoundary::Complete);
}

#[test]
fn illegal_headers_remain_invalid_instead_of_acquiring_a_clean_end() {
    for (raw, expected) in [
        (vec![0xc1, 0x80], FrameViolation::ReservedBits),
        (vec![0x83, 0x80], FrameViolation::UnknownOpcode),
        (vec![0x81, 0x00], FrameViolation::MaskRequired),
        (vec![0x09, 0x80], FrameViolation::FragmentedControl),
        (vec![0x89, 0xfe], FrameViolation::OversizedControl),
        (vec![0x88, 0x81], FrameViolation::InvalidCloseLength),
        (vec![0x80, 0x80], FrameViolation::UnexpectedContinuation),
        (
            vec![0x81, 0xfe, 0, 1, 0, 0, 0, 0],
            FrameViolation::NoncanonicalLength,
        ),
        (
            vec![0x81, 0xff, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            FrameViolation::InvalidLength,
        ),
        (
            vec![0x81, 0xff, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0],
            FrameViolation::NoncanonicalLength,
        ),
    ] {
        let mut parser = Framing::default();
        parser.read(&raw);
        assert_eq!(parser.boundary(), FrameBoundary::Invalid(expected));
        parser.read(&frame(1, true, b"valid later frame"));
        assert_eq!(parser.boundary(), FrameBoundary::Invalid(expected));
    }
    let mut parser = Framing::default();
    parser.read(&frame(1, false, b"unfinished"));
    parser.read(&frame(2, true, b"different data message"));
    assert_eq!(
        parser.boundary(),
        FrameBoundary::Invalid(FrameViolation::InterruptedFragment)
    );
}

#[test]
fn huge_claimed_lengths_retain_only_a_fixed_header_and_payload_counter() {
    let mut parser = Framing::default();
    parser.read(&[
        0x82, 0xff, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0,
    ]);
    assert_eq!(parser.boundary(), FrameBoundary::Payload);
    assert_eq!(parser.remaining, (1_u64 << 63) - 1);
    parser.read(&[0; 32]);
    assert_eq!(parser.remaining, (1_u64 << 63) - 33);
    assert_eq!(parser.header.len(), 14);
}

async fn tcp() -> (TcpStream, FramedTransport<TcpStream>, FrameObservation) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peer = TcpStream::connect(listener.local_addr().unwrap());
    let (peer, accepted) = tokio::join!(peer, listener.accept());
    let (stream, monitor) = FramedTransport::new(accepted.unwrap().0, true);
    (peer.unwrap(), stream, monitor)
}

#[tokio::test]
async fn real_tcp_fin_preserves_complete_frames_and_partial_input_facts() {
    let complete = frame(1, true, b"complete");
    for (raw, boundary) in [
        (complete.clone(), FrameBoundary::Complete),
        (complete[..1].to_vec(), FrameBoundary::Header),
        (
            complete[..complete.len() - 1].to_vec(),
            FrameBoundary::Payload,
        ),
        (frame(1, false, b"unfinished"), FrameBoundary::Fragmented),
    ] {
        let (mut peer, mut stream, monitor) = tcp().await;
        peer.write_all(&raw).await.unwrap();
        peer.shutdown().await.unwrap();
        let before = Instant::now();
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await.unwrap();
        let after = Instant::now();
        assert_eq!(received, raw);
        assert_eq!(monitor.boundary(), boundary);
        assert_eq!(
            monitor.complete_boundary(),
            boundary == FrameBoundary::Complete
        );
        let (kind, at) = monitor.termination().unwrap();
        assert_eq!(kind, ClientTransportEnd::Eof);
        assert!(at >= before && at <= after);
        monitor.begin_cleanup();
        assert_eq!(monitor.termination(), Some((kind, at)));
        assert_eq!(monitor.boundary(), boundary);
    }
}

#[tokio::test]
async fn decoder_read_ahead_cannot_erase_a_later_partial_frame() {
    let (mut peer, stream, monitor) = tcp().await;
    let mut bytes = frame(1, true, b"first");
    bytes.extend_from_slice(&[0x81]);
    peer.write_all(&bytes).await.unwrap();
    peer.shutdown().await.unwrap();
    let mut decoder = WebSocketStream::from_raw_socket(stream, Role::Server, None).await;
    assert_eq!(
        decoder.next().await.unwrap().unwrap(),
        Message::Text("first".into())
    );
    assert_eq!(monitor.boundary(), FrameBoundary::Header);
    assert!(decoder.next().await.unwrap().is_err());
    assert_eq!(monitor.termination().unwrap().0, ClientTransportEnd::Eof);
    assert!(!monitor.complete_boundary());
}

#[tokio::test]
async fn complete_read_ahead_frames_are_all_observed_before_eof() {
    let (mut peer, stream, monitor) = tcp().await;
    let mut bytes = frame(1, true, b"one");
    bytes.extend_from_slice(&frame(1, true, b"two"));
    peer.write_all(&bytes).await.unwrap();
    peer.shutdown().await.unwrap();
    let mut decoder = WebSocketStream::from_raw_socket(stream, Role::Server, None).await;
    for value in ["one", "two"] {
        assert_eq!(
            decoder.next().await.unwrap().unwrap(),
            Message::Text(value.into())
        );
        assert!(monitor.complete_boundary());
    }
    assert!(decoder.next().await.unwrap().is_err());
    assert_eq!(monitor.termination().unwrap().0, ClientTransportEnd::Eof);
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn a_real_reset_is_observed_but_cannot_overwrite_an_earlier_fin() {
    for fin_first in [false, true] {
        let (peer, mut stream, monitor) = tcp().await;
        let control = crate::dependency::termination::ConnectionControl::new(&peer).unwrap();
        if fin_first {
            control.shutdown_write().unwrap();
            assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
        }
        let first = monitor.termination();
        control.reset().unwrap();
        let result =
            tokio::time::timeout(std::time::Duration::from_secs(1), stream.read(&mut [0; 1]))
                .await
                .unwrap();
        if fin_first {
            assert_eq!(monitor.termination(), first);
        } else {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::ConnectionReset);
            assert_eq!(monitor.termination().unwrap().0, ClientTransportEnd::Reset);
        }
    }
}

#[tokio::test]
async fn engine_cleanup_before_peer_eof_does_not_forge_a_client_input() {
    let (mut peer, mut stream, monitor) = tcp().await;
    monitor.begin_cleanup();
    peer.shutdown().await.unwrap();
    assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
    assert!(monitor.termination().is_none());
    assert!(monitor.complete_boundary());
}

struct ReadFailure(io::ErrorKind);
impl AsyncRead for ReadFailure {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::from(self.0)))
    }
}

#[tokio::test]
async fn unexpected_eof_broken_pipe_and_zero_capacity_are_not_peer_facts() {
    for kind in [
        io::ErrorKind::UnexpectedEof,
        io::ErrorKind::BrokenPipe,
        io::ErrorKind::NotConnected,
        io::ErrorKind::InvalidData,
    ] {
        let (mut stream, monitor) = FramedTransport::new(ReadFailure(kind), true);
        assert_eq!(stream.read(&mut [0; 1]).await.unwrap_err().kind(), kind);
        assert!(monitor.termination().is_none());
    }
    let (empty, _peer) = tokio::io::duplex(1);
    let (mut stream, monitor) = FramedTransport::new(empty, true);
    assert_eq!(stream.read(&mut []).await.unwrap(), 0);
    assert!(monitor.termination().is_none());
}

#[tokio::test]
async fn writes_and_shutdown_are_transparent_and_do_not_claim_peer_termination() {
    let (peer, stream) = tokio::io::duplex(64);
    let (mut stream, monitor) = FramedTransport::new(stream, true);
    let reading = tokio::spawn(async move {
        let mut peer = peer;
        let mut bytes = Vec::new();
        peer.read_to_end(&mut bytes).await.unwrap();
        bytes
    });
    stream.write_all(b"opaque server bytes").await.unwrap();
    stream.flush().await.unwrap();
    stream.shutdown().await.unwrap();
    assert_eq!(reading.await.unwrap(), b"opaque server bytes");
    assert!(monitor.termination().is_none());
}
