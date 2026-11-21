use super::*;
use http_body_util::Empty;
use hyper_util::rt::TokioIo;
use std::collections::VecDeque;
use tokio::net::{TcpListener, TcpStream};
use traffic_replay::{EventKind, SequencePlan, SequenceRuntime, SourceEvent};

struct Chunks(VecDeque<Bytes>);
impl Body for Chunks {
    type Data = Bytes;
    type Error = std::io::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        Poll::Ready(self.0.pop_front().map(|bytes| Ok(Frame::data(bytes))))
    }
    fn is_end_stream(&self) -> bool {
        self.0.is_empty()
    }
}

#[tokio::test]
async fn actual_http_flush_releases_headers_and_chunks_around_another_dependency_request() {
    let plan = SequencePlan::compile(
        [
            (1, 1, EventKind::Request),
            (2, 1, EventKind::ResponseHeaders),
            (3, 1, EventKind::ResponsePart),
            (4, 2, EventKind::Request),
            (5, 1, EventKind::ResponseEnd),
            (6, 2, EventKind::ResponseEnd),
        ]
        .into_iter()
        .map(|(sequence, dependency_sequence, kind)| SourceEvent {
            sequence,
            dependency_sequence,
            kind,
            offset_micros: sequence,
        }),
    )
    .unwrap();
    let runtime = SequenceRuntime::new(plan);
    let claim = runtime.admit(1).unwrap();
    claim
        .wait_delivery(tokio::time::Instant::now() + std::time::Duration::from_secs(5))
        .await
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server_claim = claim.clone();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let termination = ClientTermination::with_control(&stream).unwrap();
        // The body and transport share the same framework flush observer.
        let response = replay(
            Response::new(
                Chunks([Bytes::from_static(b"one"), Bytes::from_static(b"two")].into()).boxed(),
            ),
            Some(server_claim),
            termination.delivery(),
        );
        let response = std::sync::Mutex::new(Some(response));
        let service = hyper::service::service_fn(move |_| {
            let response = response.lock().unwrap().take().unwrap();
            async { Ok::<_, std::convert::Infallible>(response) }
        });
        hyper::server::conn::http1::Builder::new()
            .serve_connection(
                TokioIo::new(super::super::termination::ObservedClientIo::new(
                    stream,
                    termination,
                )),
                service,
            )
            .await
            .unwrap();
    });
    let stream = TcpStream::connect(address).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    let client = tokio::spawn(connection);
    let request = hyper::Request::builder()
        .uri("/")
        .header("host", "test")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let mut response = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        sender.send_request(request),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        response
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        b"one"[..]
    );
    assert_eq!(runtime.expected().unwrap().dependency_sequence, 2);
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(50),
            response.body_mut().frame()
        )
        .await
        .is_err()
    );
    let second = runtime.admit(2).unwrap();
    let rest = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        response.into_body().collect(),
    )
    .await
    .unwrap()
    .unwrap()
    .to_bytes();
    assert_eq!(rest, b"two"[..]);
    assert!(claim.complete());
    second
        .wait_delivery(tokio::time::Instant::now() + std::time::Duration::from_secs(5))
        .await
        .unwrap();
    second.publish().unwrap();
    assert!(runtime.complete());
    client.abort();
    server.abort();
}
