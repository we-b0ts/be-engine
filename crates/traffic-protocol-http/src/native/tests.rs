use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use traffic_protocol::{
    connection::{NativeFuture, RequestHost, ResponseDelivery, ResponseFramer},
    message::{MessageEncoder, ProtocolMessage},
};

struct Host;
struct Delivery(ResponseMessage);
impl RequestHost for Host {
    fn execute(
        &self,
        request: Arc<dyn ProtocolMessage>,
    ) -> NativeFuture<'_, Box<dyn ResponseDelivery>> {
        Box::pin(async move {
            let request = request.project()?;
            ensure!(
                request.values["/body"].bytes.as_ref() == br#"{"id":42}"#,
                "unexpected body"
            );
            Ok(Box::new(Delivery(ResponseMessage {
                status: 200,
                headers: Default::default(),
                body: Bytes::from_static(b"ok"),
                head_request: false,
            })) as Box<dyn ResponseDelivery>)
        })
    }
}
impl ResponseDelivery for Delivery {
    fn write<'a>(
        self: Box<Self>,
        io: &'a mut dyn traffic_protocol::connection::OutputIo,
        framer: &'a mut dyn ResponseFramer,
    ) -> NativeFuture<'a, ()> {
        Box::pin(async move {
            let values = self
                .0
                .project()?
                .values
                .into_iter()
                .map(|(path, value)| (path, value.bytes))
                .collect();
            io.write_all(&framer.frame(self.0.encode(&values)?)?)
                .await?;
            io.flush().await?;
            Ok(())
        })
    }
}
fn info() -> ConnectionInfo {
    ConnectionInfo {
        endpoint: Endpoint {
            host: "api.test".into(),
            port: 80,
        },
        client_addr: None,
        upstream_addr: None,
        max_frame_bytes: 1024,
    }
}

#[tokio::test]
async fn native_server_reads_chunked_requests_and_uses_the_shared_delivery_port() {
    let (mut client, io) = tokio::io::duplex(4096);
    let task = tokio::spawn(
        Native
            .server_session(info())
            .unwrap()
            .run(Box::new(io), Arc::new(Host)),
    );
    client.write_all(b"POST /resource HTTP/1.1\r\nHost: api.test\r\nTransfer-Encoding: chunked\r\n\r\n9\r\n{\"id\":42}\r\n0\r\n\r\n").await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    task.await.unwrap().unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with(b"\r\n\r\nok"));
}

#[tokio::test]
async fn ambiguous_http_framing_is_rejected() {
    let (mut client, io) = tokio::io::duplex(4096);
    client
        .write_all(b"POST / HTTP/1.1\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n")
        .await
        .unwrap();
    let mut reader = wire::Reader::new(Box::new(io), 1024);
    assert!(reader.request().await.is_err());
}

#[derive(Default)]
struct Sink(Arc<std::sync::Mutex<Vec<traffic_protocol::capture::CaptureSnapshot>>>);
struct Permit(Arc<std::sync::Mutex<Vec<traffic_protocol::capture::CaptureSnapshot>>>);
struct Receipt;
impl traffic_protocol::connection::CaptureOutput for Receipt {
    fn commit(self: Box<Self>) {}
}
impl traffic_protocol::connection::CaptureExchange for Permit {
    fn prepare_output(
        &self,
        _: traffic_model::trace::OutputKind,
    ) -> Result<Box<dyn traffic_protocol::connection::CaptureOutput>> {
        Ok(Box::new(Receipt))
    }
    fn complete(
        self: Box<Self>,
        event: traffic_protocol::capture::CaptureSnapshot,
    ) -> NativeFuture<'static, ()> {
        Box::pin(async move {
            self.0.lock().unwrap().push(event);
            Ok(())
        })
    }
}
impl traffic_protocol::connection::CaptureHost for Sink {
    fn begin(
        &self,
        _: ProtocolRef,
        _: traffic_protocol::connection::Operation,
    ) -> NativeFuture<'_, Option<Box<dyn traffic_protocol::connection::CaptureExchange>>> {
        Box::pin(async move {
            Ok(Some(Box::new(Permit(self.0.clone()))
                as Box<dyn traffic_protocol::connection::CaptureExchange>))
        })
    }
    fn observe(&self, event: traffic_protocol::capture::CaptureSnapshot) -> NativeFuture<'_, ()> {
        Box::pin(async move {
            self.0.lock().unwrap().push(event);
            Ok(())
        })
    }
}

#[tokio::test]
async fn native_capture_persists_protocol_owned_data_that_can_project_for_replay() {
    let (mut client, capture_client) = tokio::io::duplex(4096);
    let (capture_upstream, upstream) = tokio::io::duplex(4096);
    let sink = Arc::new(Sink::default());
    let capture = tokio::spawn(Native.capture_session(info()).unwrap().run(
        Box::new(capture_client),
        Box::new(capture_upstream),
        sink.clone(),
    ));
    let source = tokio::spawn(async move {
        let mut reader = wire::Reader::new(Box::new(upstream), 1024);
        let request = reader.request().await.unwrap().unwrap();
        assert_eq!(request.body.as_ref(), br#"{"id":42}"#);
        reader.io.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n9\r\n{\"id\":42}\r\n0\r\n\r\n").await.unwrap();
        reader.io.flush().await.unwrap();
    });
    client
        .write_all(
            b"POST /items HTTP/1.1\r\nHost: api.test\r\nContent-Length: 9\r\n\r\n{\"id\":42}",
        )
        .await
        .unwrap();
    let mut bytes = Vec::new();
    client.read_to_end(&mut bytes).await.unwrap();
    capture.await.unwrap().unwrap();
    source.await.unwrap();
    assert!(bytes.ends_with(br#"{"id":42}"#));
    let events = sink.0.lock().unwrap();
    assert_eq!(events.len(), 1);
    let exchange = Native
        .recorded_exchange(events[0].payload())
        .unwrap()
        .unwrap();
    assert_eq!(exchange.endpoint.host, "api.test");
    let request = exchange
        .request()
        .expect("native request")
        .project()
        .unwrap();
    assert_eq!(request.values["/body"].bytes.as_ref(), br#"{"id":42}"#);
    assert_eq!(
        exchange.response.project().unwrap().values["/body"]
            .bytes
            .as_ref(),
        br#"{"id":42}"#
    );
    let mut protected = events[0].payload().clone();
    protected["request_headers"]["authorization"] = serde_json::json!(["traffic-e2e:enc:test"]);
    assert!(Native.recorded_exchange(&protected).is_err());
    assert!(
        Native
            .recorded_exchange_with_secrets(&protected, &Secrets)
            .unwrap()
            .is_some()
    );
}

struct Secrets;
impl traffic_protocol::evidence::EvidenceSecrets for Secrets {
    fn unseal_text<'a>(&self, label: &str, value: &'a str) -> Result<std::borrow::Cow<'a, str>> {
        if value == "traffic-e2e:enc:test" {
            ensure!(label == "authorization", "secret label changed");
            return Ok(std::borrow::Cow::Owned("Bearer test-token".into()));
        }
        Ok(std::borrow::Cow::Borrowed(value))
    }
}
