use super::*;
use std::sync::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use traffic_protocol::{
    capture::CaptureSnapshot,
    connection::{
        CaptureExchange, CaptureHost, CaptureOutput, NativeFuture, Operation, RequestHost,
        ResponseDelivery, ResponseFramer,
    },
    message::{MessageEncoder, ProtocolMessage},
};

fn info() -> ConnectionInfo {
    ConnectionInfo {
        endpoint: Endpoint {
            host: "cache.test".into(),
            port: 6379,
        },
        client_addr: None,
        upstream_addr: None,
        max_frame_bytes: 1024 * 1024,
    }
}

struct Host;

impl RequestHost for Host {
    fn execute(
        &self,
        request: Arc<dyn ProtocolMessage>,
    ) -> NativeFuture<'_, Box<dyn ResponseDelivery>> {
        Box::pin(async move {
            let request = request.project()?;
            ensure!(
                request.structure["command"] == "GET" && request.structure["database"] == 3,
                "unexpected native request context"
            );
            ensure!(
                request.values["/args/0"].bytes.as_ref() == b"key",
                "unexpected native request value"
            );
            Ok(Box::new(Reply) as Box<dyn ResponseDelivery>)
        })
    }
}

struct Reply;
impl ResponseDelivery for Reply {
    fn write<'a>(
        self: Box<Self>,
        io: &'a mut dyn traffic_protocol::connection::OutputIo,
        framer: &'a mut dyn ResponseFramer,
    ) -> NativeFuture<'a, ()> {
        Box::pin(async move {
            io.write_all(&framer.frame(Bytes::from_static(b"$5\r\nvalue\r\n"))?)
                .await?;
            io.flush().await?;
            Ok(())
        })
    }
}

#[tokio::test]
async fn native_server_owns_session_controls_and_delegates_business_requests() {
    let (mut client, io) = tokio::io::duplex(4096);
    let server = Native.server_session(info()).unwrap();
    let task = tokio::spawn(server.run(Box::new(io), Arc::new(Host)));
    let mut commands = crate::encode_array(&[b"SELECT", b"3"]);
    commands.extend(crate::encode_array(&[b"GET", b"key"]));
    commands.extend(crate::encode_array(&[b"QUIT"]));
    client.write_all(&commands).await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    task.await.unwrap().unwrap();
    assert_eq!(response, b"+OK\r\n$5\r\nvalue\r\n+OK\r\n");
}

#[test]
fn response_projection_renders_selected_values_and_preserves_exact_source_frames() {
    for bytes in [
        b"*-1\r\n".as_slice(),
        b"*2\r\n$3\r\nold\r\n$-1\r\n".as_slice(),
    ] {
        let response = ResponseMessage::decode(Bytes::copy_from_slice(bytes)).unwrap();
        let values = response
            .project()
            .unwrap()
            .values
            .into_iter()
            .map(|(path, value)| (path, value.bytes))
            .collect();
        assert_eq!(response.encode(&values).unwrap().as_ref(), bytes);
    }
    let response = ResponseMessage::decode(Bytes::from_static(b"$3\r\nold\r\n")).unwrap();
    assert_eq!(
        response
            .encode(&std::collections::BTreeMap::from([(
                String::new(),
                Bytes::from_static(b"new-value")
            )]))
            .unwrap(),
        b"$9\r\nnew-value\r\n".as_slice()
    );
}

#[test]
fn unsupported_native_evidence_is_rejected_before_inventory_preparation() {
    assert!(
        Native
            .recorded_exchange(&json!({"event_type":"redis_pub_sub_push"}))
            .is_err()
    );
    assert!(
        Native
            .recorded_exchange(&json!({"event_type":"redis_connection","replay_safe":false}))
            .is_err()
    );
}

#[derive(Default)]
struct CaptureSink(Arc<Mutex<Vec<CaptureSnapshot>>>);
struct Permit(Arc<Mutex<Vec<CaptureSnapshot>>>);
struct Receipt;
impl CaptureOutput for Receipt {
    fn commit(self: Box<Self>) {}
}
impl CaptureExchange for Permit {
    fn prepare_output(
        &self,
        _: traffic_model::trace::OutputKind,
    ) -> Result<Box<dyn CaptureOutput>> {
        Ok(Box::new(Receipt))
    }
    fn complete(self: Box<Self>, event: CaptureSnapshot) -> NativeFuture<'static, ()> {
        Box::pin(async move {
            self.0.lock().unwrap().push(event);
            Ok(())
        })
    }
}
impl CaptureHost for CaptureSink {
    fn begin_message(
        &self,
        event: &CaptureSnapshot,
    ) -> NativeFuture<'_, Option<Box<dyn CaptureExchange>>> {
        self.begin(event.facts().reference.clone(), Operation::Unknown)
    }

    fn begin(
        &self,
        _: ProtocolRef,
        _: Operation,
    ) -> NativeFuture<'_, Option<Box<dyn CaptureExchange>>> {
        Box::pin(async {
            Ok(Some(
                Box::new(Permit(self.0.clone())) as Box<dyn CaptureExchange>
            ))
        })
    }
    fn observe(&self, event: CaptureSnapshot) -> NativeFuture<'_, ()> {
        Box::pin(async move {
            self.0.lock().unwrap().push(event);
            Ok(())
        })
    }
}

mod pubsub;

#[tokio::test]
async fn native_recording_redacts_credentials_and_produces_executable_records() {
    let (mut client, capture_client) = tokio::io::duplex(4096);
    let (capture_upstream, mut upstream) = tokio::io::duplex(4096);
    let sink = Arc::new(CaptureSink::default());
    let mut recording_info = info();
    recording_info.max_frame_bytes = 8;
    let recording = Native.capture_session(recording_info).unwrap();
    let task = tokio::spawn(recording.run(
        Box::new(capture_client),
        Box::new(capture_upstream),
        sink.clone(),
    ));
    let source = tokio::spawn(async move {
        let mut upstream = crate::BufferedReader::new(&mut upstream, 4096);
        for response in [b"+OK\r\n".as_slice(), b"$5\r\nvalue\r\n".as_slice()] {
            crate::read_frame(&mut upstream).await.unwrap().unwrap();
            upstream.inner.write_all(response).await.unwrap();
            upstream.inner.flush().await.unwrap();
        }
    });
    client
        .write_all(&crate::encode_array(&[b"AUTH", b"private-password"]))
        .await
        .unwrap();
    let mut client = crate::BufferedReader::new(client, 4096);
    assert_eq!(
        crate::read_frame(&mut client)
            .await
            .unwrap()
            .unwrap()
            .raw
            .as_ref(),
        b"+OK\r\n"
    );
    client
        .inner
        .write_all(&crate::encode_array(&[b"GET", b"key"]))
        .await
        .unwrap();
    assert_eq!(
        crate::read_frame(&mut client)
            .await
            .unwrap()
            .unwrap()
            .raw
            .as_ref(),
        b"$5\r\nvalue\r\n"
    );
    client.inner.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
    source.await.unwrap();
    let events = sink.0.lock().unwrap();
    assert_eq!(events.len(), 2);
    assert!(
        !serde_json::to_string(events[0].payload())
            .unwrap()
            .contains("private-password")
    );
    assert!(
        Native
            .recorded_exchange(events[0].payload())
            .unwrap()
            .is_none()
    );
    assert!(
        Native
            .recorded_exchange(events[1].payload())
            .unwrap()
            .is_some()
    );
}
