use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use traffic_protocol::ProtocolId;
use traffic_protocol::{
    connection::{NativeFuture, RequestHost, ResponseDelivery, ResponseFramer},
    message::{MessageEncoder, ProtocolMessage},
    output::OutputBoundary,
};
use traffic_replay::{
    EventKind, ReplaySource, SequenceClaim, SequenceRuntime, SourceEvent, StreamEvent,
    exchange::{ExchangeInventory, ExchangeRules, MatchContext, Selection, SourceContext},
};

struct Host;
struct Delivery(Arc<dyn MessageEncoder>, Option<SequenceClaim>);
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
            Ok(Box::new(Delivery(
                Arc::new(ResponseMessage {
                    status: 200,
                    headers: Default::default(),
                    body: Bytes::from_static(b"ok"),
                    head_request: false,
                }),
                None,
            )) as Box<dyn ResponseDelivery>)
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
            if let Some(sequence) = &self.1 {
                sequence
                    .wait_delivery(tokio::time::Instant::now() + std::time::Duration::from_secs(1))
                    .await?;
                let output = self.0.output(&values)?;
                let mut output = traffic_protocol::output::FramedOutput::new(output, framer);
                traffic_replay::output::deliver(io, &mut output, Some(sequence)).await?;
                return sequence.publish();
            }
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
        upstream_addr: Some("192.0.2.1:80".into()),
        max_frame_bytes: 1,
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
    let mut reader = wire::Reader::new(Box::new(io));
    assert!(reader.request().await.is_err());
}

fn websocket_event(status: u16) -> Value {
    let capture = |value| serde_json::json!({"encoding":"utf8", "data":value, "truncated":false});
    serde_json::json!({
        "event_type":"http_exchange", "id":uuid::Uuid::nil(), "scheme":"http",
        "authority":"api.test:80", "method":"GET", "uri":"/socket?room=one",
        "request_headers":{
            "Host":["api.test"], "Connection":["Upgrade"], "Upgrade":["websocket"],
            "Sec-WebSocket-Version":["13"], "Sec-WebSocket-Key":["dGhlIHNhbXBsZSBub25jZQ=="],
            "Sec-WebSocket-Extensions":["permessage-deflate; client_max_window_bits"],
            "User-Agent":["Python/3.12 websockets/15.0.1"],
            "Sec-WebSocket-Protocol":["chat"], "X-Sdk-Signature":["business-value"]
        },
        "request_body":capture(""), "response_status":status,
        "response_headers":{"Content-Type":["text/plain"], "X-Request-Id":["refused"]},
        "response_body":capture("upgrade refused")
    })
}

const WEBSOCKET_REQUEST: &str = concat!(
    "GET /socket?room=one HTTP/1.1\r\nHost: api.test\r\nConnection: Upgrade\r\n",
    "Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n",
    "Sec-WebSocket-Key: MDEyMzQ1Njc4OWFiY2RlZg==\r\nSec-WebSocket-Protocol: chat\r\n",
    "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n",
    "User-Agent: Python/3.12 websockets/15.0.1\r\n",
    "X-Sdk-Signature: business-value\r\n\r\n",
);

struct RecordedHost(ExchangeInventory, Option<Arc<SequenceRuntime>>);

impl RecordedHost {
    fn new(event: &Value) -> Self {
        Self::with_session(event, None)
    }

    fn with_session(event: &Value, runtime: Option<Arc<SequenceRuntime>>) -> Self {
        let exchange = if runtime.is_some() {
            Native.recorded_session_exchange(event, &Secrets)
        } else {
            Native.recorded_exchange(event)
        }
        .unwrap()
        .unwrap();
        let mut inventory = ExchangeInventory::default();
        inventory
            .register(
                ProtocolId::new("http"),
                exchange,
                SourceContext {
                    source: ReplaySource::Startup,
                    case_id: None,
                    position: 0,
                    capture: None,
                },
                ExchangeRules::default(),
            )
            .unwrap();
        inventory.seal();
        Self(inventory, runtime)
    }
}

impl RequestHost for RecordedHost {
    fn execute(
        &self,
        request: Arc<dyn ProtocolMessage>,
    ) -> NativeFuture<'_, Box<dyn ResponseDelivery>> {
        Box::pin(async move {
            let selected = self.0.select(
                MatchContext {
                    protocol: ProtocolId::new("http"),
                    endpoint: &info().endpoint,
                    active_case: None,
                    request: request.as_ref(),
                    session: None,
                    lane: None,
                    request_session: None,
                    metadata: &(),
                },
                |_| (),
                |_, _| Ok(()),
            )?;
            let Selection::Matched(selected) = selected else {
                anyhow::bail!("unmatched HTTP request");
            };
            Ok(Box::new(Delivery(
                self.0.exchanges[selected.index].native.response.clone(),
                self.1
                    .as_ref()
                    .map(|runtime| runtime.admit(2))
                    .transpose()?,
            )) as Box<dyn ResponseDelivery>)
        })
    }
}

async fn replay_http(host: Arc<RecordedHost>, wire: &str) -> (String, Result<()>) {
    let (mut client, io) = tokio::io::duplex(4096);
    let task = tokio::spawn(
        Native
            .server_session(info())
            .unwrap()
            .run(Box::new(io), host),
    );
    client.write_all(wire.as_bytes()).await.unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).await.unwrap();
    (response, task.await.unwrap())
}

#[tokio::test]
async fn native_replay_delivers_only_the_matching_recorded_websocket_refusal() {
    let mut event = websocket_event(400);
    event["request_headers"]["Accept-Encoding"] = serde_json::json!(["gzip, deflate, br"]);
    let host = Arc::new(RecordedHost::new(&event));
    let reqwest = WEBSOCKET_REQUEST.replace(
        "X-Sdk-Signature",
        "Accept: */*\r\nAccept-Encoding: gzip\r\nX-Sdk-Signature",
    );
    let variants = [
        (WEBSOCKET_REQUEST.to_owned(), true),
        (reqwest.clone(), true),
        (reqwest.replace("*/*", "application/json"), false),
        (
            reqwest.replace("Accept-Encoding: gzip", "Accept-Encoding: gzip, br"),
            true,
        ),
        (
            reqwest.replace(
                "Accept-Encoding: gzip",
                "Accept-Encoding: gzip\r\nAccept-Encoding: gzip",
            ),
            true,
        ),
        (
            reqwest.replace(
                "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n",
                "",
            ),
            false,
        ),
        (
            reqwest.replace("Python/3.12 websockets/15.0.1", "different-sdk"),
            false,
        ),
        (WEBSOCKET_REQUEST.replace("room=one", "room=two"), false),
        (
            WEBSOCKET_REQUEST.replace("business-value", "different"),
            false,
        ),
        (
            WEBSOCKET_REQUEST.replace("Protocol: chat", "Protocol: other"),
            false,
        ),
        (
            WEBSOCKET_REQUEST.replace("Version: 13", "Version: 12"),
            false,
        ),
        (
            WEBSOCKET_REQUEST.replace("Connection: Upgrade", "Connection: close"),
            false,
        ),
        (
            WEBSOCKET_REQUEST.replace("MDEyMzQ1Njc4OWFiY2RlZg==", "websocket-nonce"),
            false,
        ),
    ];
    for (wire, matches) in variants {
        let (response, outcome) = replay_http(host.clone(), &wire).await;
        if matches {
            outcome.unwrap();
            assert_eq!(
                response,
                concat!(
                    "HTTP/1.1 400 Bad Request\r\ncontent-type: text/plain\r\n",
                    "x-request-id: refused\r\ncontent-length: 15\r\nconnection: close\r\n\r\nupgrade refused",
                )
            );
        } else {
            assert_eq!(outcome.unwrap_err().to_string(), "unmatched HTTP request");
            assert!(response.is_empty());
        }
    }
}

#[tokio::test]
async fn replay_accept_defaults_only_apply_to_unnegotiated_identity_refusals() {
    let request = WEBSOCKET_REQUEST.replace(
        "X-Sdk-Signature",
        "Accept: */*\r\nAccept-Encoding: gzip\r\nX-Sdk-Signature",
    );
    for (name, value) in [
        ("Vary", "accept-encoding"),
        ("Content-Encoding", "gzip"),
        ("Sec-WebSocket-Accept", "negotiated"),
        ("Sec-WebSocket-Extensions", "permessage-deflate"),
        ("Sec-WebSocket-Protocol", "chat"),
        ("Upgrade", "websocket"),
        ("Connection", "upgrade"),
    ] {
        let mut event = websocket_event(400);
        event["response_headers"][name] = serde_json::json!([value]);
        assert!(
            replay_http(Arc::new(RecordedHost::new(&event)), &request)
                .await
                .1
                .is_err(),
            "{name}"
        );
    }
    let mut streamed = websocket_event(400);
    streamed["response_stream"] = serde_json::json!({"version":2,"headers_ms":0,"end_ms":2,"complete":true,"chunks":[{"start":0,"end":15,"at_ms":1}]});
    assert!(
        replay_http(Arc::new(RecordedHost::new(&streamed)), &request)
            .await
            .1
            .is_err()
    );
    assert!(
        replay_http(Arc::new(RecordedHost::new(&websocket_event(403))), &request)
            .await
            .1
            .is_err()
    );
    let mut explicit = websocket_event(400);
    explicit["request_headers"]["Accept"] = serde_json::json!(["*/*"]);
    explicit["request_headers"]["Accept-Encoding"] = serde_json::json!(["gzip"]);
    explicit["response_headers"]["Content-Encoding"] = serde_json::json!(["identity"]);
    replay_http(Arc::new(RecordedHost::new(&explicit)), WEBSOCKET_REQUEST)
        .await
        .1
        .unwrap();
}

#[test]
fn native_replay_cannot_prepare_or_encode_switching_protocols() {
    let Err(error) = Native.recorded_exchange(&websocket_event(101)) else {
        panic!("native Replay prepared Switching Protocols");
    };
    assert!(error.to_string().contains("HTTP upgrades"));
    let response = ResponseMessage {
        status: 101,
        headers: Default::default(),
        body: Bytes::new(),
        head_request: false,
    };
    assert!(
        response
            .encode(&std::collections::BTreeMap::from([(
                "/body".into(),
                Bytes::new()
            )]))
            .is_err()
    );
}

fn sse_event() -> Value {
    serde_json::json!({
        "event_type": "http_exchange",
        "id": uuid::Uuid::nil(),
        "scheme": "https",
        "authority": "api.test:443",
        "method": "POST",
        "uri": "/messages",
        "request_headers": {"Host": ["api.test"]},
        "request_body": {"encoding": "utf8", "data": "{}", "truncated": false},
        "response_status": 200,
        "response_headers": {
            "Content-Type": ["text/event-stream; charset=utf-8"],
            "Content-Length": ["18"],
            "X-Request-Id": ["source-id"],
        },
        "response_body": {
            "encoding": "utf8", "data": "data: a\n\ndata: b\n\n", "truncated": false
        },
        "response_stream": {
            "version": 2,
            "headers_ms": 10,
            "chunks": [
                {"start": 0, "end": 7, "at_ms": 15},
                {"start": 7, "end": 18, "at_ms": 25},
            ],
            "end_ms": 30,
            "complete": true,
        },
    })
}

#[test]
fn native_replay_preserves_recorded_sse_boundaries_with_chunked_framing() {
    let response = Native
        .recorded_exchange(&sse_event())
        .unwrap()
        .unwrap()
        .response;
    let mut values: std::collections::BTreeMap<_, _> = response
        .project()
        .unwrap()
        .values
        .into_iter()
        .map(|(path, value)| (path, value.bytes))
        .collect();
    let header = response
        .locate(&serde_json::json!({"kind": "header", "name": "x-request-id"}))
        .unwrap()
        .pop()
        .unwrap();
    values.insert(header, Bytes::from_static(b"target-id"));

    let mut output = response.output(&values).unwrap();
    assert_eq!(output.part_count(), 2);
    let mut events = Vec::new();
    let mut pending = Vec::new();
    let mut boundary = None;
    while let Some(chunk) = output.next().unwrap() {
        assert_eq!(*boundary.get_or_insert(chunk.boundary), chunk.boundary);
        pending.extend_from_slice(&chunk.bytes);
        if chunk.complete {
            events.push((boundary.take().unwrap(), std::mem::take(&mut pending)));
        }
    }
    assert!(boundary.is_none());
    let [
        (OutputBoundary::Headers, headers),
        (OutputBoundary::Part, first),
        (OutputBoundary::Part, second),
        (OutputBoundary::End, end),
    ] = events.as_slice()
    else {
        panic!("SSE response emitted unexpected logical boundaries");
    };
    let headers = std::str::from_utf8(headers).unwrap().to_ascii_lowercase();
    assert!(headers.starts_with("http/1.1 200 ok\r\n"));
    assert!(headers.contains("content-type: text/event-stream; charset=utf-8\r\n"));
    assert!(headers.contains("transfer-encoding: chunked\r\n"));
    assert!(headers.contains("x-request-id: target-id\r\n"));
    assert!(!headers.contains("content-length:"));
    assert!(headers.ends_with("\r\n\r\n"));
    assert_eq!(first, b"7\r\ndata: a\r\n");
    assert_eq!(second, b"b\r\n\n\ndata: b\n\n\r\n");
    assert_eq!(end, b"0\r\n\r\n");
}

#[test]
fn native_replay_rejects_sse_without_complete_consistent_stream_evidence() {
    let mut missing = sse_event();
    missing.as_object_mut().unwrap().remove("response_stream");
    let mut incomplete = sse_event();
    incomplete["response_stream"]["complete"] = false.into();
    let mut gap = sse_event();
    gap["response_stream"]["chunks"][1]["start"] = 8.into();
    for event in [missing, incomplete, gap] {
        assert!(Native.recorded_exchange(&event).is_err());
    }
}

fn stopped_sse_event() -> Value {
    let mut event = sse_event();
    event["scheme"] = "http".into();
    event["authority"] = "api.test:80".into();
    event["duration_ms"] = 30.into();
    event["response_stream"]["complete"] = false.into();
    event["response_stream"]["stopped_at_source_exit"] = true.into();
    event
}

#[test]
fn stopped_http_prefix_requires_managed_session_and_consistent_evidence() {
    let event = stopped_sse_event();
    assert!(Native.recorded_exchange(&event).is_err());
    let exchange = Native
        .recorded_session_exchange(&event, &Secrets)
        .unwrap()
        .unwrap();
    assert_eq!(exchange.response_delay.as_millis(), 10);

    for (field, value) in [
        ("complete", true.into()),
        ("version", 1.into()),
        ("end_ms", 31.into()),
        ("trailers", serde_json::json!({"x-after":["done"]})),
    ] {
        let mut invalid = event.clone();
        invalid["response_stream"][field] = value;
        assert!(
            Native
                .recorded_session_exchange(&invalid, &Secrets)
                .is_err()
        );
    }
}

#[tokio::test]
async fn stopped_http_prefix_waits_through_the_session_without_writing_chunked_eof() {
    use EventKind::*;
    use std::time::Duration;
    use tokio::io::AsyncBufReadExt;

    let runtime = SequenceRuntime::streaming_session(Some(Duration::ZERO), []);
    runtime
        .push_stream(
            [
                (1, 0, SessionSourceStart, None),
                (2, 2, Request, None),
                (3, 2, ResponseHeadersStarted, None),
                (4, 2, ResponseHeaders, Some(3)),
                (5, 2, ResponsePartStarted, None),
                (6, 2, ResponsePart, Some(5)),
                (7, 0, SessionStop, None),
                (8, 2, ResponsePartStarted, None),
                (9, 2, ResponsePart, Some(8)),
                (10, 0, SessionSourceExit, None),
                (11, 2, TargetStopStarted, None),
                (12, 2, TargetStop, Some(11)),
            ]
            .into_iter()
            .map(
                |(sequence, dependency_sequence, kind, receipt_start)| StreamEvent {
                    source: SourceEvent {
                        sequence,
                        dependency_sequence,
                        offset_micros: sequence,
                        kind,
                    },
                    receipt_start,
                },
            )
            .collect(),
            true,
        )
        .unwrap();
    runtime.commit_driver(1).unwrap();
    let (client, server) = tokio::io::duplex(4096);
    let host = Arc::new(RecordedHost::with_session(
        &stopped_sse_event(),
        Some(runtime.clone()),
    ));
    let task = tokio::spawn(
        Native
            .server_session(info())
            .unwrap()
            .run(Box::new(server), host),
    );
    let mut client = tokio::io::BufReader::new(client);
    client
        .write_all(b"POST /messages HTTP/1.1\r\nHost: api.test\r\nContent-Length: 2\r\n\r\n{}")
        .await
        .unwrap();
    let mut line = String::new();
    loop {
        line.clear();
        assert_ne!(client.read_line(&mut line).await.unwrap(), 0);
        if line == "\r\n" {
            break;
        }
    }
    let mut first = [0; 12];
    client.read_exact(&mut first).await.unwrap();
    assert_eq!(&first, b"7\r\ndata: a\r\n");
    assert_eq!(runtime.expected().unwrap().kind, SessionStop);
    runtime.commit_driver(7).unwrap();
    let mut second = [0; 16];
    client.read_exact(&mut second).await.unwrap();
    assert_eq!(&second, b"b\r\n\n\ndata: b\n\n\r\n");
    assert_eq!(runtime.expected().unwrap().kind, SessionSourceExit);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), client.read_u8())
            .await
            .is_err()
    );
    runtime.commit_driver(10).unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), client.read(&mut [0; 1]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    task.await.unwrap().unwrap();
    assert!(runtime.complete());
}

#[test]
fn native_replay_requires_unchanged_sse_body_bytes() {
    let response = Native
        .recorded_exchange(&sse_event())
        .unwrap()
        .unwrap()
        .response;
    let mut values: std::collections::BTreeMap<_, _> = response
        .project()
        .unwrap()
        .values
        .into_iter()
        .map(|(path, value)| (path, value.bytes))
        .collect();
    values.insert(
        "/body".into(),
        Bytes::from_static(b"data: x\n\ndata: b\n\n"),
    );
    assert!(response.output(&values).is_err());
}

#[tokio::test]
async fn cancelled_http_prefix_waits_for_target_disconnect() {
    use EventKind::*;
    use std::time::Duration;
    use tokio::io::AsyncBufReadExt;

    let mut event = stopped_sse_event();
    event["outcome"] = serde_json::to_value(traffic_model::DependencyExchangeOutcome::Terminated(
        traffic_model::DependencyTermination {
            side: traffic_model::TerminationSide::Client,
            kind: traffic_model::TerminationKind::Cancelled,
            scope: traffic_model::TerminationScope::Stream,
        },
    ))
    .unwrap();
    event["response_stream"]["complete"] = true.into();
    event["response_stream"]
        .as_object_mut()
        .unwrap()
        .remove("stopped_at_source_exit");
    event["response_stream"]["chunks"]
        .as_array_mut()
        .unwrap()
        .truncate(1);
    event["response_body"]["data"] = "data: a".into();

    let runtime = SequenceRuntime::streaming_session(Some(Duration::ZERO), []);
    runtime
        .push_stream(
            [
                (1, 0, SessionSourceStart, None),
                (2, 2, Request, None),
                (3, 2, ResponseHeadersStarted, None),
                (4, 2, ResponseHeaders, Some(3)),
                (5, 2, ResponsePartStarted, None),
                (6, 2, ResponsePart, Some(5)),
                (7, 2, ClientTerminationStarted, None),
                (8, 2, ClientTermination, Some(7)),
            ]
            .into_iter()
            .map(
                |(sequence, dependency_sequence, kind, receipt_start)| StreamEvent {
                    source: SourceEvent {
                        sequence,
                        dependency_sequence,
                        offset_micros: sequence,
                        kind,
                    },
                    receipt_start,
                },
            )
            .collect(),
            true,
        )
        .unwrap();
    runtime.commit_driver(1).unwrap();
    let (client, io) = tokio::io::duplex(4096);
    let host = Arc::new(RecordedHost::with_session(&event, Some(runtime.clone())));
    let task = tokio::spawn(
        Native
            .server_session(info())
            .unwrap()
            .run(Box::new(io), host),
    );
    let mut client = tokio::io::BufReader::new(client);
    client
        .write_all(b"POST /messages HTTP/1.1\r\nHost: api.test\r\nContent-Length: 2\r\n\r\n{}")
        .await
        .unwrap();
    let mut line = String::new();
    loop {
        line.clear();
        assert_ne!(client.read_line(&mut line).await.unwrap(), 0);
        if line == "\r\n" {
            break;
        }
    }
    let mut chunk = [0; 12];
    client.read_exact(&mut chunk).await.unwrap();
    assert_eq!(&chunk, b"7\r\ndata: a\r\n");
    assert!(
        tokio::time::timeout(Duration::from_millis(20), client.read_u8())
            .await
            .is_err()
    );
    assert!(!runtime.complete());
    client.shutdown().await.unwrap();
    assert_eq!(client.read(&mut [0; 1]).await.unwrap(), 0);
    task.await.unwrap().unwrap();
    assert!(runtime.complete());
}

#[tokio::test]
async fn source_exit_before_headers_emits_no_http_response() {
    use EventKind::*;
    use std::time::Duration;

    let mut event = stopped_sse_event();
    for key in [
        "response_status",
        "response_headers",
        "response_body",
        "response_stream",
    ] {
        event.as_object_mut().unwrap().remove(key);
    }
    event["outcome"] = "no_response".into();
    assert!(Native.recorded_exchange(&event).is_err());
    let runtime = SequenceRuntime::streaming_session(Some(Duration::ZERO), []);
    runtime
        .push_stream(
            [
                (1, 0, SessionSourceStart, None),
                (2, 2, Request, None),
                (3, 0, SessionStop, None),
                (4, 0, SessionSourceExit, None),
                (5, 2, TargetStopStarted, None),
                (6, 2, TargetStop, Some(5)),
            ]
            .into_iter()
            .map(
                |(sequence, dependency_sequence, kind, receipt_start)| StreamEvent {
                    source: SourceEvent {
                        sequence,
                        dependency_sequence,
                        offset_micros: sequence,
                        kind,
                    },
                    receipt_start,
                },
            )
            .collect(),
            true,
        )
        .unwrap();
    runtime.commit_driver(1).unwrap();
    let (mut client, io) = tokio::io::duplex(4096);
    let host = Arc::new(RecordedHost::with_session(&event, Some(runtime.clone())));
    let task = tokio::spawn(
        Native
            .server_session(info())
            .unwrap()
            .run(Box::new(io), host),
    );
    client
        .write_all(b"POST /messages HTTP/1.1\r\nHost: api.test\r\nContent-Length: 2\r\n\r\n{}")
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(20), client.read_u8())
            .await
            .is_err()
    );
    assert_eq!(runtime.expected().unwrap().kind, SessionStop);
    runtime.commit_driver(3).unwrap();
    runtime.commit_driver(4).unwrap();
    assert_eq!(client.read(&mut [0; 1]).await.unwrap(), 0);
    task.await.unwrap().unwrap();
    assert!(runtime.complete());
}

#[tokio::test]
async fn native_capture_still_rejects_upgrades_before_forwarding() {
    let (mut client, io) = tokio::io::duplex(4096);
    client
        .write_all(WEBSOCKET_REQUEST.as_bytes())
        .await
        .unwrap();
    let mut reader = wire::Reader::new(Box::new(io));
    let Err(error) = reader.request().await else {
        panic!("native capture admitted Upgrade");
    };
    assert!(error.to_string().contains("HTTP upgrades"));
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
        let mut reader = wire::Reader::new(Box::new(upstream));
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
    assert_eq!(
        events[0].facts().recording_target.as_deref(),
        Some("api.test:80")
    );
    assert_eq!(
        events[0].facts().recording_upstream.as_deref(),
        Some("192.0.2.1:80")
    );
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
