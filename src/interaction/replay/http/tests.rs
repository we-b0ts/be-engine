use super::*;
use crate::interaction::{
    model::{InputAction, Protocol, WireMessage},
    policy::{InteractionPolicy, StreamTerminal},
};
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
};

fn policy() -> InteractionPolicy {
    InteractionPolicy {
        business_idle_ms: 30,
        max_duration_ms: 2_000,
        cleanup_timeout_ms: 200,
        request_timeout_ms: 300,
        input_gap_ms: 1,
        stream_terminal: Some(StreamTerminal::Text {
            value: "[DONE]".into(),
        }),
        ..InteractionPolicy::default()
    }
}

#[tokio::test]
async fn terminal_stream_waits_for_business_idle_while_sse_comments_continue() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buffer = [0; 2048];
        read_request_head(&mut socket).await;
        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n").await.unwrap();
        for data in ["data: hello\n\n", "data: [DONE]\n\n"] {
            socket
                .write_all(format!("{:X}\r\n{data}\r\n", data.len()).as_bytes())
                .await
                .unwrap();
        }
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            tokio::select! {
                read = socket.read(&mut buffer) => { if read.unwrap_or(0) == 0 { break; } },
                _ = tokio::time::sleep(Duration::from_millis(5)) => {
                    if socket.write_all(b"8\r\n: ping\n\n\r\n").await.is_err() { break; }
                },
                _ = sleep_until(deadline) => panic!("Target stream was not actively cancelled"),
            }
        }
    });
    let transcript = InputTranscript::new(Protocol::Sse, policy());
    let request = Request::builder()
        .uri(format!("http://{address}/events"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let client = Client::builder(TokioExecutor::new()).build_http();
    let actual = execute(
        &client,
        request,
        &transcript,
        Duration::from_secs(1),
        1_000_000,
    )
    .await
    .unwrap();
    assert!(actual.observation.end.clean);
    assert_eq!(actual.observation.end.reason, EndReason::BusinessIdle);
    assert!(actual.observation.end.offset_ms >= 30);
    assert_eq!(
        actual
            .observation
            .events
            .iter()
            .filter(|event| !event.heartbeat)
            .count(),
        2
    );
    server.await.unwrap();
}

#[tokio::test]
async fn pending_stream_times_out_instead_of_passing_after_idle() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buffer = [0; 2048];
        read_request_head(&mut socket).await;
        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\nD\r\ndata: hello\n\n\r\n").await.unwrap();
        assert_eq!(socket.read(&mut buffer).await.unwrap(), 0);
    });
    let transcript = InputTranscript::new(Protocol::Sse, policy());
    let request = Request::builder()
        .uri(format!("http://{address}/events"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let client = Client::builder(TokioExecutor::new()).build_http();
    let actual = execute(
        &client,
        request,
        &transcript,
        Duration::from_secs(1),
        1_000_000,
    )
    .await
    .unwrap();
    assert_eq!(actual.observation.end.reason, EndReason::RequestTimeout);
    assert!(!actual.observation.end.clean);
    assert_eq!(actual.observation.end.pending, vec![0]);
    server.await.unwrap();
}

#[tokio::test]
async fn a_partial_message_after_terminal_does_not_pass_when_business_idle_expires() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buffer = [0; 2048];
        read_request_head(&mut socket).await;
        let data = "data: [DONE]\n\ndata: uncompleted";
        socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n{:X}\r\n{data}\r\n", data.len()).as_bytes()).await.unwrap();
        assert_eq!(socket.read(&mut buffer).await.unwrap(), 0);
    });
    let transcript = InputTranscript::new(Protocol::Sse, policy());
    let request = Request::builder()
        .uri(format!("http://{address}/events"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let client = Client::builder(TokioExecutor::new()).build_http();
    let error = execute(
        &client,
        request,
        &transcript,
        Duration::from_secs(1),
        1_000_000,
    )
    .await
    .err()
    .unwrap();
    assert!(format!("{error:#}").contains("partial message"));
    server.await.unwrap();
}

async fn read_request_head(socket: &mut tokio::net::TcpStream) {
    let mut head = Vec::new();
    let mut buffer = [0; 1024];
    loop {
        let count = socket.read(&mut buffer).await.unwrap();
        assert!(count > 0, "request ended before its headers");
        head.extend_from_slice(&buffer[..count]);
        if head.windows(4).any(|boundary| boundary == b"\r\n\r\n") {
            break;
        }
        assert!(
            head.len() <= 8192,
            "test request headers exceed the fixture limit"
        );
    }
}

#[tokio::test]
async fn a_json_response_to_sse_input_cannot_be_observed_as_empty_success() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        read_request_head(&mut socket).await;
        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 7\r\nConnection: close\r\n\r\n{\"x\":1}").await.unwrap();
    });
    let client = Client::builder(TokioExecutor::new()).build_http();
    let request = Request::builder()
        .uri(format!("http://{address}/events"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let error = execute(
        &client,
        request,
        &InputTranscript::new(Protocol::Sse, policy()),
        Duration::from_secs(1),
        1_000_000,
    )
    .await
    .err()
    .unwrap();
    assert!(format!("{error:#}").contains("protocol differs"));
    server.await.unwrap();
}

fn close_action(offset_ms: u64) -> InputAction {
    InputAction {
        sequence: 1,
        offset_ms,
        after: Vec::new(),
        compressible_gap: false,
        gap_start_ms: None,
        ack_ref: None,
        action: InputActionKind::Close {
            code: None,
            reason: String::new(),
        },
    }
}

async fn observe_client_close(
    data: &'static str,
    offset_ms: u64,
    business_idle_ms: u64,
    server_eof: bool,
) -> Result<ReplayResponse> {
    observe_close_action(
        data,
        close_action(offset_ms),
        business_idle_ms,
        server_eof,
        0,
    )
    .await
}

async fn observe_close_action(
    data: &'static str,
    action: InputAction,
    business_idle_ms: u64,
    server_eof: bool,
    headers_delay_ms: u64,
) -> Result<ReplayResponse> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        read_request_head(&mut socket).await;
        tokio::time::sleep(Duration::from_millis(headers_delay_ms)).await;
        let tail = if server_eof { "0\r\n\r\n" } else { "" };
        socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:X}\r\n{data}\r\n{tail}", data.len()).as_bytes()).await.unwrap();
        if !server_eof {
            let mut buffer = [0; 1];
            let ended = tokio::time::timeout(Duration::from_secs(1), socket.read(&mut buffer))
                .await
                .expect("Target body was not cancelled");
            match ended {
                Ok(0) => {}
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
                other => panic!("Target stream did not end: {other:?}"),
            }
        }
    });
    let mut policy = policy();
    policy.business_idle_ms = business_idle_ms;
    let mut transcript = InputTranscript::new(Protocol::Sse, policy);
    transcript.actions.push(action);
    let client = Client::builder(TokioExecutor::new()).build_http();
    let request = Request::builder()
        .uri(format!("http://{address}/events"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let result = execute(
        &client,
        request,
        &transcript,
        Duration::from_secs(1),
        1_000_000,
    )
    .await;
    server.await.unwrap();
    result
}

#[tokio::test]
async fn completed_stream_replays_client_close_at_its_original_absolute_time() {
    let actual = observe_client_close("data: [DONE]\n\n", 80, 300, false)
        .await
        .unwrap();
    let end = actual.observation.end;
    assert_eq!(end.reason, EndReason::ClientClose);
    assert_eq!(
        end.close,
        Some(CloseObservation {
            code: None,
            reason: String::new()
        })
    );
    assert!(end.clean);
    assert!(end.pending.is_empty());
    assert!(
        end.offset_ms >= 80,
        "client close must not use the 1 ms input-gap compression"
    );
    assert_eq!(actual.observation.events.len(), 1);
}

#[tokio::test]
async fn same_tick_source_close_waits_for_independent_target_completion() {
    let mut action = close_action(0);
    action.after = vec![0];
    action.gap_start_ms = Some(0);
    let actual = observe_close_action("data: [DONE]\n\n", action, 300, false, 40)
        .await
        .unwrap();
    assert_eq!(actual.observation.end.reason, EndReason::ClientClose);
    assert!(actual.observation.end.clean);
    assert!(actual.observation.end.offset_ms >= 40);
    assert_eq!(actual.observation.events.len(), 1);
    assert_eq!(actual.observation.end.close.as_ref().unwrap().code, None);
}

#[tokio::test]
async fn completion_bound_client_close_preserves_the_entire_source_gap() {
    let mut action = close_action(80);
    action.after = vec![0];
    action.gap_start_ms = Some(30);
    let actual = observe_close_action("data: [DONE]\n\n", action, 300, false, 40)
        .await
        .unwrap();
    assert_eq!(actual.observation.end.reason, EndReason::ClientClose);
    assert!(actual.observation.end.clean);
    assert!(actual.observation.end.offset_ms >= 90);
    assert!(actual.observation.end.offset_ms - actual.observation.events[0].offset_ms >= 50);
}

#[tokio::test]
async fn target_eof_during_completion_bound_close_gap_keeps_server_eof() {
    let mut action = close_action(80);
    action.after = vec![0];
    action.gap_start_ms = Some(30);
    let actual = observe_close_action("data: [DONE]\n\n", action, 300, true, 40)
        .await
        .unwrap();
    assert_eq!(actual.observation.end.reason, EndReason::ServerEof);
    assert!(actual.observation.end.clean);
    assert!(actual.observation.end.close.is_none());
}

#[tokio::test]
async fn completion_bound_close_does_not_clear_unfinished_target_business() {
    let mut action = close_action(0);
    action.after = vec![0];
    action.gap_start_ms = Some(0);
    let actual = observe_close_action("data: working\n\n", action, 300, false, 40)
        .await
        .unwrap();
    assert_eq!(actual.observation.end.reason, EndReason::RequestTimeout);
    assert!(!actual.observation.end.clean);
    assert_eq!(actual.observation.end.pending, vec![0]);
    assert!(actual.observation.end.close.is_none());
}

#[tokio::test]
async fn engine_idle_during_completion_bound_close_gap_keeps_business_idle() {
    let mut action = close_action(80);
    action.after = vec![0];
    action.gap_start_ms = Some(30);
    let actual = observe_close_action("data: [DONE]\n\n", action, 30, false, 40)
        .await
        .unwrap();
    assert_eq!(actual.observation.end.reason, EndReason::BusinessIdle);
    assert!(actual.observation.end.clean);
    assert!(actual.observation.end.close.is_none());
}

#[tokio::test]
async fn target_eof_before_recorded_client_close_keeps_its_independent_end_reason() {
    let actual = observe_client_close("data: [DONE]\n\n", 150, 300, true)
        .await
        .unwrap();
    assert_eq!(actual.observation.end.reason, EndReason::ServerEof);
    assert!(actual.observation.end.clean);
    assert!(actual.observation.end.close.is_none());
}

#[tokio::test]
async fn engine_idle_before_recorded_client_close_is_still_business_idle() {
    let actual = observe_client_close("data: [DONE]\n\n", 150, 30, false)
        .await
        .unwrap();
    assert_eq!(actual.observation.end.reason, EndReason::BusinessIdle);
    assert!(actual.observation.end.clean);
    assert!(actual.observation.end.close.is_none());
}

#[tokio::test]
async fn client_close_with_unfinished_business_records_a_complete_cancellation() {
    let actual = observe_client_close("data: working\n\n", 50, 300, false)
        .await
        .unwrap();
    assert_eq!(actual.observation.end.reason, EndReason::ClientClose);
    assert!(actual.observation.end.clean);
    assert_eq!(actual.observation.end.pending, vec![0]);
    assert_eq!(actual.observation.end.close.as_ref().unwrap().code, None);
}

#[tokio::test]
async fn client_close_preserves_exact_partial_message_after_done() {
    let actual = observe_client_close("data: [DONE]\n\ndata: unfinished", 50, 300, false)
        .await
        .unwrap();
    assert!(actual.observation.end.clean);
    assert_eq!(actual.observation.end.reason, EndReason::ClientClose);
    assert!(actual.observation.end.pending.is_empty());
    assert_eq!(
        actual
            .observation
            .end
            .partial_message
            .unwrap()
            .decode()
            .unwrap(),
        b"data: unfinished"
    );
}

#[tokio::test]
async fn client_close_deadline_also_bounds_slow_target_response_headers() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        read_request_head(&mut socket).await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        let _ = socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 14\r\nConnection: close\r\n\r\ndata: [DONE]\n\n").await;
    });
    let mut transcript = InputTranscript::new(Protocol::Sse, policy());
    transcript.actions.push(close_action(30));
    let client = Client::builder(TokioExecutor::new()).build_http();
    let request = Request::builder()
        .uri(format!("http://{address}/events"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let result = execute(
        &client,
        request,
        &transcript,
        Duration::from_secs(1),
        1_000_000,
    )
    .await;
    assert!(
        result.is_err(),
        "headers after the client close cannot produce successful evidence"
    );
    assert!(
        !server.is_finished(),
        "client close must not wait for late Target headers"
    );
    server.await.unwrap();
}

#[test]
fn http_client_close_rejects_socket_inputs_or_transformed_timing() {
    let mut transcript = InputTranscript::new(Protocol::Sse, policy());
    let mut action = close_action(50);
    action.action = InputActionKind::Message {
        message: WireMessage::text("done"),
    };
    transcript.actions = vec![action];
    assert!(client_close_timing(&transcript).is_err());
    let mut action = close_action(50);
    action.action = InputActionKind::Upgrade {
        uri: "/socket.io".into(),
        headers: Default::default(),
    };
    transcript.actions = vec![action];
    assert!(client_close_timing(&transcript).is_err());
    let mut action = close_action(50);
    action.compressible_gap = true;
    transcript.actions = vec![action];
    assert!(client_close_timing(&transcript).is_err());
    let mut action = close_action(50);
    action.after.push(0);
    transcript.actions = vec![action];
    assert!(client_close_timing(&transcript).is_err());
    let mut action = close_action(50);
    action.after = vec![0];
    action.gap_start_ms = Some(51);
    transcript.actions = vec![action];
    assert!(client_close_timing(&transcript).is_err());
    transcript.actions = vec![close_action(50), close_action(60)];
    assert!(client_close_timing(&transcript).is_err());
}

#[tokio::test]
async fn subscription_input_cannot_bypass_post_response_completion() {
    let mut profile = policy();
    profile.stream_terminal = None;
    let mut input = InputTranscript::new(Protocol::Sse, profile);
    input.http_stream_mode = crate::interaction::model::HttpStreamMode::Subscription;
    let client = Client::builder(TokioExecutor::new()).build_http();
    let request = Request::builder()
        .method("POST")
        .uri("http://127.0.0.1:1/events")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let error = execute(&client, request, &input, Duration::from_secs(1), 1_024)
        .await
        .err()
        .unwrap();
    assert!(error.to_string().contains("requires a GET request"));
}
