//! Accept offers do not determine the protocol of the actual Source response.

use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

const INPUT: &str = r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}"#;

async fn ordinary_response(
    accept: &'static str,
    status: &'static str,
    content_type: Option<&'static str>,
    body: &'static str,
) {
    let temp = tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap();
    let state = AppState::new(config(temp.path(), upstream)).await.unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let source_calls = calls.clone();
    let (stop, mut stopped) = oneshot::channel();
    let source = tokio::spawn(async move {
        loop {
            let (mut stream, _) = tokio::select! {
                accepted = listener.accept() => accepted.unwrap(),
                _ = &mut stopped => break,
            };
            let call = source_calls.fetch_add(1, Ordering::SeqCst);
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(stream.read_u8().await.unwrap());
            }
            let head = String::from_utf8(head).unwrap();
            assert!(head.starts_with("POST /mcp HTTP/1.1\r\n"));
            assert!(
                head.to_ascii_lowercase()
                    .contains(&format!("accept: {accept}\r\n"))
            );
            if call == 0 {
                assert!(
                    head.to_ascii_lowercase()
                        .contains("accept-encoding: identity\r\n")
                );
            }
            let mut input = vec![0; INPUT.len()];
            stream.read_exact(&mut input).await.unwrap();
            assert_eq!(input, INPUT.as_bytes());
            let content =
                content_type.map_or(String::new(), |value| format!("Content-Type: {value}\r\n"));
            stream.write_all(format!(
                "HTTP/1.1 {status}\r\n{content}Content-Length: {}\r\nX-Source: original\r\nConnection: close\r\n\r\n{body}",
                body.len()
            ).as_bytes()).await.unwrap();
        }
    });
    let (address, recording) = gateway(state.clone()).await;
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let response = client
        .request(
            Request::builder()
                .method("POST")
                .uri(format!("http://{address}/mcp"))
                .header("accept", accept)
                .header("accept-encoding", "gzip")
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from_static(INPUT.as_bytes())))
                .unwrap(),
        )
        .await
        .unwrap();
    let status_code: u16 = status[..3].parse().unwrap();
    assert_eq!(response.status().as_u16(), status_code);
    assert_eq!(response.headers()["x-source"], "original");
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .map(|value| value.to_str().unwrap()),
        content_type
    );
    assert_eq!(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .as_ref(),
        body.as_bytes()
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "POST must execute exactly once"
    );
    let case = published(&state).await;
    let input: Value = serde_json::from_slice(
        &crate::request_headers::load_request_file(&case.join("request.json")).unwrap(),
    )
    .unwrap();
    let expected: Value =
        serde_json::from_slice(&std::fs::read(case.join("expected-response.json")).unwrap())
            .unwrap();
    assert!(input.get("interaction").is_none());
    assert!(expected.get("interaction").is_none());
    assert_eq!(input["body"]["data"], INPUT);
    assert_eq!(expected["status"], status_code);
    assert_eq!(expected["body"]["data"], body);
    assert_eq!(expected["body"]["truncated"], false);
    assert_eq!(expected["headers"]["x-source"][0], "original");
    assert!(!state.recorder().run_dir.join("errors.jsonl").exists());
    assert_eq!(state.recording_lifecycle_phase(), "running");
    assert!(!*state.inner.interactions.source_stop.borrow());

    let replay = crate::recorded_request::RecordedHttpClient::new(
        format!("http://{upstream}"),
        Duration::from_secs(1),
        1024,
    )
    .send(&case.join("request.json"))
    .await
    .unwrap();
    assert_eq!(replay.status.as_u16(), status_code);
    assert_eq!(replay.body.as_ref(), body.as_bytes());
    assert!(replay.interaction.is_none());
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "replay sends one fresh request"
    );
    stop.send(()).unwrap();
    source.await.unwrap();
    recording.abort();
}

#[tokio::test]
async fn mixed_accept_json_response_records_and_replays_ordinary_http() {
    timeout(
        Duration::from_secs(5),
        ordinary_response(
            "application/json, text/event-stream",
            "200 OK",
            Some("application/json"),
            r#"{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":"2025-03-26"}}"#,
        ),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn stream_offers_preserve_json_errors_and_empty_responses() {
    for accept in [
        "application/json, text/event-stream",
        "text/event-stream",
        "application/x-ndjson",
    ] {
        timeout(
            Duration::from_secs(5),
            ordinary_response(
                accept,
                "400 Bad Request",
                Some("application/json"),
                r#"{"error":"invalid request"}"#,
            ),
        )
        .await
        .unwrap();
        timeout(
            Duration::from_secs(5),
            ordinary_response(accept, "204 No Content", None, ""),
        )
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn disabled_stream_recording_keeps_stream_offers_on_predispatch_fallback() {
    let temp = tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut settings = config(temp.path(), listener.local_addr().unwrap());
    settings.http_gateway.record_streaming = false;
    let state = AppState::new(settings).await.unwrap();
    let (address, recording) = gateway(state.clone()).await;
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    for accept in [
        "application/json, text/event-stream",
        "application/json, application/x-ndjson",
        "application/ndjson",
    ] {
        let response = timeout(
            Duration::from_secs(2),
            client.request(
                Request::builder()
                    .method("POST")
                    .uri(format!("http://{address}/mcp"))
                    .header("accept", accept)
                    .body(Full::new(Bytes::from_static(INPUT.as_bytes())))
                    .unwrap(),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response.status(), hyper::StatusCode::OK);
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "busy"
        );
    }
    let mut cases = Vec::new();
    find_cases(&state.recorder().run_dir.join("apis"), &mut cases);
    assert!(cases.is_empty());
    assert!(!state.recorder().run_dir.join("errors.jsonl").exists());
    assert_eq!(state.recording_lifecycle_phase(), "running");
    recording.abort();
}
