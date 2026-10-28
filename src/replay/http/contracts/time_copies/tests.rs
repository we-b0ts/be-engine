use super::*;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn http_time_provenance_is_not_published_before_stream_eof() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let case = root.join(".traffic-e2e/local/recordings/case");
    std::fs::create_dir_all(&case).unwrap();
    crate::platform::encryption_key::load_or_create(root).unwrap();
    std::fs::write(
        case.join("request.json"),
        json!({"method":"POST","uri":"/api","timestamp":"1970-01-01T00:16:40Z"}).to_string(),
    )
    .unwrap();
    std::fs::write(case.join("expected-response.json"), "{}").unwrap();
    let body = "data: {\"block\":{\"timestamp\":1010000}}\n\n";
    let record = json!({"event_type":"http_exchange","id":"source-stream","scheme":"http","authority":"stream.test",
        "method":"POST","uri":"/stream","outcome":"response",
        "request_body":{"encoding":"utf8","truncated":false,"data":""},
        "request_started_at":"1970-01-01T00:16:40Z","timestamp":"1970-01-01T00:16:40.300Z","duration_ms":300,
        "response_status":200,"response_headers":{"content-type":["text/event-stream"]},
        "response_body":{"encoding":"utf8","truncated":false,"data":body},
        "response_stream":{"version":1,"headers_ms":0,"chunks":[{"at_ms":10,"start":0,"end":body.len()}],"end_ms":300,"complete":true}});
    std::fs::write(case.join("dependencies.jsonl"), record.to_string()).unwrap();
    let policy = root.join("policy.yaml");
    std::fs::write(&policy,"format: traffic-policy/v2\njson:\n  fields:\n    /block/timestamp: {kind: time, formats: [unix_milliseconds]}\n").unwrap();
    let (address, runtime, task) = crate::replay::http::tests::spawn_http_replay_with_policy(
        &case,
        vec![],
        Some(policy.clone()),
        None,
    )
    .await;
    let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
    client
        .write_all(b"POST /stream HTTP/1.1\r\nHost: stream.test\r\nContent-Length: 0\r\n\r\n")
        .await
        .unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(client.read_u8().await.unwrap());
    }
    let mut length = Vec::new();
    while !length.ends_with(b"\r\n") {
        length.push(client.read_u8().await.unwrap());
    }
    let length = usize::from_str_radix(std::str::from_utf8(&length).unwrap().trim(), 16).unwrap();
    let mut payload = vec![0; length];
    client.read_exact(&mut payload).await.unwrap();
    let mut crlf = [0; 2];
    client.read_exact(&mut crlf).await.unwrap();
    assert_eq!(&crlf, b"\r\n");
    let delivered = crate::value_codec::sse::Document::decode(&payload).unwrap();
    let target: serde_json::Value = serde_json::from_str(&delivered.events[0].data).unwrap();
    let compiled =
        crate::policy::parse_and_compile_policy(&std::fs::read_to_string(policy).unwrap()).unwrap();
    let plan = compiled.global_json.as_ref().unwrap();
    let source = json!({"block":{"timestamp":1010000}});
    let clocks = AnchorClocks {
        dependency: crate::value_contract::time::ClockPair {
            source: chrono::DateTime::from_timestamp(1000, 0),
            target: chrono::DateTime::from_timestamp(2000, 0),
        },
        ..Default::default()
    };
    let observed = crate::value_contract::time::ClockPair {
        source: chrono::DateTime::from_timestamp(1100, 0),
        target: Some(Utc::now()),
    };
    let before = runtime
        .state
        .lock()
        .await
        .replay_policy
        .as_ref()
        .unwrap()
        .request_contracts
        .delivered_time_copies("case");
    assert!(
        before
            .proofs(&source, plan, clocks, observed)
            .unwrap()
            .is_empty()
    );
    let mut tail = [0; 5];
    client.read_exact(&mut tail).await.unwrap();
    assert_eq!(&tail, b"0\r\n\r\n");
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if runtime.state.lock().await.http_events.matched_count == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let after = runtime
        .state
        .lock()
        .await
        .replay_policy
        .as_ref()
        .unwrap()
        .request_contracts
        .delivered_time_copies("case");
    let observed = crate::value_contract::time::ClockPair {
        target: Some(Utc::now()),
        ..observed
    };
    let proofs = after.proofs(&source, plan, clocks, observed).unwrap();
    assert!(!proofs.is_empty());
    assert!(
        crate::value_contract::global::compare_logical_with_time_copies(
            &source,
            &target,
            plan,
            &[],
            clocks,
            &proofs
        )
        .unwrap()
        .passed()
    );
    task.abort();
}
