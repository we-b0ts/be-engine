use super::*;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod cancellation;

fn dependency() -> Value {
    serde_json::json!({
        "event_type":"http_exchange", "scheme":"http", "method":"POST", "uri":"/stream", "authority":"stream.test",
        "request_body":{"encoding":"utf8","truncated":false,"data":""},
        "response_status":200,"response_headers":{"content-type":["text/event-stream"]},
        "response_body":{"encoding":"utf8","truncated":false,"data":"onetwo"},
        "response_stream":{"version":1,"headers_ms":80,"chunks":[{"at_ms":150,"start":0,"end":3},{"at_ms":400,"start":3,"end":6}],"end_ms":600,"complete":true},
        "error":null
    })
}

async fn line(client: &mut TcpStream) -> Vec<u8> {
    let mut line = Vec::new();
    while !line.ends_with(b"\r\n") {
        line.push(client.read_u8().await.unwrap());
    }
    line
}

async fn chunk(client: &mut TcpStream) -> Vec<u8> {
    let length =
        usize::from_str_radix(std::str::from_utf8(&line(client).await).unwrap().trim(), 16)
            .unwrap();
    let mut bytes = vec![0; length];
    client.read_exact(&mut bytes).await.unwrap();
    assert_eq!(line(client).await, b"\r\n");
    bytes
}

#[tokio::test]
async fn dependency_stream_preserves_header_chunk_eof_delays_and_consumes_at_eof() {
    tokio::time::timeout(Duration::from_secs(4), exercise(false))
        .await
        .unwrap();
}

#[tokio::test]
async fn dependency_stream_target_cancellation_is_dirty_and_not_consumed() {
    tokio::time::timeout(Duration::from_secs(4), exercise(true))
        .await
        .unwrap();
}

async fn exercise(cancel: bool) {
    let temp = tempfile::tempdir().unwrap();
    let case = temp.path().join("stream-case");
    tokio::fs::create_dir_all(&case).await.unwrap();
    tokio::fs::write(case.join("dependencies.jsonl"), dependency().to_string())
        .await
        .unwrap();
    let (address, runtime, task) =
        crate::replay::http::tests::spawn_http_replay(&case, Vec::new()).await;
    let mut client = TcpStream::connect(address).await.unwrap();
    let started = tokio::time::Instant::now();
    client.write_all(b"POST /stream HTTP/1.1\r\nHost: stream.test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
    let mut byte = [0];
    assert!(
        tokio::time::timeout(Duration::from_millis(30), client.read(&mut byte))
            .await
            .is_err()
    );
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        headers.push(client.read_u8().await.unwrap());
    }
    assert!(started.elapsed() >= Duration::from_millis(60));
    assert!(
        !String::from_utf8(headers)
            .unwrap()
            .to_lowercase()
            .contains("content-length:")
    );
    assert_eq!(chunk(&mut client).await, b"one");
    assert!(started.elapsed() >= Duration::from_millis(130));
    {
        let state = runtime.state.lock().await;
        assert_eq!(state.http_events.matched_count, 0);
        assert_eq!(
            state.http_exchanges[0].status,
            super::super::super::ReplayExchangeStatus::Responding
        );
    }
    if cancel {
        crate::dependency::termination::ConnectionControl::new(&client)
            .unwrap()
            .reset()
            .unwrap();
        drop(client);
    } else {
        assert!(
            tokio::time::timeout(Duration::from_millis(50), client.read(&mut byte))
                .await
                .is_err()
        );
        assert_eq!(chunk(&mut client).await, b"two");
        assert!(started.elapsed() >= Duration::from_millis(370));
        assert!(chunk(&mut client).await.is_empty());
        assert!(started.elapsed() >= Duration::from_millis(570));
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let state = runtime.state.lock().await;
            if state.http_exchanges[0].status
                != super::super::super::ReplayExchangeStatus::Responding
            {
                break;
            }
            drop(state);
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let state = runtime.state.lock().await;
    if cancel {
        assert_eq!(state.http_events.matched_count, 0);
        assert_eq!(
            state.http_exchanges[0].status,
            super::super::super::ReplayExchangeStatus::Failed
        );
        assert!(state.http_events.unsupported[0].reason.contains("dropped"));
    } else {
        assert_eq!(state.http_events.matched_count, 1);
        assert!(state.http_exchanges[0].status.is_consumed());
        assert!(state.http_events.unsupported.is_empty());
    }
    task.abort();
}

#[test]
fn incomplete_stream_evidence_and_payload_or_timing_tampering_are_rejected() {
    let original = dependency()["response_stream"].clone();
    for (field, value) in [
        ("complete", Value::Bool(false)),
        ("version", Value::from(3)),
        ("end_ms", Value::from(100)),
    ] {
        let mut invalid = original.clone();
        invalid[field] = value;
        let stream: ResponseStream = serde_json::from_value(invalid).unwrap();
        assert!(stream.validate(6).is_err());
    }
    let mut invalid = original.clone();
    invalid["chunks"][1]["start"] = Value::from(1);
    assert!(
        serde_json::from_value::<ResponseStream>(invalid)
            .unwrap()
            .validate(6)
            .is_err()
    );
    assert!(
        serde_json::from_value::<ResponseStream>(original)
            .unwrap()
            .validate(7)
            .is_err()
    );
}

#[test]
fn old_stream_dependencies_require_rerecording_instead_of_full_body_delivery() {
    let mut value = dependency();
    value.as_object_mut().unwrap().remove("response_stream");
    let record: RecordedHttpExchange = serde_json::from_value(value).unwrap();
    let error = register_http_exchange(
        record,
        ReplaySource::Case,
        Some("case"),
        &mut Vec::new(),
        &mut BTreeMap::new(),
    )
    .unwrap_err();
    assert!(error.to_string().contains("re-record"));
}
