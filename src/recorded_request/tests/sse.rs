use super::*;
use crate::http::sse::SseStreamEnd;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn request(policy: bool) -> Vec<u8> {
    let mut request = serde_json::json!({
        "method": "GET", "uri": "/sse", "headers": {},
        "body": {"encoding": "utf8", "data": "", "truncated": false}
    });
    if policy {
        request["sse_observation"] = serde_json::json!({"window_ms": 50});
    }
    serde_json::to_vec(&request).unwrap()
}

#[tokio::test]
async fn observes_data_and_closes_an_open_target_after_headers_plus_window() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buffer = [0; 1024];
        assert!(stream.read(&mut buffer).await.unwrap() > 0);
        tokio::time::sleep(Duration::from_millis(100)).await;
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\nD\r\ndata: ready\n\n\r\n").await.unwrap();
        // An unfinished HTTP/1 response must be cancelled at the observation deadline.
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buffer))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    });
    let started = tokio::time::Instant::now();
    let response =
        RecordedHttpClient::new(format!("http://{address}"), Duration::from_secs(2), 1024)
            .send_bytes(&request(true), "in-memory SSE request")
            .await
            .unwrap();
    assert_eq!(response.body.as_ref(), b"data: ready\n\n");
    assert_eq!(
        response.sse_observation.unwrap().end,
        SseStreamEnd::ObservationWindowElapsed
    );
    assert!(started.elapsed() >= Duration::from_millis(150));
    server.await.unwrap();
}

#[tokio::test]
async fn target_eof_is_recorded_even_with_an_empty_body() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buffer = [0; 1024];
        assert!(stream.read(&mut buffer).await.unwrap() > 0);
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
    });
    let response =
        RecordedHttpClient::new(format!("http://{address}"), Duration::from_secs(2), 1024)
            .send_bytes(&request(true), "in-memory SSE request")
            .await
            .unwrap();
    assert!(response.body.is_empty());
    assert_eq!(
        response.sse_observation.unwrap().end,
        SseStreamEnd::ServerEof
    );
    server.await.unwrap();
}

#[tokio::test]
async fn malformed_stream_and_body_limit_are_errors_instead_of_window_completion() {
    for (response, limit) in [
        (b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\nD\r\npartial".as_slice(), 1024),
        (b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 13\r\n\r\ndata: ready\n\n".as_slice(), 5),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0; 1024];
            assert!(stream.read(&mut buffer).await.unwrap() > 0);
            stream.write_all(response).await.unwrap();
        });
        assert!(RecordedHttpClient::new(format!("http://{address}"), Duration::from_secs(2), limit)
            .send_bytes(&request(true), "in-memory SSE request").await.is_err());
        server.await.unwrap();
    }
}

#[tokio::test]
async fn ordinary_http_still_reads_the_full_body_beyond_fifty_ms() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buffer = [0; 1024];
        assert!(stream.read(&mut buffer).await.unwrap() > 0);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        stream.write_all(b"hello").await.unwrap();
    });
    let response =
        RecordedHttpClient::new(format!("http://{address}"), Duration::from_secs(2), 1024)
            .send_bytes(&request(false), "ordinary HTTP request")
            .await
            .unwrap();
    assert_eq!(response.body.as_ref(), b"hello");
    assert!(response.sse_observation.is_none());
    server.await.unwrap();
}
