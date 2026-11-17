use super::*;
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
async fn legacy_fifty_ms_recordings_require_explicit_rerecording() {
    let error = RecordedHttpClient::new("http://127.0.0.1:1".into(), Duration::from_secs(2), 1024)
        .send_bytes(&request(true), "legacy SSE case")
        .await
        .err()
        .unwrap();
    assert!(format!("{error:#}").contains("require re-recording"));
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
