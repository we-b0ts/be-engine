use std::time::Duration;

use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

#[tokio::test]
async fn primary_stream_observes_source_parts_across_target_chunks() {
    let mut response = target_stream().await;
    response.part(1, &STANDARD.encode(b"a")).await.unwrap();
    response.part(2, &STANDARD.encode(b"bcde")).await.unwrap();
    response.end().await.unwrap();
}

#[tokio::test]
async fn primary_stream_rejects_bytes_beyond_the_recorded_end() {
    let mut response = target_stream().await;
    response.part(1, &STANDARD.encode(b"abcd")).await.unwrap();
    let error = response.end().await.expect_err("unrecorded response byte");
    assert!(error.to_string().contains("extra primary stream data"));
}

async fn target_stream() -> Response {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut headers = Vec::new();
        while !headers.ends_with(b"\r\n\r\n") {
            headers.push(stream.read_u8().await.unwrap());
        }
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n3\r\ncde\r\n0\r\n\r\n").await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let deadline = Instant::now() + Duration::from_secs(2);
    let request = Request::builder()
        .uri(format!("http://{addr}/stream"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let response = tokio::time::timeout_at(deadline, request_target(request, deadline, false))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.response.status(), hyper::StatusCode::OK);
    Response::begin(
        json!({"headers":{"content-type":["text/event-stream"]}, "status":200}),
        response,
        32,
    )
    .unwrap()
}
