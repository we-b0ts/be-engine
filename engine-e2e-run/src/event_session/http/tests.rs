use std::time::Duration;

use super::*;
use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

#[tokio::test]
async fn primary_stream_observes_source_parts_across_target_chunks() {
    let mut response = target_stream().await;
    response.part(1, b"a").await.unwrap();
    response.part(2, b"bcde").await.unwrap();
    response.end().await.unwrap();
}

#[tokio::test]
async fn primary_stream_rejects_bytes_beyond_the_recorded_end() {
    let mut response = target_stream().await;
    response.part(1, b"abcd").await.unwrap();
    let error = response.end().await.expect_err("unrecorded response byte");
    assert!(error.to_string().contains("extra primary stream data"));
}

#[tokio::test]
async fn complete_primary_response_returns_validated_identity_pairs() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let policy = directory.path().join("policy.yaml");
    std::fs::write(
        &policy,
        "format: traffic-policy/v3\njson:\n  fields:\n    /session_id: {kind: identity, formats: [{prefix: vnc-, base64url: 24}]}\n",
    )?;
    let assertions = ResponseAssertionRuntime::load(&policy)?;
    let source_id = "vnc-AAAAAAAAAAAAAAAAAAAAAAAA";
    let target_id = "vnc-BBBBBBBBBBBBBBBBBBBBBBBB";
    let request = json!({"method":"POST", "uri":"/sessions", "timestamp":Utc::now()});
    let source = json!({"session_id":source_id, "stable":"yes"}).to_string();
    for stable in ["yes", "bad"] {
        let body = json!({"session_id":target_id, "stable":stable}).to_string();
        let length = body.len();
        let wire = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {length}\r\n\r\n{body}"
        );
        let mut response = target_response(
            wire.into(),
            json!({
                "status": 200,
                "headers": {"content-type":["application/json"], "content-length":[length.to_string()]},
            }),
            4096,
        )
        .await;
        response.part(1, source.as_bytes()).await?;
        response.end().await?;
        let verified = response.verify(Verification {
            id: Uuid::new_v4(),
            request: &request,
            request_headers: &Default::default(),
            request_sent_at: Utc::now(),
            source: directory.path(),
            policy: &policy,
            assertions: &assertions,
        });
        if stable == "yes" {
            assert_eq!(
                verified?,
                vec![IdentityPair {
                    source: json!(source_id).to_string(),
                    target: json!(target_id).to_string(),
                }]
            );
        } else {
            assert!(verified.is_err());
        }
    }
    Ok(())
}

async fn target_stream() -> Response {
    target_response(
        Bytes::from_static(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n3\r\ncde\r\n0\r\n\r\n"),
        json!({"headers":{"content-type":["text/event-stream"]}, "status":200}),
        32,
    )
    .await
}

async fn target_response(wire: Bytes, expected: Value, limit: usize) -> Response {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut headers = Vec::new();
        while !headers.ends_with(b"\r\n\r\n") {
            headers.push(stream.read_u8().await.unwrap());
        }
        stream.write_all(&wire).await.unwrap();
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
    Response::begin(expected, response, limit).unwrap()
}
