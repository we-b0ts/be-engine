//! Supported multipart bodies select the same protocol comparator without policy.
use super::*;
use serde_json::json;

fn body(boundary: &str) -> String {
    ordered_body(boundary, false)
}

fn ordered_body(boundary: &str, reversed: bool) -> String {
    let first = "Content-Disposition: form-data; name=\"first\"\r\n\r\none";
    let second = "Content-Disposition: form-data; name=\"file\"; filename=\"exact.txt\"\r\nContent-Type: text/plain\r\n\r\nfile bytes";
    let parts = if reversed {
        [second, first]
    } else {
        [first, second]
    };
    format!(
        "--{boundary}\r\n{}\r\n--{boundary}\r\n{}\r\n--{boundary}--\r\n",
        parts[0], parts[1]
    )
}

async fn fixture(
    source_body: &str,
) -> (
    crate::policy::runtime::test_fixture::ManagedFixtureDirectory,
    PathBuf,
) {
    let temp = tempdir().unwrap();
    let case = temp.path().join("case-multipart");
    write_http_case(
        &case,
        "http",
        "api.example.test",
        "/upload?mode=original",
        source_body,
        "accepted",
    )
    .await;
    let path = case.join("dependencies.jsonl");
    let mut source: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    source["request_headers"] = json!({
        "content-type":["multipart/form-data; boundary=source"],
        "authorization":["Bearer exact"],
        "digest":["exact-digest"],
    });
    std::fs::write(path, format!("{source}\n")).unwrap();
    std::fs::write(
        case.join("request.json"),
        r#"{"method":"POST","uri":"/attachments/1","timestamp":"2026-07-15T04:30:00Z"}"#,
    )
    .unwrap();
    std::fs::write(case.join("expected-response.json"), "{}").unwrap();
    (temp, case)
}

async fn send(
    address: SocketAddr,
    body: String,
    content_type: &[&str],
    authorization: &str,
    digest: &str,
) -> StatusCode {
    let client = TcpStream::connect(address).await.unwrap();
    let (mut sender, connection) = http1::handshake(TokioIo::new(client)).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut request = Request::builder()
        .method("POST")
        .uri("/upload?mode=original")
        .header("host", "api.example.test")
        .header("authorization", authorization)
        .header("digest", digest);
    for value in content_type {
        request = request.header("content-type", *value);
    }
    let response = sender
        .send_request(request.body(Full::new(Bytes::from(body))).unwrap())
        .await
        .unwrap();
    let status = response.status();
    response.into_body().collect().await.unwrap();
    status
}

#[tokio::test]
async fn multipart_is_native_without_policy_and_is_consumed_once() {
    let (_temp, case) = fixture(&body("source")).await;
    let original = std::fs::read(case.join("dependencies.jsonl")).unwrap();
    let (address, runtime, task) = spawn_http_replay(&case, vec![]).await;
    let content_type = ["multipart/form-data; boundary=\"target-longer\""];
    assert_eq!(
        send(
            address,
            body("target-longer"),
            &content_type,
            "Bearer exact",
            "exact-digest"
        )
        .await,
        StatusCode::OK
    );
    assert!(!runtime.state.lock().await.snapshot_report().is_dirty());
    assert_eq!(
        send(
            address,
            body("target-longer"),
            &content_type,
            "Bearer exact",
            "exact-digest"
        )
        .await,
        StatusCode::BAD_GATEWAY
    );
    assert_eq!(
        std::fs::read(case.join("dependencies.jsonl")).unwrap(),
        original
    );
    task.abort();
}

#[tokio::test]
async fn multipart_protocol_comparison_precedes_unrelated_global_json_formats() {
    let (temp, case) = fixture(&body("source")).await;
    let policy = temp.path().join("policy.yaml");
    std::fs::write(
        &policy,
        "format: traffic-policy/v3\njson:\n  fields:\n    /id: {kind: identity, formats: [uuid]}\n",
    )
    .unwrap();
    let (address, runtime, task) =
        spawn_http_replay_with_policy(&case, vec![], Some(policy), None).await;
    assert_eq!(
        send(
            address,
            body("target"),
            &["multipart/form-data; boundary=target"],
            "Bearer exact",
            "exact-digest"
        )
        .await,
        StatusCode::OK
    );
    assert!(!runtime.state.lock().await.snapshot_report().is_dirty());
    task.abort();
}

#[tokio::test]
async fn multipart_native_selection_keeps_parts_headers_and_malformed_targets_strict() {
    let (_temp, case) = fixture(&body("source")).await;
    let normal = "multipart/form-data; boundary=target";
    let actual = body("target");
    let reversed = ordered_body("target", true);
    let cases = [
        (
            actual.replace("file bytes", "changed"),
            vec![normal],
            "Bearer exact",
            "exact-digest",
        ),
        (
            actual.replace("exact.txt", "changed.txt"),
            vec![normal],
            "Bearer exact",
            "exact-digest",
        ),
        (reversed, vec![normal], "Bearer exact", "exact-digest"),
        (
            actual.clone(),
            vec![normal],
            "Bearer changed",
            "exact-digest",
        ),
        (
            actual.clone(),
            vec![normal],
            "Bearer exact",
            "changed-digest",
        ),
        (
            actual.clone(),
            vec![normal, normal],
            "Bearer exact",
            "exact-digest",
        ),
        (
            actual.clone(),
            vec!["multipart/form-data; boundary=wrong"],
            "Bearer exact",
            "exact-digest",
        ),
        (
            actual.clone(),
            vec!["multipart/form-data; boundary=target; charset=UTF-8"],
            "Bearer exact",
            "exact-digest",
        ),
        (
            actual[..actual.len() - 5].into(),
            vec![normal],
            "Bearer exact",
            "exact-digest",
        ),
        (actual, vec![], "Bearer exact", "exact-digest"),
    ];
    for (body, headers, authorization, digest) in cases {
        let (address, runtime, task) = spawn_http_replay(&case, vec![]).await;
        assert_eq!(
            send(address, body, &headers, authorization, digest).await,
            StatusCode::BAD_GATEWAY
        );
        assert!(runtime.state.lock().await.snapshot_report().is_dirty());
        task.abort();
    }
}

#[tokio::test]
async fn unsupported_source_multipart_keeps_exact_bytes_and_header_contract() {
    let malformed = "unsupported multipart body";
    let (_temp, case) = fixture(malformed).await;
    let (address, runtime, task) = spawn_http_replay(&case, vec![]).await;
    assert_eq!(
        send(
            address,
            malformed.into(),
            &["multipart/form-data; boundary=source"],
            "Bearer exact",
            "exact-digest"
        )
        .await,
        StatusCode::OK
    );
    assert!(!runtime.state.lock().await.snapshot_report().is_dirty());
    task.abort();
    let (address, _runtime, task) = spawn_http_replay(&case, vec![]).await;
    assert_eq!(
        send(
            address,
            body("target"),
            &["multipart/form-data; boundary=target"],
            "Bearer exact",
            "exact-digest"
        )
        .await,
        StatusCode::BAD_GATEWAY
    );
    task.abort();
}
