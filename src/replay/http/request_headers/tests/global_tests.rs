use super::*;
use crate::value_contract::identities::IdentityPair;

const A: &str = "01234567-89ab-4def-8123-456789abcdef";
const B: &str = "fedcba98-7654-4321-8123-fedcba987654";
const C: &str = "11234567-89ab-4def-8123-456789abcdef";

fn primary(case: &std::path::Path) {
    std::fs::write(
        case.join("request.json"),
        json!({"method":"GET","uri":"/api","timestamp":"2019-01-01T00:00:00Z"}).to_string(),
    )
    .unwrap();
    std::fs::write(case.join("expected-response.json"), "{}").unwrap();
}

async fn request(addr: SocketAddr, headers: &[(&str, &str)], body: String) -> StatusCode {
    let stream = TcpStream::connect(addr).await.unwrap();
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream)).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut request = Request::builder()
        .method("POST")
        .uri("/business")
        .header("host", HOST);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    sender
        .send_request(request.body(Full::new(Bytes::from(body))).unwrap())
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn global_request_header_time_is_case_insensitive_strict_in_count_and_has_no_api_scope() {
    let source: chrono::DateTime<Utc> = "2020-01-01T00:00:00Z".parse().unwrap();
    let (temp, case) = fixture(
        json!({"X-Amz-Date":[source.format("%Y%m%dT%H%M%SZ").to_string()]}),
        1,
    )
    .await;
    primary(&case);
    let path = case.join("dependencies.jsonl");
    let mut record: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    record["request_started_at"] = json!(source);
    std::fs::write(&path, format!("{record}\n")).unwrap();
    let policy = temp.path().join("global-headers.yaml");
    std::fs::write(&policy, "format: traffic-policy/v3\nhttp:\n  headers:\n    x-amz-date: {kind: time, formats: [amz_date]}\n").unwrap();
    let (addr, runtime, task) =
        spawn_http_replay_with_policy(&case, vec![], Some(policy), None).await;
    let now = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    assert_eq!(
        request(
            addr,
            &[("x-amz-date", &now), ("X-AMZ-DATE", &now)],
            BODY.into()
        )
        .await,
        StatusCode::BAD_GATEWAY
    );
    assert_eq!(
        request(addr, &[("x-amz-date", &now)], BODY.into()).await,
        StatusCode::OK
    );
    let report = serde_json::to_value(runtime.state.lock().await.snapshot_report()).unwrap();
    assert!(
        report["http_request_header_mismatches"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let usage = report["replay_policy"]["global_formats"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == "global.http")
        .unwrap();
    assert_eq!(usage["validations"], 1);
    assert_eq!(usage["time_validations"], 1);
    task.abort();
}

#[tokio::test]
async fn header_and_body_identity_conflicts_leave_the_shared_case_map_uncommitted() {
    let (temp, case) = fixture(json!({"x-generated-id":[A]}), 1).await;
    primary(&case);
    let path = case.join("dependencies.jsonl");
    let mut record: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    record["request_body"] =
        json!({"encoding":"utf8","data":json!({"id":A}).to_string(),"truncated":false});
    std::fs::write(&path, format!("{record}\n")).unwrap();
    let policy = temp.path().join("global-headers.yaml");
    std::fs::write(&policy, "format: traffic-policy/v3\nhttp:\n  headers:\n    x-generated-id: {kind: identity, formats: [uuid]}\njson:\n  fields:\n    /id: {kind: identity, formats: [uuid]}\n").unwrap();
    let (addr, runtime, task) =
        spawn_http_replay_with_policy(&case, vec![], Some(policy), None).await;
    assert_eq!(
        request(addr, &[("x-generated-id", B)], json!({"id":C}).to_string()).await,
        StatusCode::BAD_GATEWAY
    );
    let pair = |target| IdentityPair {
        source: json!(A).to_string(),
        target: json!(target).to_string(),
    };
    {
        let state = runtime.state.lock().await;
        let owner = &state.replay_policy.as_ref().unwrap().request_contracts;
        assert!(!owner.has_identities("case-headers"));
        assert!(
            owner
                .preview_identity_pairs("case-headers", &[pair(C)])
                .is_ok()
        );
    }
    assert_eq!(
        request(addr, &[("X-Generated-ID", B)], json!({"id":B}).to_string()).await,
        StatusCode::OK
    );
    let state = runtime.state.lock().await;
    assert!(
        state
            .replay_policy
            .as_ref()
            .unwrap()
            .request_contracts
            .preview_identity_pairs("case-headers", &[pair(C)])
            .is_err()
    );
    assert!(state.protocols.http_events.header_mismatches.is_empty());
    task.abort();
}

#[tokio::test]
async fn response_echoes_staged_request_header_and_body_identities_atomically() {
    for integrity_header in [false, true] {
        let (temp, case) = fixture(json!({"x-generated-id":[A]}), 1).await;
        primary(&case);
        let path = case.join("dependencies.jsonl");
        let mut record: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let captured =
            |id| json!({"encoding":"utf8","data":json!({"id":id}).to_string(),"truncated":false});
        record["request_body"] = captured(A);
        record["response_body"] = captured(A);
        record["response_headers"]["x-generated-id"] = json!([A]);
        if integrity_header {
            record["response_headers"]["etag"] = json!(["\"original\""]);
        }
        record["response_headers"]["content-length"] =
            json!([json!({"id":A}).to_string().len().to_string()]);
        std::fs::write(&path, format!("{record}\n")).unwrap();
        let policy = temp.path().join("global-headers.yaml");
        std::fs::write(&policy, "format: traffic-policy/v3\nhttp:\n  headers:\n    x-generated-id: {kind: identity, formats: [uuid]}\njson:\n  fields:\n    /id: {kind: identity, formats: [uuid]}\n").unwrap();
        let (addr, runtime, task) =
            spawn_http_replay_with_policy(&case, vec![], Some(policy), None).await;
        let (mut sender, connection) =
            http1::handshake(TokioIo::new(TcpStream::connect(addr).await.unwrap()))
                .await
                .unwrap();
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let response = sender
            .send_request(
                Request::builder()
                    .method("POST")
                    .uri("/business")
                    .header("host", HOST)
                    .header("x-generated-id", B)
                    .body(Full::new(Bytes::from(json!({"id":B}).to_string())))
                    .unwrap(),
            )
            .await
            .unwrap();
        if integrity_header {
            assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
            let state = runtime.state.lock().await;
            let owner = &state.replay_policy.as_ref().unwrap().request_contracts;
            assert!(!owner.has_identities("case-headers"));
            assert!(
                owner
                    .preview_identity_pairs(
                        "case-headers",
                        &[IdentityPair {
                            source: json!(A).to_string(),
                            target: json!(C).to_string(),
                        }]
                    )
                    .is_ok()
            );
        } else {
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()["x-generated-id"], B);
            let delivered = response.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(
                serde_json::from_slice::<Value>(&delivered).unwrap(),
                json!({"id":B})
            );
            let state = runtime.state.lock().await;
            assert!(
                state
                    .replay_policy
                    .as_ref()
                    .unwrap()
                    .request_contracts
                    .knows_identity_value("case-headers", &json!(A), &json!(B))
                    .unwrap()
            );
        }
        task.abort();
    }
}
