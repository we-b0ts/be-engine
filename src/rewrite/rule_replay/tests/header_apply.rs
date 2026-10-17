use super::*;
use chrono::{Duration, Utc};
use http_body_util::{BodyExt, Full};
use hyper::{Request, body::Bytes, client::conn::http1};
use hyper_util::rt::TokioIo;
use serde_json::json;
use std::fs;

async fn request(addr: std::net::SocketAddr) {
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream)).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let response = sender
        .send_request(
            Request::builder()
                .method("POST")
                .uri("/business")
                .header("host", "api.example.test")
                .header(
                    "x-amz-date",
                    Utc::now().format("%Y%m%dT%H%M%SZ").to_string(),
                )
                .body(Full::new(Bytes::from_static(b"{}")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "recorded"
    );
}

#[tokio::test]
async fn typed_header_contract_validates_real_replay_without_rewriting_source_evidence() {
    let target = configured_target();
    let source = target
        .path()
        .join(".traffic-e2e/local/artifacts/recordings/recording");
    let case = source.join("case-headers");
    let clock = Utc::now() - Duration::days(1);
    crate::replay::write_http_case(
        &case,
        "fake_ip_http",
        "api.example.test",
        "/business",
        "{}",
        "recorded",
    )
    .await;
    let dependency = case.join("dependencies.jsonl");
    let mut record: serde_json::Value =
        serde_json::from_slice(&fs::read(&dependency).unwrap()).unwrap();
    record["request_started_at"] = json!(clock);
    record["timestamp"] = json!(clock + Duration::milliseconds(1));
    record["duration_ms"] = json!(1);
    record["request_headers"] = json!({"x-amz-date":[clock.format("%Y%m%dT%H%M%SZ").to_string()]});
    fs::write(&dependency, format!("{record}\n")).unwrap();
    fs::write(
        case.join("request.json"),
        json!({"method":"GET","uri":"/api","timestamp":clock}).to_string(),
    )
    .unwrap();
    fs::write(case.join("expected-response.json"), "{}").unwrap();
    let key = target
        .path()
        .join(".traffic-e2e/local")
        .join(crate::repository::LOCAL_ENCRYPTION_KEY_FROM_LOCAL);
    fs::create_dir_all(key.parent().unwrap()).unwrap();
    fs::write(
        key,
        crate::request_headers::generate_encryption_key().unwrap(),
    )
    .unwrap();
    let original_recording = fs::read(&dependency).unwrap();
    let (addr, runtime, task) = crate::replay::spawn_coordinator_http_replay(&case, None).await;
    request(addr).await;
    let before = crate::replay::snapshot_http_replay(&runtime).await;
    assert!(
        !before["http_request_header_mismatches"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let proof = json!({"source":"sdk.py:build_headers","fact":"Source signs this dependency request with its current UTC date"});
    let document = json!({"format":"traffic-policy/v1","rules":[{"id":"signing-time",
        "match":{"api":"GET /api","resource":{"protocol":"http","endpoint":"api.example.test:80"},"operation":"POST","path":"/business"},
        "effect":{"kind":"http_request","headers":{"x-amz-date":{"contract":{"format":"amz_date","relation":"request_window","anchor":"dependency.request_start"},"proof":proof}}},"proof":proof}]});
    crate::policy::compile_policy(&serde_json::from_value(document.clone()).unwrap()).unwrap();
    let policy = target.path().join(".traffic-e2e/policy.yaml");
    fs::write(&policy, serde_yaml::to_string(&document).unwrap()).unwrap();
    let (addr, runtime, next_task) =
        crate::replay::spawn_coordinator_http_replay(&case, Some(policy)).await;
    request(addr).await;
    let after = crate::replay::snapshot_http_replay(&runtime).await;
    assert!(
        after["http_request_header_mismatches"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(fs::read(dependency).unwrap(), original_recording);
    task.abort();
    next_task.abort();
}
