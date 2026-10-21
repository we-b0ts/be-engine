use super::super::tests::{spawn_http_replay_with_policy, write_http_case, write_http_dependency};
use super::*;
use crate::replay::control::{ReplayControlRequest, end_case, handle_control_request};
use crate::replay::policy::test_fixture::ManagedFixtureDirectory as TempDir;
use crate::replay::report::{build_dependency_evidence, report_has_case_dirty_events};
use hyper::client::conn::http1;
use serde_json::json;
use std::path::PathBuf;
mod client_metadata;
mod timestamp_tests;

const HOST: &str = "api.example.test";
const BODY: &str = "{\"input\":1}";

async fn fixture(headers: Value, count: usize) -> (TempDir, PathBuf) {
    let temp = crate::replay::policy::test_fixture::managed_tempdir().unwrap();
    let case = temp.path().join("case-headers");
    write_http_case(
        &case,
        "fake_ip_http",
        HOST,
        "/business",
        BODY,
        "recorded-response",
    )
    .await;
    let path = case.join("dependencies.jsonl");
    let mut record: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    record["request_headers"] = headers;
    std::fs::write(path, format!("{record}\n").repeat(count)).unwrap();
    (temp, case)
}

async fn send(addr: SocketAddr, uri: &str, headers: Value) {
    let stream = TcpStream::connect(addr).await.unwrap();
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream)).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut request = Request::builder()
        .method("POST")
        .uri(uri)
        .header("host", HOST);
    for (name, values) in headers.as_object().unwrap() {
        for value in values.as_array().unwrap() {
            request = request.header(name, value.as_str().unwrap());
        }
    }
    let response = sender
        .send_request(
            request
                .body(Full::new(Bytes::from_static(BODY.as_bytes())))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "recorded-response"
    );
}

#[tokio::test]
async fn business_header_differences_return_the_response_and_fail_dirty_gates() {
    let (_temp, case) = fixture(json!({
        "X-Wegent-User-Id": ["source-user"], "tenant-id": ["source-tenant"], "required-context": ["required"],
    }), 1).await;
    let (addr, runtime, task) = spawn_http_replay_with_policy(&case, vec![], None, None).await;
    send(addr, "/business", json!({
        "x-wegent-user-id": ["target-user"], "tenant-id": ["target-tenant"], "extra-context": ["extra"],
    })).await;
    {
        let state = runtime.state.lock().await;
        let report = state.snapshot_report();
        assert!(report.is_dirty());
        assert!(state.http_case_is_dirty("case-headers"));
        assert!(report.unmatched_http_requests.is_empty());
        assert!(report.unused_case_http_exchanges.is_empty());
        assert_eq!(report.matched_http_exchange_count, 1);
        let value = serde_json::to_value(report).unwrap();
        assert!(report_has_case_dirty_events(&value));
        let evidence = build_dependency_evidence(&value);
        assert_eq!(evidence.clusters.len(), 4);
        let user = evidence
            .clusters
            .iter()
            .find(|cluster| cluster.reason.ends_with("x-wegent-user-id"))
            .unwrap();
        let diff = &user.representative.as_ref().unwrap().difference;
        assert_eq!(diff.kind, "header_value_mismatch");
        assert_eq!(
            diff.expected.signature.as_ref().unwrap()["values"],
            json!(["source-user"])
        );
        assert_eq!(
            diff.actual.signature.as_ref().unwrap()["values"],
            json!(["target-user"])
        );
        let missing = evidence
            .clusters
            .iter()
            .find(|c| c.reason.ends_with("required-context"))
            .unwrap();
        assert_eq!(
            missing
                .representative
                .as_ref()
                .unwrap()
                .difference
                .actual
                .presence,
            "missing"
        );
        let added = evidence
            .clusters
            .iter()
            .find(|c| c.reason.ends_with("extra-context"))
            .unwrap();
        assert_eq!(
            added
                .representative
                .as_ref()
                .unwrap()
                .difference
                .expected
                .presence,
            "missing"
        );
    }
    let end = end_case(
        &ReplayControlRequest {
            command: "end".into(),
            case_id: Some("case-headers".into()),
            fail_on_dirty: true,
            fail_on_incomplete: false,
        },
        runtime.state.clone(),
    )
    .await;
    assert_eq!(end["dirty"], true);
    assert_eq!(end["ok"], false);
    let (finalize, _) = handle_control_request(
        ReplayControlRequest {
            command: "finalize".into(),
            case_id: None,
            fail_on_dirty: true,
            fail_on_incomplete: true,
        },
        runtime.state.clone(),
        None,
        None,
    )
    .await;
    assert_eq!(finalize["complete"], true);
    assert_eq!(finalize["dirty"], true);
    assert_eq!(finalize["ok"], false);
    task.abort();
}

#[tokio::test]
async fn excludes_transport_tracing_and_engine_metadata_but_normalizes_business_names() {
    let (_temp, case) = fixture(json!({
        "Tenant-Id": [" tenant "], "connection": ["keep-alive, source-hop"], "source-hop": ["source"],
        "content-length": ["999"], "transfer-encoding": ["chunked"], "user-agent": ["source-sdk"],
        "x-recorder-fake-ip": ["198.19.0.1:80"], "traceparent": ["source-trace"],
        "tracestate": ["source-state"], "x-b3-traceid": ["source-trace"], "x-request-id": ["source-id"],
    }), 1).await;
    let (addr, runtime, task) = spawn_http_replay_with_policy(&case, vec![], None, None).await;
    send(
        addr,
        "/business",
        json!({
            "tenant-id": ["tenant"], "user-agent": ["target-sdk"], "traceparent": ["target-trace"],
            "x-request-id": ["target-id"], "x-recorder-upstream-addr": ["new-address"],
            "connection": ["target-hop"], "target-hop": ["target"],
        }),
    )
    .await;
    let state = runtime.state.lock().await;
    assert!(!state.snapshot_report().is_dirty());
    assert!(state.http_events.header_mismatches.is_empty());
    assert!(state.http_events.header_observations.is_empty());
    task.abort();
}

#[tokio::test]
async fn observes_credential_and_negotiation_values_without_dirty_or_secret_leakage() {
    let (_temp, case) = fixture(json!({
        "authorization": ["Bearer source-secret"], "cookie": ["session=source-secret"],
        "content-type": ["application/json"], "accept": ["application/json"], "accept-language": ["zh"],
    }), 1).await;
    let (addr, runtime, task) = spawn_http_replay_with_policy(&case, vec![], None, None).await;
    send(
        addr,
        "/business",
        json!({
            "authorization": ["Bearer target-secret"], "cookie": ["session=target-secret"],
            "content-type": ["text/plain"], "accept-language": ["en"],
        }),
    )
    .await;
    let report = runtime.state.lock().await.snapshot_report();
    assert!(!report.is_dirty());
    assert_eq!(report.http_request_header_observations.len(), 5);
    let value = serde_json::to_value(report).unwrap();
    assert!(!value.to_string().contains("source-secret"));
    assert!(!value.to_string().contains("target-secret"));
    assert!(!report_has_case_dirty_events(&value));
    assert!(build_dependency_evidence(&value).clusters.is_empty());
    task.abort();
}

#[tokio::test]
async fn source_request_id_requires_presence_and_allows_new_values_or_target_additions() {
    for (source, actual, dirty) in [
        (json!({"x-request-id": ["source-id"]}), json!({}), true),
        (
            json!({"X-Request-Id": ["source-id"]}),
            json!({"x-request-id": ["target-id"]}),
            false,
        ),
        (json!({}), json!({"x-request-id": ["target-id"]}), false),
        (json!({}), json!({}), false),
    ] {
        let (_temp, case) = fixture(source, 1).await;
        let (addr, runtime, task) = spawn_http_replay_with_policy(&case, vec![], None, None).await;
        send(addr, "/business", actual).await;
        let report = runtime.state.lock().await.snapshot_report();
        assert_eq!(report.is_dirty(), dirty);
        assert!(report.http_request_header_observations.is_empty());
        let value = serde_json::to_value(report).unwrap();
        assert!(!value.to_string().contains("source-id"));
        assert!(!value.to_string().contains("target-id"));
        task.abort();
    }
}

#[tokio::test]
async fn credential_presence_and_api_key_values_are_dirty_and_protected() {
    let (_temp, case) = fixture(
        json!({"authorization": ["Bearer source-secret"], "x-api-key": ["source-api-secret"]}),
        1,
    )
    .await;
    let (addr, runtime, task) = spawn_http_replay_with_policy(&case, vec![], None, None).await;
    send(
        addr,
        "/business",
        json!({"cookie": ["session=target-secret"], "x-api-key": ["target-api-secret"]}),
    )
    .await;
    let report = runtime.state.lock().await.snapshot_report();
    assert!(report.is_dirty());
    assert_eq!(report.http_request_header_mismatches.len(), 3);
    let value = serde_json::to_value(report).unwrap();
    assert!(!value.to_string().contains("secret"));
    for cluster in build_dependency_evidence(&value).clusters {
        let representative = cluster.representative.unwrap();
        for observation in [
            representative.difference.expected,
            representative.difference.actual,
        ] {
            assert_eq!(observation.signature.unwrap()["protected"], true);
        }
    }
    task.abort();
}

#[tokio::test]
async fn preserves_repeated_header_multiplicity() {
    let (_temp, case) = fixture(json!({"business-flags": ["one", "one"]}), 1).await;
    let (addr, runtime, task) = spawn_http_replay_with_policy(&case, vec![], None, None).await;
    send(addr, "/business", json!({"business-flags": ["one"]})).await;
    assert!(runtime.state.lock().await.snapshot_report().is_dirty());
    task.abort();
}

#[tokio::test]
async fn header_dirty_evidence_survives_the_matched_detail_limit() {
    let (_temp, case) = fixture(
        json!({"tenant-id": ["tenant"], "content-type": ["application/json"]}),
        101,
    )
    .await;
    let (addr, runtime, task) = spawn_http_replay_with_policy(&case, vec![], None, None).await;
    for _ in 0..100 {
        send(
            addr,
            "/business",
            json!({"tenant-id": ["tenant"], "content-type": ["text/plain"]}),
        )
        .await;
    }
    send(
        addr,
        "/business",
        json!({"tenant-id": ["different"], "content-type": ["text/plain"]}),
    )
    .await;
    let report = runtime.state.lock().await.snapshot_report();
    assert_eq!(report.matched_http_exchange_count, 101);
    assert_eq!(report.matched_http_exchanges.len(), 100);
    assert_eq!(report.http_request_header_mismatches.len(), 1);
    assert_eq!(report.http_request_header_observation_count, 101);
    assert_eq!(report.http_request_header_observations.len(), 100);
    assert!(report.is_dirty());
    let value = serde_json::to_value(report).unwrap();
    assert_eq!(
        value["http_request_header_mismatches"][0]["target_event_index"],
        100
    );
    assert_eq!(build_dependency_evidence(&value).clusters.len(), 1);
    task.abort();
}

#[tokio::test]
async fn global_exchange_header_mismatch_belongs_to_the_active_case() {
    let (temp, case) = fixture(json!({}), 1).await;
    let global = temp.path().join("global-dependencies.jsonl");
    write_http_dependency(
        &global,
        "fake_ip_http",
        HOST,
        "/global",
        BODY,
        "recorded-response",
    )
    .await;
    let mut record: Value = serde_json::from_slice(&std::fs::read(&global).unwrap()).unwrap();
    record["request_headers"] = json!({"tenant-id": ["source-tenant"]});
    std::fs::write(global, format!("{record}\n")).unwrap();
    let (addr, runtime, task) = spawn_http_replay_with_policy(&case, vec![], None, None).await;
    send(addr, "/business", json!({})).await;
    send(addr, "/global", json!({"tenant-id": ["target-tenant"]})).await;
    let report = runtime.state.lock().await.snapshot_report();
    assert!(report.is_dirty());
    let value = serde_json::to_value(report).unwrap();
    assert_eq!(
        value["http_request_header_mismatches"][0]["source"],
        "global"
    );
    assert_eq!(
        value["http_request_header_mismatches"][0]["case_id"],
        "case-headers"
    );
    task.abort();
}

#[test]
fn bounds_plaintext_observations_and_protects_encrypted_custom_fields() {
    let long = vec!["v".repeat(1000); 20];
    let value = serde_json::to_value(observation("business-context", Some(&long), false)).unwrap();
    assert_eq!(value["values"].as_array().unwrap().len(), 8);
    assert_eq!(value["values"][0].as_str().unwrap().len(), 256);
    assert_eq!(
        serde_json::to_value(observation("private-context", Some(&long), true)).unwrap()["values"],
        json!(["<redacted>"])
    );
}

#[tokio::test]
async fn redaction_keeps_value_unavailable_but_still_checks_missing_credentials() {
    let (_temp, case) = fixture(
        json!({"authorization": ["<redacted>"], "x-api-key": ["<redacted>"], "private-context": ["<redacted>"]}),
        1,
    )
    .await;
    let (addr, runtime, task) = spawn_http_replay_with_policy(&case, vec![], None, None).await;
    send(
        addr,
        "/business",
        json!({"x-api-key": ["target-secret"], "private-context": ["private-value"]}),
    )
    .await;
    let report = runtime.state.lock().await.snapshot_report();
    assert!(report.is_dirty());
    let value = serde_json::to_value(report).unwrap();
    assert_eq!(
        value["http_request_header_mismatches"][0]["kind"],
        "header_missing"
    );
    assert_eq!(
        value["http_request_header_observations"][0]["expected"]["presence"],
        "unavailable"
    );
    assert!(!value.to_string().contains("target-secret"));
    assert!(!value.to_string().contains("private-value"));
    task.abort();
}

#[tokio::test]
async fn encrypted_dependency_headers_are_decrypted_before_audit_and_remain_protected() {
    let key: [u8; 32] = match std::env::var(crate::request_headers::ENCRYPTION_KEY_ENV) {
        Ok(encoded) => STANDARD
            .decode(encoded)
            .unwrap()
            .try_into()
            .unwrap_or_else(|_| panic!("test requires an AES-256 key")),
        Err(_) => [7; 32],
    };
    let capture = crate::request_headers::RequestHeaderCapture::with_key(
        &["authorization".into(), "private-context".into()],
        &[],
        &key,
    );
    let mut source = hyper::HeaderMap::new();
    source.insert(
        "authorization",
        hyper::header::HeaderValue::from_static("Bearer source-token"),
    );
    source.insert(
        "private-context",
        hyper::header::HeaderValue::from_static("source-private"),
    );
    let (temp, case) = fixture(
        serde_json::to_value(capture.capture(&source).unwrap()).unwrap(),
        2,
    )
    .await;
    let local = temp.path().join(".traffic-e2e/local");
    let key_file = local.join(crate::repository::LOCAL_ENCRYPTION_KEY_FROM_LOCAL);
    std::fs::create_dir_all(key_file.parent().unwrap()).unwrap();
    std::fs::write(key_file, STANDARD.encode(key)).unwrap();
    let moved = local.join("recordings/case-headers");
    std::fs::create_dir_all(moved.parent().unwrap()).unwrap();
    std::fs::rename(case, &moved).unwrap();
    let (addr, runtime, task) = spawn_http_replay_with_policy(&moved, vec![], None, None).await;
    send(
        addr,
        "/business",
        json!({"authorization": ["Bearer source-token"], "private-context": ["source-private"]}),
    )
    .await;
    assert!(
        runtime
            .state
            .lock()
            .await
            .http_events
            .header_observations
            .is_empty()
    );
    assert!(
        runtime
            .state
            .lock()
            .await
            .http_events
            .header_mismatches
            .is_empty()
    );
    send(
        addr,
        "/business",
        json!({"authorization": ["Bearer source-token"], "private-context": ["target-private"]}),
    )
    .await;
    let report = runtime.state.lock().await.snapshot_report();
    assert!(report.is_dirty());
    assert_eq!(report.http_request_header_mismatches.len(), 1);
    let value = serde_json::to_value(report).unwrap();
    for secret in [
        "source-token",
        "source-private",
        "target-private",
        "traffic-e2e:enc:",
    ] {
        assert!(!value.to_string().contains(secret));
    }
    task.abort();
}
