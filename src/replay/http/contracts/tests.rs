use super::*;
use serde_json::json;

fn capture(bytes: &[u8]) -> Value {
    json!({"encoding":"base64","truncated":false,"data":STANDARD.encode(bytes)})
}
fn varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let low = (value & 127) as u8;
        value >>= 7;
        out.push(if value == 0 { low } else { low | 128 });
        if value == 0 {
            return out;
        }
    }
}
fn payload(pb: bool, time: i64, reversed: bool, stable: u8) -> Vec<u8> {
    let names = if reversed { ["b", "a"] } else { ["a", "b"] };
    if !pb {
        return serde_json::to_vec(&json!({"time":time,"members":names,"stable":stable})).unwrap();
    }
    let mut bytes = vec![8];
    bytes.extend(varint(time as u64));
    for name in names {
        bytes.extend([18, 1, name.as_bytes()[0]]);
    }
    bytes.extend([24, stable, 72, 0x87, 0]);
    bytes
}
fn fixture(
    pb: bool,
) -> (
    tempfile::TempDir,
    std::path::PathBuf,
    std::path::PathBuf,
    Value,
) {
    let temp = tempfile::tempdir().unwrap();
    let local = temp.path().join(".traffic-e2e/local");
    let case = local.join("recordings/case-http");
    std::fs::create_dir_all(&case).unwrap();
    let key = local.join(crate::repository::LOCAL_ENCRYPTION_KEY_FROM_LOCAL);
    std::fs::create_dir_all(key.parent().unwrap()).unwrap();
    std::fs::write(
        key,
        crate::request_headers::generate_encryption_key().unwrap(),
    )
    .unwrap();
    std::fs::write(
        case.join("request.json"),
        json!({"method":"POST","uri":"/api","timestamp":"1970-01-01T00:16:40Z"}).to_string(),
    )
    .unwrap();
    std::fs::write(case.join("expected-response.json"), "{}").unwrap();
    let source = payload(pb, 1000, false, 7);
    let response = payload(pb, 1005, false, 7);
    let event = json!({"event_type":"http_exchange","id":uuid::Uuid::new_v4(),"scheme":"http","authority":"service.test:8080",
        "method":"POST","uri":"/dependency?x=1&x=2","request_body":capture(&source),
        "request_headers":{"authorization":["source-token"],"cookie":["source=1"],"tenant-id":["7"],"content-type":["application/octet-stream"]},
        "response_status":200,"response_headers":{"x-stable":["fixed"],"content-type":["application/octet-stream"],"content-length":[response.len().to_string()]},
        "response_body":capture(&response),"timestamp":"1970-01-01T00:16:45Z","request_started_at":"1970-01-01T00:16:40Z","duration_ms":5000,"outcome":"response","error":null});
    std::fs::write(case.join("dependencies.jsonl"), event.to_string()).unwrap();
    let codec = if pb {
        "{kind: protobuf, fields: {/time: {field_path: [1], field_type: uint64}, /members: {field_path: [2], field_type: string, repeated: true}, /stable: {field_path: [3], field_type: uint64}}}"
    } else {
        "json"
    };
    let path = temp.path().join("policy.yaml");
    std::fs::write(&path,format!(r#"format: traffic-policy/v1
rules:
  - id: http-request
    surface: dependency.request
    match:
      api: POST /api
      resource: {{protocol: http, endpoint: 'service.test:8080'}}
      operation: POST
      path: /dependency
    slot: body
    codec: {codec}
    contract:
      /time: {{kind: time, format: unix_seconds, relation: preserve_offset}}
      /members: {{kind: unordered}}
    proof: {{source: 'src/client:send', fact: 'Request time uses the dependency clock; member order is not observed'}}
  - id: http-response
    surface: dependency.response
    match:
      api: POST /api
      resource: {{protocol: http, endpoint: 'service.test:8080'}}
      operation: POST
      path: /dependency
    slot: body
    codec: {codec}
    contract:
      /time: {{kind: time, format: unix_seconds, relation: preserve_offset}}
    delivery: {{rebase_time: [/time]}}
    proof: {{source: 'src/server:build', fact: 'Response time preserves its offset from the dependency request start and is not signed'}}
"#)).unwrap();
    (temp, case, path, event)
}

async fn send(address: SocketAddr, body: Vec<u8>, tenant: &str) -> Response<Incoming> {
    let client = TcpStream::connect(address).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(client))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    sender
        .send_request(
            Request::builder()
                .method("POST")
                .uri("/dependency?x=2&x=1")
                .header("host", "service.test:8080")
                .header("authorization", "target-token")
                .header("cookie", "target=1")
                .header("content-type", "application/json")
                .header("tenant-id", tenant)
                .body(Full::new(Bytes::from(body)))
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn request_and_response_json_and_protobuf_share_native_safe_contracts_and_finite_delivery() {
    for pb in [false, true] {
        let (_temp, case, path, event) = fixture(pb);
        let parsed = crate::policy::parse_policy(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let compiled = crate::policy::compile_policy(&parsed).unwrap();
        let (address, runtime, task) =
            super::super::tests::spawn_http_replay_with_policy(&case, vec![], Some(path), None)
                .await;
        let sent_at = Utc::now().timestamp();
        let response = send(address, payload(pb, sent_at, true, 7), "7").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["x-stable"], "fixed");
        let declared = response.headers()["content-length"]
            .to_str()
            .unwrap()
            .parse::<usize>()
            .unwrap();
        let date = response.headers()["date"].clone();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(declared, bytes.len());
        let decoded =
            crate::value_codec::CodecView::decode(&compiled.rules[1].rule.codec, &bytes).unwrap();
        // Preserve the Source response's +5s offset from this dependency's
        // start, regardless of when Replay delivers the response.
        let timestamp = decoded.logical["time"].as_i64().unwrap();
        assert!((sent_at + 5..=Utc::now().timestamp() + 5).contains(&timestamp));
        assert_eq!(decoded.logical["stable"], 7);
        if pb {
            assert!(bytes.ends_with(&[24, 7, 72, 0x87, 0]));
        }
        {
            let state = runtime.state.lock().await;
            let report = serde_json::to_value(state.snapshot_report()).unwrap();
            assert_eq!(report["matched_http_exchange_count"], 1);
            for rule in report["replay_policy"]["dependency_rules"]
                .as_array()
                .unwrap()
            {
                assert_eq!(rule["matches"], 1);
                assert_eq!(rule["time_validations"], 1);
            }
            assert!(!state.http_case_is_dirty("case-http"));
            let manifest = state
                .replay_policy
                .as_ref()
                .unwrap()
                .request_contracts
                .witness_manifest()
                .unwrap();
            let witnesses = manifest.witnesses().unwrap();
            let derived = witnesses
                .iter()
                .find(|witness| witness.metadata.target_role == TargetRole::DerivedDelivery)
                .unwrap();
            let private = case.join(".replay").join(&manifest.artifact);
            let (source, target) = crate::policy_evidence::read(&private, derived, &case).unwrap();
            assert_eq!(
                source,
                source_witness(&event, Surface::DependencyResponse, &case).unwrap()
            );
            let target = target.unwrap();
            validate_witness(
                &source,
                &target,
                Surface::DependencyResponse,
                derived.metadata.clocks.comparison(),
            )
            .unwrap();
            let target: Value = serde_json::from_slice(&target).unwrap();
            assert_eq!(
                target["response_headers"]["date"][0],
                date.to_str().unwrap()
            );
            assert_eq!(
                witness_value(
                    &serde_json::to_vec(&target).unwrap(),
                    Surface::DependencyResponse
                )
                .unwrap()
                .unwrap(),
                bytes
            );
        }
        let sent_at = Utc::now().timestamp();
        let response = send(address, payload(pb, sent_at, true, 7), "7").await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_GATEWAY,
            "finite response evidence must not be reused"
        );
        task.abort();
    }
}

#[tokio::test]
async fn body_contract_keeps_native_business_header_differences_dirty() {
    let (_temp, case, path, _event) = fixture(false);
    let (address, runtime, task) =
        super::super::tests::spawn_http_replay_with_policy(&case, vec![], Some(path), None).await;
    let response = send(
        address,
        payload(false, Utc::now().timestamp(), true, 7),
        "wrong",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let state = runtime.state.lock().await;
    assert!(state.http_case_is_dirty("case-http"));
    assert!(
        serde_json::to_value(&state.http_events.header_mismatches)
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .any(|header| header["header"] == "tenant-id")
    );
    task.abort();
}

#[tokio::test]
async fn body_contract_rejects_unselected_fields_and_retains_the_failed_target_pair() {
    let (_temp, case, path, _event) = fixture(false);
    let (address, runtime, task) =
        super::super::tests::spawn_http_replay_with_policy(&case, vec![], Some(path), None).await;
    let response = send(
        address,
        payload(false, Utc::now().timestamp(), true, 8),
        "7",
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let state = runtime.state.lock().await;
    let report = serde_json::to_value(state.snapshot_report()).unwrap();
    assert_eq!(report["matched_http_exchange_count"], 0);
    let manifest = state
        .replay_policy
        .as_ref()
        .unwrap()
        .request_contracts
        .witness_manifest()
        .unwrap();
    assert!(manifest.witnesses().unwrap().iter().any(|witness|witness.metadata.target_role==TargetRole::IndependentTargetObservation));
    task.abort();
}

#[tokio::test]
async fn empty_native_response_preserves_204_and_is_unavailable_without_rule_usage() {
    let (_temp, case, path, mut event) = fixture(false);
    event["response_status"] = json!(204);
    event["response_body"] = Value::Null;
    event["response_headers"] = json!({"content-length":["0"]});
    std::fs::write(case.join("dependencies.jsonl"), event.to_string()).unwrap();
    let (address, runtime, task) =
        super::super::tests::spawn_http_replay_with_policy(&case, vec![], Some(path), None).await;
    let response = send(
        address,
        payload(false, Utc::now().timestamp(), true, 7),
        "7",
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .is_empty()
    );
    let state = runtime.state.lock().await;
    let report = serde_json::to_value(state.snapshot_report()).unwrap();
    assert_eq!(
        report["replay_policy"]["unavailable_value_slots"]["http-response"],
        1
    );
    let rule = report["replay_policy"]["dependency_rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|rule| rule["id"] == "http-response")
        .unwrap();
    assert_eq!(rule["applicable"], false);
    assert_eq!(rule["matches"], 0);
    assert!(!state.http_case_is_dirty("case-http"));
    task.abort();
}

#[tokio::test]
async fn first_body_failure_without_rules_keeps_complete_independent_target_evidence() {
    let (_temp, case, path, event) = fixture(false);
    std::fs::write(&path, "format: traffic-policy/v1\nrules: []\n").unwrap();
    let (address, runtime, task) =
        super::super::tests::spawn_http_replay_with_policy(&case, vec![], Some(path), None).await;
    let response = send(
        address,
        payload(false, Utc::now().timestamp(), true, 7),
        "7",
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let state = runtime.state.lock().await;
    let manifest = state
        .replay_policy
        .as_ref()
        .unwrap()
        .request_contracts
        .witness_manifest()
        .unwrap();
    assert!(manifest.complete);
    let witnesses = manifest.witnesses().unwrap();
    let target = witnesses
        .iter()
        .find(|witness| witness.metadata.target_role == TargetRole::IndependentTargetObservation)
        .unwrap();
    let (source, actual) = crate::policy_evidence::read(
        &case.join(".replay").join(&manifest.artifact),
        target,
        &case,
    )
    .unwrap();
    assert_eq!(
        source,
        source_witness(&event, Surface::DependencyRequest, &case).unwrap()
    );
    let actual = actual.unwrap();
    validate_witness(
        &source,
        &actual,
        Surface::DependencyRequest,
        target.metadata.clocks.comparison(),
    )
    .unwrap();
    assert_ne!(
        witness_value(&source, Surface::DependencyRequest).unwrap(),
        witness_value(&actual, Surface::DependencyRequest).unwrap()
    );
    assert_eq!(
        target.metadata.source.exchange_id,
        event["id"].as_str().map(str::to_owned)
    );
    task.abort();
}

#[test]
fn response_digest_or_signature_requires_its_own_typed_rewrite_owner() {
    let (_temp, case, _path, mut event) = fixture(false);
    event["response_headers"]["content-digest"] = json!(["sha-256=:original:"]);
    let source = source_witness(&event, Surface::DependencyResponse, &case).unwrap();
    let mut target: Value = serde_json::from_slice(&source).unwrap();
    let delivered = chrono::DateTime::from_timestamp(2005, 0).unwrap();
    let body = payload(false, 2005, false, 7);
    let headers: HeaderSnapshot =
        serde_json::from_value(event["response_headers"].clone()).unwrap();
    target["response_body"] = STANDARD.encode(&body).into();
    target["response_headers"] = serde_json::to_value(request_headers::capture(
        &response_headers_for_payload(Some(&headers), body.len(), delivered),
    ))
    .unwrap();
    target["response_delivered_at"] = serde_json::to_value(delivered).unwrap();
    let clocks = AnchorClocks {
        dependency: crate::value_contract::time::ClockPair {
            source: chrono::DateTime::from_timestamp(1000, 0),
            target: chrono::DateTime::from_timestamp(2000, 0),
        },
        delivery: crate::value_contract::time::ClockPair {
            source: chrono::DateTime::from_timestamp(1005, 0),
            target: Some(delivered),
        },
        ..Default::default()
    };
    assert!(
        validate_witness(
            &source,
            &serde_json::to_vec(&target).unwrap(),
            Surface::DependencyResponse,
            clocks
        )
        .is_err()
    );
}

#[test]
fn native_header_contract_uses_presence_and_observation_modes_without_relaxing_business_fields() {
    let source=serde_json::from_value(json!({"authorization":["source"],"cookie":["a=1"],"content-type":["application/json"],"tenant-id":["7"],"x-request-id":["source"]})).unwrap();
    let target=serde_json::from_value(json!({"authorization":["target"],"cookie":["a=2"],"content-type":["application/protobuf"],"tenant-id":["7"],"x-request-id":["target"]})).unwrap();
    assert!(request_headers::native_contract_match(&source, &target));
    for name in ["authorization", "cookie", "tenant-id", "x-request-id"] {
        let mut changed: HeaderSnapshot = target.clone();
        changed.remove(name);
        assert!(
            !request_headers::native_contract_match(&source, &changed),
            "{name}"
        );
    }
    let mut changed = target;
    changed.insert("tenant-id".into(), vec!["8".into()]);
    assert!(!request_headers::native_contract_match(&source, &changed));
}

#[tokio::test]
async fn unmatched_requests_without_any_source_candidate_keep_distinct_target_observations() {
    let (_temp, case, path, mut event) = fixture(false);
    // Keep a real HTTP endpoint registered, without a candidate for /dependency.
    event["uri"] = "/unrelated".into();
    std::fs::write(case.join("dependencies.jsonl"), event.to_string()).unwrap();
    std::fs::write(&path, "format: traffic-policy/v1\nrules: []\n").unwrap();
    let (address, runtime, task) =
        super::super::tests::spawn_http_replay_with_policy(&case, vec![], Some(path), None).await;
    for _ in 0..2 {
        let response = send(address, b"same genuine request body".to_vec(), "7").await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        response.into_body().collect().await.unwrap();
    }
    {
        let state = runtime.state.lock().await;
        let owner = &state.replay_policy.as_ref().unwrap().request_contracts;
        owner.seal_witnesses().unwrap();
        let manifest = owner.witness_manifest().unwrap();
        let graph = manifest.graph().unwrap();
        assert!(manifest.complete && manifest.sealed);
        assert_eq!(graph.sources.len(), 2);
        assert!(graph.sources.iter().all(|source| {
            source.metadata.source.exchange_id.as_deref() == event["id"].as_str()
        }));
        assert!(graph.associations.is_empty());
        assert_eq!(graph.targets.len(), 2);
        assert_ne!(graph.targets[0].id, graph.targets[1].id);
        assert!(
            graph
                .targets
                .iter()
                .all(|target| target.metadata.role == TargetRole::IndependentTargetObservation)
        );
        let report = case.join(".replay/replay.json");
        std::fs::write(
            &report,
            serde_json::to_vec(&state.snapshot_report()).unwrap(),
        )
        .unwrap();
        crate::policy_evidence::verify(&report, &manifest).unwrap();
    }
    task.abort();
}

#[tokio::test]
async fn target_observation_io_failure_preserves_global_matching_and_rejects_case_candidates() {
    for global in [false, true] {
        let (_temp, case, path, event) = fixture(false);
        std::fs::write(&path, "format: traffic-policy/v1\nrules: []\n").unwrap();
        if global {
            std::fs::write(case.join("dependencies.jsonl"), "").unwrap();
            std::fs::write(
                case.parent().unwrap().join("global-dependencies.jsonl"),
                event.to_string(),
            )
            .unwrap();
        }
        let (address, runtime, task) =
            super::super::tests::spawn_http_replay_with_policy(&case, vec![], Some(path), None)
                .await;
        let store =
            crate::policy_evidence::WitnessStore::new(&case.join(".replay/io-failure")).unwrap();
        store.fail_writes_for_test().unwrap();
        {
            let mut state = runtime.state.lock().await;
            state
                .replay_policy
                .as_mut()
                .unwrap()
                .request_contracts
                .configure_witnesses(store, false)
                .unwrap();
        }
        let response = send(address, payload(false, 1000, false, 7), "7").await;
        assert_eq!(
            response.status(),
            if global {
                StatusCode::OK
            } else {
                StatusCode::BAD_GATEWAY
            }
        );
        response.into_body().collect().await.unwrap();
        let state = runtime.state.lock().await;
        assert_eq!(state.http_events.matched_count, usize::from(global));
        assert_eq!(state.http_events.unmatched.len(), usize::from(!global));
        let manifest = state
            .replay_policy
            .as_ref()
            .unwrap()
            .request_contracts
            .witness_manifest()
            .unwrap();
        assert!(!manifest.complete);
        assert!(manifest.omitted > 0);
        assert!(manifest.graph().unwrap().targets.is_empty());
        assert_eq!(state.http_exchanges[0].status.is_consumed(), global);
        task.abort();
    }
}
