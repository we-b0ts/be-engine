use super::*;

fn rule() -> Value {
    json!({"id":"sdk","match":{"api":"POST /api","resource":{"protocol":"http","endpoint":format!("{HOST}:80")},"operation":"POST","path":"/business"},
        "effect":{"kind":"http_client_metadata","headers":["x-stainless-lang","x-stainless-runtime","x-stainless-arch"]},
        "proof":{"source":"sdk.py:headers; consumer.py:route","fact":"The selected consumer does not use these SDK metadata headers"}})
}
async fn run(rule: Option<Value>, actual: Value) -> Value {
    let (_temp, case) = fixture(json!({"x-stainless-lang":["python"],"x-stainless-runtime":["CPython"],"tenant-id":["same"],"authorization":["source"]}), 1).await;
    std::fs::write(
        case.join("request.json"),
        json!({"method":"POST","uri":"/api","timestamp":"2026-10-01T00:00:00Z"}).to_string(),
    )
    .unwrap();
    std::fs::write(case.join("expected-response.json"), "{}").unwrap();
    let path = case.join("policy.yaml");
    std::fs::write(
        &path,
        json!({"format":"traffic-policy/v1","rules":rule.into_iter().collect::<Vec<_>>()} )
            .to_string(),
    )
    .unwrap();
    let (addr, runtime, task) =
        spawn_http_replay_with_policy(&case, vec![], Some(path), None).await;
    send(addr, "/business", actual).await;
    let state = runtime.state.lock().await;
    let report = state.snapshot_report();
    let dirty = report.is_dirty();
    let mut value = serde_json::to_value(report).unwrap();
    value["test_dirty"] = dirty.into();
    task.abort();
    value
}
fn actual() -> Value {
    json!({"x-stainless-runtime":["rust"],"x-stainless-arch":["arm64"],"tenant-id":["same"],"authorization":["target"]})
}

#[tokio::test]
async fn scoped_sdk_differences_are_audited_without_dirtying_or_changing_delivery() {
    let report = run(Some(rule()), actual()).await;
    assert_eq!(report["test_dirty"], false, "{report}");
    assert_eq!(report["matched_http_exchange_count"], 1);
    let observations = report["http_request_header_observations"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["rule_id"] == "sdk")
        .collect::<Vec<_>>();
    assert_eq!(observations.len(), 3);
    for row in observations {
        assert_eq!(row["rule_id"], "sdk");
        assert_eq!(row["comparison"], "observe");
    }
    let usage = report["replay_policy"]["dependency_rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "sdk")
        .unwrap();
    assert_eq!(usage["matches"], 1);
    assert_eq!(usage["validations"], 3);
}

#[tokio::test]
async fn sdk_headers_default_to_strict_and_permissions_do_not_escape_consumer_scope() {
    assert_eq!(run(None, actual()).await["test_dirty"], true);
    for (field, value) in [
        ("api", json!("GET /api")),
        ("operation", json!("GET")),
        ("path", json!("/other")),
        (
            "resource",
            json!({"protocol":"http","endpoint":"other.test:80"}),
        ),
    ] {
        let mut other = rule();
        other["match"][field] = value;
        let report = run(Some(other), actual()).await;
        assert_eq!(report["test_dirty"], true, "{field}: {report}");
        assert!(
            report["http_request_header_observations"]
                .as_array()
                .unwrap()
                .iter()
                .all(|row| row["rule_id"] != "sdk")
        );
    }
    let mut changed = actual();
    changed["tenant-id"] = json!(["other"]);
    changed.as_object_mut().unwrap().remove("authorization");
    changed["x-stainless-api-key"] = json!(["secret"]);
    let report = run(Some(rule()), changed).await;
    assert_eq!(report["test_dirty"], true);
    assert_eq!(
        report["http_request_header_mismatches"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
}

#[tokio::test]
async fn client_metadata_envelope_preflight_preserves_identity_and_business_headers() {
    use crate::policy::Surface;
    use crate::replay::http::contracts::{
        source_witness, validate_contract_witness, validate_witness,
    };
    let (_temp, case) = fixture(
        json!({"x-stainless-lang":["python"],"tenant-id":["same"],"authorization":["source"]}),
        1,
    )
    .await;
    let event: Value =
        serde_json::from_slice(&std::fs::read(case.join("dependencies.jsonl")).unwrap()).unwrap();
    let source = source_witness(&event, Surface::DependencyRequest, &case).unwrap();
    let mut target: Value = serde_json::from_slice(&source).unwrap();
    target["exchange_id"] = json!(uuid::Uuid::new_v4());
    target["request_headers"]
        .as_object_mut()
        .unwrap()
        .remove("x-stainless-lang");
    let source_time = serde_json::from_value::<Option<chrono::DateTime<Utc>>>(
        target["request_started_at"].clone(),
    )
    .unwrap();
    let clocks = crate::value_contract::json::AnchorClocks {
        dependency: crate::value_contract::time::ClockPair {
            source: source_time,
            target: source_time,
        },
        ..Default::default()
    };
    let compiled = crate::policy::parse_and_compile_policy(
        &json!({"format":"traffic-policy/v1","rules":[rule()]}).to_string(),
    )
    .unwrap();
    let native = compiled.native.iter().collect::<Vec<_>>();
    let bytes = serde_json::to_vec(&target).unwrap();
    assert!(validate_witness(&source, &bytes, Surface::DependencyRequest, clocks).is_err());
    validate_contract_witness(&source, &bytes, Surface::DependencyRequest, &native, clocks)
        .unwrap();
    for (field, value) in [
        ("method", json!("GET")),
        ("uri", json!("/other")),
        ("endpoint", json!({"host":"other.test","port":80})),
    ] {
        let mut bad = target.clone();
        bad[field] = value;
        assert!(
            validate_contract_witness(
                &source,
                &serde_json::to_vec(&bad).unwrap(),
                Surface::DependencyRequest,
                &native,
                clocks
            )
            .is_err()
        );
    }
    for name in ["tenant-id", "authorization"] {
        let mut bad = target.clone();
        bad["request_headers"].as_object_mut().unwrap().remove(name);
        assert!(
            validate_contract_witness(
                &source,
                &serde_json::to_vec(&bad).unwrap(),
                Surface::DependencyRequest,
                &native,
                clocks
            )
            .is_err()
        );
    }
}
