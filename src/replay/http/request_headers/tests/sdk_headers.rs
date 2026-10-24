//! SDK headers obey the ordinary native HTTP contract, without rule exemptions.
use super::*;

fn expected() -> Value {
    json!({"x-stainless-lang":["python"],"x-stainless-runtime":["CPython"],
        "tenant-id":["same"],"authorization":["source"]})
}
async fn run(actual: Value) -> Value {
    let (_temporary, case) = fixture(expected(), 1).await;
    std::fs::write(
        case.join("request.json"),
        json!({"method":"POST","uri":"/api","timestamp":"2026-07-15T04:30:00Z"}).to_string(),
    )
    .unwrap();
    std::fs::write(case.join("expected-response.json"), "{}").unwrap();
    let path = case.join("policy.yaml");
    std::fs::write(&path, "format: traffic-policy/v2\nrules: []\n").unwrap();
    let (address, runtime, task) =
        spawn_http_replay_with_policy(&case, vec![], Some(path), None).await;
    send(address, "/business", actual).await;
    let state = runtime.state.lock().await;
    let report = state.snapshot_report();
    let dirty = report.is_dirty();
    let mut report = serde_json::to_value(report).unwrap();
    report["test_dirty"] = dirty.into();
    task.abort();
    report
}

#[tokio::test]
async fn ordinary_sdk_headers_require_matching_presence_and_values_without_prefix_whitelists() {
    assert_eq!(run(expected()).await["test_dirty"], false);
    for (name, value, kind) in [
        ("x-stainless-lang", Value::Null, "header_missing"),
        (
            "x-stainless-runtime",
            json!(["rust"]),
            "header_value_mismatch",
        ),
        ("x-stainless-arch", json!(["arm64"]), "header_added"),
        ("x-stainless-custom", json!(["custom"]), "header_added"),
    ] {
        let mut actual = expected();
        if value.is_null() {
            actual.as_object_mut().unwrap().remove(name);
        } else {
            actual[name] = value;
        }
        let report = run(actual).await;
        assert_eq!(report["test_dirty"], true, "{report}");
        assert_eq!(report["matched_http_exchange_count"], 1);
        let mismatches = report["http_request_header_mismatches"].as_array().unwrap();
        assert!(mismatches.iter().any(|row| row["header"] == name
            && row["kind"] == kind
            && row["comparison"] == "strict"));
    }
}

#[tokio::test]
async fn protected_http_witness_cannot_waive_sdk_headers_or_business_values() {
    use crate::policy::Surface;
    use crate::replay::http::contracts::{source_witness, validate_witness};
    let (_temporary, case) = fixture(expected(), 1).await;
    let event: Value =
        serde_json::from_slice(&std::fs::read(case.join("dependencies.jsonl")).unwrap()).unwrap();
    let source = source_witness(&event, Surface::DependencyRequest, &case).unwrap();
    let mut target: Value = serde_json::from_slice(&source).unwrap();
    target["exchange_id"] = json!(uuid::Uuid::new_v4());
    let time = serde_json::from_value(target["request_started_at"].clone()).unwrap();
    let clocks = crate::value_contract::json::AnchorClocks {
        dependency: crate::value_contract::time::ClockPair {
            source: time,
            target: time,
        },
        ..Default::default()
    };
    validate_witness(
        &source,
        &serde_json::to_vec(&target).unwrap(),
        Surface::DependencyRequest,
        clocks,
    )
    .unwrap();
    for (name, value) in [
        ("x-stainless-lang", Value::Null),
        ("x-stainless-runtime", json!(["rust"])),
        ("tenant-id", json!(["changed"])),
    ] {
        let mut changed = target.clone();
        if value.is_null() {
            changed["request_headers"]
                .as_object_mut()
                .unwrap()
                .remove(name);
        } else {
            changed["request_headers"][name] = value;
        }
        assert!(
            validate_witness(
                &source,
                &serde_json::to_vec(&changed).unwrap(),
                Surface::DependencyRequest,
                clocks
            )
            .is_err()
        );
    }
}

#[test]
fn policy_cannot_declare_an_sdk_header_presence_exemption() {
    let proposal = json!({"format":"traffic-policy/v2","rules":[{
        "id":"sdk","match":{"resource":{"protocol":"http","endpoint":"api.example.test:80"},"operation":"POST","path":"/business"},
        "effect":{"kind":"http_client_metadata","headers":["x-stainless-lang"]},
        "proof":{"source":"client.py:headers","fact":"An SDK header description does not grant permission to omit it"}
    }]});
    assert!(crate::policy::parse_and_compile_policy(&proposal.to_string()).is_err());
}
