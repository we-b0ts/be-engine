use super::*;
use crate::{
    HttpHeaderTimestampFeedback, HttpHeaderTimestampSelector, ResponseTimestampFormat,
    plan_http_header_timestamp,
};
use chrono::{DateTime, Duration, Utc};
mod legacy_clock_tests;

fn source_time() -> DateTime<Utc> {
    "2026-10-03T16:00:01Z".parse().unwrap()
}

fn amz(time: DateTime<Utc>) -> String {
    time.format("%Y%m%dT%H%M%SZ").to_string()
}

async fn clock_fixture(headers: Value, clock: Option<DateTime<Utc>>) -> (TempDir, PathBuf) {
    let (temp, case) = fixture(headers, 1).await;
    let path = case.join("dependencies.jsonl");
    let mut record: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    record["request_started_at"] = json!(clock);
    record["duration_ms"] = Value::Null;
    // Both the primary API clock and exchange completion are far from the header time.
    record["timestamp"] = json!(source_time() + Duration::seconds(30));
    std::fs::write(path, format!("{record}\n")).unwrap();
    std::fs::write(
        case.join("request.json"),
        json!({
            "method":"GET", "uri":"/api/attachments/example/download",
            "timestamp":source_time() - Duration::seconds(120),
        })
        .to_string(),
    )
    .unwrap();
    std::fs::write(case.join("expected-response.json"), "{}").unwrap();
    std::fs::write(
        temp.path().join("recording-run.json"),
        r#"{"status":"completed"}"#,
    )
    .unwrap();
    (temp, case)
}

fn policy(case: &std::path::Path, path: &str) -> PathBuf {
    let file = case.join("policy.yaml");
    crate::replay::write_policy_fixture(
        &file,
        format!(
            r#"version: 3
expected_response: assertions_only
dependency_rules:
- id: signing-time
  protocol: http
  target: {{host: {HOST}, port: 80}}
  http:
    method: POST
    path: {path}
    headers:
      x-amz-date:
        kind: timestamp
        format: amz_date
        source_evidence: sdk.py:build_headers uses current UTC time
"#
        ),
    )
    .unwrap();
    file
}

#[test]
fn header_timestamp_uses_the_shared_five_second_window_and_fails_closed() {
    let source = source_time();
    let target = source + Duration::days(1);
    let clocks = crate::replay::assertion::RequestTimes {
        source: Some(source),
        target: Some(target),
    };
    for (source_offset, target_offset, valid) in
        [(-5, 5, true), (5, -5, true), (-6, 0, false), (0, 6, false)]
    {
        assert_eq!(
            timestamp::validate(
                ResponseTimestampFormat::AmzDate,
                Some(&[amz(source + Duration::seconds(source_offset))]),
                Some(&[amz(target + Duration::seconds(target_offset))]),
                clocks
            )
            .is_ok(),
            valid
        );
    }
    let value = vec![amz(source)];
    assert!(
        timestamp::validate(
            ResponseTimestampFormat::AmzDate,
            Some(&value),
            Some(&value),
            clocks
        )
        .is_err()
    );
    for value in [
        "20261003T160001+00:00",
        "20261003t160001z",
        "20261303T160001Z",
        "20261003T160001Z-extra",
    ] {
        assert!(
            timestamp::validate(
                ResponseTimestampFormat::AmzDate,
                Some(&[value.into()]),
                Some(&[amz(target)]),
                clocks
            )
            .is_err()
        );
    }
    assert!(
        timestamp::validate(ResponseTimestampFormat::AmzDate, None, Some(&value), clocks).is_err()
    );
    assert!(
        timestamp::validate(
            ResponseTimestampFormat::AmzDate,
            Some(&value),
            Some(&[amz(target), amz(target)]),
            clocks
        )
        .is_err()
    );
    assert!(
        timestamp::validate(
            ResponseTimestampFormat::AmzDate,
            Some(&value),
            Some(&[amz(target)]),
            crate::replay::assertion::RequestTimes::default()
        )
        .is_err()
    );
    assert!(
        timestamp::validate(
            ResponseTimestampFormat::AmzDate,
            Some(&value),
            Some(&[amz(target)]),
            crate::replay::assertion::RequestTimes {
                source: Some(source + Duration::seconds(5) + Duration::nanoseconds(1)),
                target: Some(target)
            }
        )
        .is_err()
    );
}

#[tokio::test]
async fn later_replay_uses_dependency_start_and_returns_response_without_header_dirty() {
    let (_temp, case) = clock_fixture(
        json!({"x-amz-date":[amz(source_time())]}),
        Some(source_time()),
    )
    .await;
    let file = policy(&case, "/business");
    let (addr, runtime, task) =
        spawn_http_replay_with_policy(&case, vec![], Some(file), None).await;
    send(addr, "/business", json!({"x-amz-date":[amz(Utc::now())]})).await;
    let state = runtime.state.lock().await;
    let report = serde_json::to_value(state.snapshot_report()).unwrap();
    assert!(!state.snapshot_report().is_dirty());
    assert_eq!(
        report["http_request_header_observations"][0]["kind"],
        "header_timestamp_validated"
    );
    assert_eq!(
        report["http_request_header_observations"][0]["rule_id"],
        "signing-time"
    );
    assert_eq!(
        report["replay_policy"]["dependency_rules"][0]["time_validations"],
        1
    );
    task.abort();
}

#[tokio::test]
async fn invalid_timestamp_headers_remain_dirty_even_for_equal_literals() {
    for (header, clock, error) in [
        (
            json!([amz(source_time())]),
            Some(source_time()),
            "timestamp_outside_request_window",
        ),
        (
            json!(["not-a-time"]),
            Some(source_time()),
            "time_field_invalid",
        ),
        (json!([amz(Utc::now())]), None, "time_reference_missing"),
        (
            Value::Null,
            Some(source_time()),
            "timestamp header is missing",
        ),
    ] {
        let (_temp, case) = clock_fixture(json!({"x-amz-date":[amz(source_time())]}), clock).await;
        let file = policy(&case, "/business");
        let (addr, runtime, task) =
            spawn_http_replay_with_policy(&case, vec![], Some(file), None).await;
        let headers = if header.is_null() {
            json!({})
        } else {
            json!({"x-amz-date":header})
        };
        send(addr, "/business", headers).await;
        let state = runtime.state.lock().await;
        let report = serde_json::to_value(state.snapshot_report()).unwrap();
        assert!(state.snapshot_report().is_dirty());
        assert_eq!(
            report["http_request_header_mismatches"][0]["kind"],
            "header_timestamp_invalid"
        );
        assert_eq!(
            report["http_request_header_mismatches"][0]["validation_error"],
            error
        );
        let bounded = build_dependency_evidence(&report);
        assert_eq!(
            bounded.clusters[0]
                .representative
                .as_ref()
                .unwrap()
                .difference
                .actual
                .signature
                .as_ref()
                .unwrap()["validation_error"],
            error
        );
        task.abort();
    }
}

#[tokio::test]
async fn timestamp_rule_preserves_other_header_checks_and_endpoint_scope() {
    for (rule_path, expected_header) in
        [("/business", "x-wegent-user-id"), ("/other", "x-amz-date")]
    {
        let (_temp, case) = clock_fixture(
            json!({"x-amz-date":[amz(source_time())],"x-wegent-user-id":["source"]}),
            Some(source_time()),
        )
        .await;
        let file = policy(&case, rule_path);
        let (addr, runtime, task) =
            spawn_http_replay_with_policy(&case, vec![], Some(file), None).await;
        send(
            addr,
            "/business",
            json!({"x-amz-date":[amz(Utc::now())],"x-wegent-user-id":["target"]}),
        )
        .await;
        let state = runtime.state.lock().await;
        let report = serde_json::to_value(state.snapshot_report()).unwrap();
        assert!(state.snapshot_report().is_dirty());
        assert!(
            report["http_request_header_mismatches"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["header"] == expected_header)
        );
        task.abort();
    }
}

#[tokio::test]
async fn timestamp_plan_apply_rechecks_evidence_and_requires_fresh_replay() {
    let (temp, case) = clock_fixture(
        json!({"x-amz-date":[amz(source_time())]}),
        Some(source_time()),
    )
    .await;
    let (addr, runtime, task) = spawn_http_replay_with_policy(&case, vec![], None, None).await;
    send(addr, "/business", json!({"x-amz-date":[amz(Utc::now())]})).await;
    let report = {
        let state = runtime.state.lock().await;
        assert!(state.snapshot_report().is_dirty());
        let mut report = serde_json::to_value(state.snapshot_report()).unwrap();
        report["finalized"] = json!(true);
        report
    };
    let report_path = temp.path().join("replay-report.json");
    std::fs::write(&report_path, report.to_string()).unwrap();
    let policy_path = temp.path().join("policy.yaml");
    crate::replay::write_policy_fixture(
        &policy_path,
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();
    let feedback = HttpHeaderTimestampFeedback {
        policy_path: policy_path.clone(),
        case_source: case.clone(),
        replay_report_path: report_path.clone(),
        rule_id: "signing-time".into(),
        selector: HttpHeaderTimestampSelector {
            host: HOST.into(),
            port: 80,
            method: "POST".into(),
            path: "/*".into(),
            header: "X-Amz-Date".into(),
            format: ResponseTimestampFormat::AmzDate,
        },
        source_evidence: "sdk.py:build_headers obtains current UTC time".into(),
    };
    let plan = plan_http_header_timestamp(feedback.clone()).unwrap();
    assert!(plan.report().changed && plan.report().requires_replay);
    let mut stale = report.clone();
    stale["finalized_at"] = json!("changed");
    std::fs::write(&report_path, stale.to_string()).unwrap();
    assert!(plan.apply().is_err());
    std::fs::write(&report_path, report.to_string()).unwrap();
    let applied = plan_http_header_timestamp(feedback.clone())
        .unwrap()
        .apply()
        .unwrap();
    assert!(applied.applied && applied.requires_replay);
    let reuse = plan_http_header_timestamp(feedback.clone()).unwrap();
    assert!(reuse.report().reused_existing);
    assert!(!reuse.report().changed);
    let (next_addr, next_runtime, next_task) =
        spawn_http_replay_with_policy(&case, vec![], Some(policy_path), None).await;
    send(
        next_addr,
        "/business",
        json!({"x-amz-date":[amz(Utc::now())]}),
    )
    .await;
    assert!(!next_runtime.state.lock().await.snapshot_report().is_dirty());
    let path = case.join("dependencies.jsonl");
    let mut record: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    record["request_headers"]["x-amz-date"] = json!([amz(source_time() + Duration::seconds(1))]);
    std::fs::write(path, format!("{record}\n")).unwrap();
    assert!(reuse.apply().is_err());
    task.abort();
    next_task.abort();
}
