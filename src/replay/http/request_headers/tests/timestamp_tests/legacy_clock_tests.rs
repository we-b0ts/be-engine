use super::*;

fn write_duration(case: &std::path::Path, duration: Value) {
    let path = case.join("dependencies.jsonl");
    let mut record: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    record["duration_ms"] = duration;
    std::fs::write(path, format!("{record}\n")).unwrap();
}

#[tokio::test]
async fn legacy_clock_supports_plan_apply_and_fresh_replay_without_changing_recordings() {
    let (temp, case) = clock_fixture(json!({"x-amz-date":[amz(source_time())]}), None).await;
    write_duration(&case, json!(30000));
    let recording_path = case.join("dependencies.jsonl");
    let original_recording = std::fs::read(&recording_path).unwrap();
    let (addr, runtime, task) = spawn_http_replay_with_policy(&case, vec![], None, None).await;
    send(addr, "/business", json!({"x-amz-date":[amz(Utc::now())]})).await;
    let mut report = serde_json::to_value(runtime.state.lock().await.snapshot_report()).unwrap();
    let event = &report["http_request_header_mismatches"][0];
    assert_eq!(event["kind"], "header_value_mismatch");
    assert_eq!(event["source_request_started_at"], json!(source_time()));
    assert!(event.get("source_request_time_reference").is_none());
    let bounded = build_dependency_evidence(&report);
    let signature = bounded.clusters[0]
        .representative
        .as_ref()
        .unwrap()
        .difference
        .expected
        .signature
        .as_ref()
        .unwrap();
    assert_eq!(signature["request_started_at"], json!(source_time()));
    assert!(signature.get("request_time_reference").is_none());
    report["finalized"] = json!(true);
    let report_path = temp.path().join("replay-report.json");
    std::fs::write(&report_path, report.to_string()).unwrap();
    let policy_path = temp.path().join("verification.yaml");
    std::fs::write(
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
            path: "/business".into(),
            header: "x-amz-date".into(),
            format: ResponseTimestampFormat::AmzDate,
        },
        source_evidence: "sdk.py:build_headers obtains current UTC time".into(),
    };
    let plan = plan_http_header_timestamp(feedback.clone()).unwrap();
    assert!(
        plan.report().candidates["records"][0]
            .get("request_time_reference")
            .is_none()
    );
    // Even a still-in-window timing change invalidates the evidence binding.
    write_duration(&case, json!(29000));
    assert!(plan.apply().is_err());
    std::fs::write(&recording_path, &original_recording).unwrap();
    // Reject invented clocks against the immutable dependency, even within the window.
    let mut forged = report.clone();
    let fake = source_time() + Duration::seconds(1);
    forged["http_request_header_mismatches"][0]["source_request_started_at"] = json!(fake);
    std::fs::write(&report_path, forged.to_string()).unwrap();
    assert!(plan_http_header_timestamp(feedback.clone()).is_err());
    std::fs::write(&report_path, report.to_string()).unwrap();
    let applied = plan_http_header_timestamp(feedback)
        .unwrap()
        .apply()
        .unwrap();
    assert!(applied.applied && applied.requires_replay);
    let (next_addr, next_runtime, next_task) =
        spawn_http_replay_with_policy(&case, vec![], Some(policy_path), None).await;
    send(
        next_addr,
        "/business",
        json!({"x-amz-date":[amz(Utc::now())]}),
    )
    .await;
    let next = next_runtime.state.lock().await.snapshot_report();
    assert!(!next.is_dirty());
    let next = serde_json::to_value(next).unwrap();
    assert_eq!(
        next["http_request_header_observations"][0]["kind"],
        "header_timestamp_validated"
    );
    assert!(
        next["http_request_header_observations"][0]
            .get("source_request_time_reference")
            .is_none()
    );
    assert_eq!(std::fs::read(&recording_path).unwrap(), original_recording);
    task.abort();
    next_task.abort();
}

#[tokio::test]
async fn unusable_legacy_clocks_remain_dirty_without_breaking_http_matching() {
    for duration in [
        Value::Null,
        json!(-1),
        json!(1.5),
        json!("30000"),
        json!(u64::MAX),
    ] {
        let (_temp, case) = clock_fixture(json!({"x-amz-date":[amz(source_time())]}), None).await;
        write_duration(&case, duration);
        let file = policy(&case, "/business");
        let (addr, runtime, task) =
            spawn_http_replay_with_policy(&case, vec![], Some(file), None).await;
        send(addr, "/business", json!({"x-amz-date":[amz(Utc::now())]})).await;
        let state = runtime.state.lock().await;
        assert!(state.snapshot_report().is_dirty());
        let report = serde_json::to_value(state.snapshot_report()).unwrap();
        assert_eq!(
            report["http_request_header_mismatches"][0]["validation_error"],
            "time_reference_missing"
        );
        assert!(
            report["unmatched_http_requests"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        task.abort();
    }
}

#[tokio::test]
async fn explicit_stale_start_is_not_replaced_by_a_valid_legacy_estimate() {
    let (_temp, case) = clock_fixture(
        json!({"x-amz-date":[amz(source_time())]}),
        Some(source_time() - Duration::seconds(30)),
    )
    .await;
    write_duration(&case, json!(30000));
    let file = policy(&case, "/business");
    let (addr, runtime, task) =
        spawn_http_replay_with_policy(&case, vec![], Some(file), None).await;
    send(addr, "/business", json!({"x-amz-date":[amz(Utc::now())]})).await;
    let report = serde_json::to_value(runtime.state.lock().await.snapshot_report()).unwrap();
    assert_eq!(
        report["http_request_header_mismatches"][0]["validation_error"],
        "timestamp_outside_request_window"
    );
    assert_eq!(
        report["http_request_header_mismatches"][0]["source_request_started_at"],
        json!(source_time() - Duration::seconds(30))
    );
    task.abort();
}
