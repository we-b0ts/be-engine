use super::*;

#[test]
fn stream_end_mismatch_has_a_response_gate_and_visible_end_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let active_dir = temp.path().join("active");
    let latest_dir = temp.path().join("latest");
    std::fs::create_dir_all(&active_dir).unwrap();
    std::fs::create_dir_all(&latest_dir).unwrap();
    let expected = temp.path().join("expected-response.json");
    let actual = latest_dir.join("actual-response.json");
    for (path, end) in [
        (&expected, "observation_window_elapsed"),
        (&actual, "server_eof"),
    ] {
        std::fs::write(
            path,
            serde_json::to_vec(&serde_json::json!({
                "status": 200,
                "sse_observation": {"window_ms": 50, "end": end},
                "body": {"encoding": "utf8", "data": "", "truncated": false}
            }))
            .unwrap(),
        )
        .unwrap();
    }
    let mut state = ActiveRunState::new("run".to_string(), 1, &one_case_inventory(), &active_dir);
    state.cases[0].assertion_passed = Some(false);
    state.replay_finalized = true;
    state.aggregate_complete = true;
    state.aggregate_clean = true;
    let difference = ResponseDifference {
        pointer: "$sse_observation/end".to_string(),
        kind: ResponseDifferenceKind::SseStreamEndMismatch,
        expected_type: None,
        actual_type: None,
        expected_status: None,
        actual_status: None,
    };
    state.cases[0].response_assertion = Some(ResponseAssertionSummary {
        passed: false,
        method: "GET".to_string(),
        path: "/sse".to_string(),
        gateway_protocol: ResponseGatewayProtocol::Http,
        body_codec: ResponseBodyCodec::ExactBytes,
        body_diagnosis: None,
        difference_count: 1,
        difference_index: vec![difference.clone()],
        representative_difference: Some(difference),
        detail_report: active_dir.join("assertion-detail.json"),
        detail_fingerprint: "detail".to_string(),
        request: PathBuf::from("request.json"),
        expected_response: expected,
        actual_response: active_dir.join("actual-response.json"),
        policy_path: "replay.yaml".to_string(),
        policy_fingerprint: "policy".to_string(),
    });
    let layout = RunLayout {
        target_root: temp.path().to_path_buf(),
        run_key: "run".to_string(),
        case_source: PathBuf::from("/cases"),
        progress_path: temp.path().join("progress.yaml"),
        legacy_progress_path: temp.path().join("legacy-progress.yaml"),
        internal_root: temp.path().join("internal"),
        current_path: temp.path().join("current"),
        run_root: temp.path().join("run"),
        index_path: temp.path().join("index.yaml"),
        group_index_path: temp.path().join("group-index.yaml"),
        active_dir,
        latest_dir,
    };
    let gates = verification_gates(&state);
    assert_eq!(gates.responses, E2eResponseGate::Nonpassing);
    assert_eq!(gates.dependencies, E2eDependencyGate::Clean);
    let report = diagnosis(&layout, &state);
    assert_eq!(
        report.response_differences.failure_clusters[0].difference_kind,
        ResponseDifferenceKind::SseStreamEndMismatch
    );
    let representative = report.representative.unwrap();
    assert_eq!(
        representative.expected.value,
        Some(serde_json::json!("observation_window_elapsed"))
    );
    assert_eq!(
        representative.actual.value,
        Some(serde_json::json!("server_eof"))
    );
    assert_eq!(
        response_pointer_scope(&representative.pointer),
        "response_sse_observation"
    );
}
