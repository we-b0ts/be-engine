use super::*;

const IDS: [&str; 4] = [
    "123e4567-e89b-42d3-a456-426614174000",
    "123e4567-e89b-42d3-a456-426614174001",
    "123e4567-e89b-42d3-a456-426614174002",
    "123e4567-e89b-42d3-a456-426614174003",
];

#[tokio::test]
async fn two_dependency_differences_continue_dirty_then_formal_rule_replay_is_clean() {
    for tentative in [true, false] {
        let (_temp, case, path, event) = fixture(false);
        let source = ["first", "second"]
            .iter()
            .enumerate()
            .map(|(i, name)| {
                let mut event = event.clone();
                event["id"] = json!(uuid::Uuid::new_v4());
                event["request_body"] =
                    capture(&serde_json::to_vec(&json!({"id":IDS[i*2],"which":name})).unwrap());
                event.to_string()
            })
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(case.join("dependencies.jsonl"), &source).unwrap();
        std::fs::write(&path, if tentative {"format: traffic-policy/v3\nrules: []\n"} else {"format: traffic-policy/v3\njson:\n  fields:\n    /id: {kind: identity, formats: [uuid]}\n"}).unwrap();
        let (address, runtime, task) = super::super::super::tests::spawn_http_replay_with_policy(
            &case,
            vec![],
            Some(path),
            None,
        )
        .await;
        runtime
            .state
            .lock()
            .await
            .replay_policy
            .as_mut()
            .unwrap()
            .request_contracts
            .configure_pre_match(tentative);
        for (i, name) in ["first", "second"].iter().enumerate() {
            let response = send(
                address,
                serde_json::to_vec(&json!({"id":IDS[i*2+1],"which":name})).unwrap(),
                "7",
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            response.into_body().collect().await.unwrap();
            let state = runtime.state.lock().await;
            assert!(!state.http_events.case_has_runtime_failure("case-http"));
        }
        let report = runtime.state.lock().await.snapshot_report();
        assert_eq!(report.matched_http_exchange_count, 2);
        assert!(report.unmatched_http_requests.is_empty());
        assert_eq!(
            report.dependency_pre_matches.len(),
            if tentative { 2 } else { 0 }
        );
        assert_eq!(report.is_dirty(), tentative);
        let report = serde_json::to_value(&report).unwrap();
        assert_eq!(
            crate::replay::report::report_has_case_dirty_events(&report),
            tentative
        );
        assert_eq!(
            crate::recorder::test_io::read_to_string_sync(case.join("dependencies.jsonl")).unwrap(),
            source
        );
        task.abort();
    }
}

#[tokio::test]
async fn sdk_header_dirty_stays_an_observation_after_a_later_dependency_rejection() {
    let (_temp, case, path, mut event) = fixture(false);
    event["request_headers"]["x-sdk-version"] = json!(["source"]);
    std::fs::write(case.join("dependencies.jsonl"), event.to_string()).unwrap();
    let (address, runtime, task) =
        super::super::super::tests::spawn_http_replay_with_policy(&case, vec![], Some(path), None)
            .await;
    let response = send(
        address,
        payload(false, Utc::now().timestamp(), false, 7),
        "7",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    response.into_body().collect().await.unwrap();
    {
        let state = runtime.state.lock().await;
        assert!(!state.http_events.header_mismatches.is_empty());
        assert!(!state.http_events.case_has_runtime_failure("case-http"));
        assert!(state.snapshot_report().is_dirty());
    }
    let command = || {
        serde_json::from_value(json!({
            "command": "case_execution_status", "case_id": "case-http"
        }))
        .unwrap()
    };
    let (clean, _) = crate::replay::control::handle_control_request(
        command(),
        runtime.state.clone(),
        None,
        None,
    )
    .await;
    assert_eq!(clean["failed"], false, "{clean}");
    // The sole Source exchange has been consumed. An additional real request
    // must fail, without promoting the earlier SDK observation into a cause.
    let response = send(
        address,
        payload(false, Utc::now().timestamp(), false, 7),
        "7",
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    response.into_body().collect().await.unwrap();
    let (failed, _) = crate::replay::control::handle_control_request(
        command(),
        runtime.state.clone(),
        None,
        None,
    )
    .await;
    assert_eq!(failed["failed"], true, "{failed}");
    let failures = failed["failures"].as_array().unwrap();
    assert!(!failures.is_empty(), "{failed}");
    assert!(
        failures
            .iter()
            .all(|failure| failure["kind"] == "unmatched_http_requests"),
        "{failed}"
    );
    assert!(
        !runtime
            .state
            .lock()
            .await
            .snapshot_report()
            .http_request_header_mismatches
            .is_empty()
    );
    task.abort();
}

#[tokio::test]
async fn ambiguous_hypotheses_preserve_every_attempt_without_claiming_or_delivering() {
    let (_temp, case, path, event) = fixture(false);
    let source = [IDS[0], IDS[2]]
        .into_iter()
        .map(|id| {
            let mut event = event.clone();
            event["id"] = json!(uuid::Uuid::new_v4());
            event["request_body"] = capture(&serde_json::to_vec(&json!({"id":id})).unwrap());
            event.to_string()
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(case.join("dependencies.jsonl"), source).unwrap();
    std::fs::write(&path, "format: traffic-policy/v3\nrules: []\n").unwrap();
    let (address, runtime, task) =
        super::super::super::tests::spawn_http_replay_with_policy(&case, vec![], Some(path), None)
            .await;
    runtime
        .state
        .lock()
        .await
        .replay_policy
        .as_mut()
        .unwrap()
        .request_contracts
        .configure_pre_match(true);
    let response = send(
        address,
        serde_json::to_vec(&json!({"id":IDS[1]})).unwrap(),
        "7",
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    response.into_body().collect().await.unwrap();
    let state = runtime.state.lock().await;
    let report = state.snapshot_report();
    assert_eq!(report.matched_http_exchange_count, 0);
    assert_eq!(report.unused_case_http_exchanges.len(), 2);
    assert_eq!(report.dependency_hypothesis_attempts.len(), 2);
    assert!(
        report
            .dependency_hypothesis_attempts
            .iter()
            .all(|attempt| attempt.status == "candidate_validated"
                && attempt.target_observation_id.is_some())
    );
    assert!(
        report.dependency_pre_matches.is_empty(),
        "an unselected assumption never becomes used evidence"
    );
    assert!(
        report
            .dependency_hypothesis_journal
            .as_ref()
            .unwrap()
            .complete
    );
    let journal = report.dependency_hypothesis_journal.as_ref().unwrap();
    let rows = std::fs::read_to_string(case.join(".replay").join(&journal.path)).unwrap();
    let checkpoints = rows
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|row| row["payload"]["kind"] == "hypothesis_witness")
        .collect::<Vec<_>>();
    assert_eq!(
        checkpoints.len(),
        1,
        "candidate scans share one protected Target checkpoint"
    );
    let checkpoint = &checkpoints[0]["payload"]["witness"];
    assert!(!checkpoint["key_envelope"].as_str().unwrap().is_empty());
    assert!(!checkpoint["blob"]["chunks"].as_array().unwrap().is_empty());
    assert_eq!(
        checkpoint["target"]["id"].as_str(),
        report.dependency_hypothesis_attempts[0]
            .target_observation_id
            .as_deref()
    );
    assert!(
        report.unmatched_http_requests[0]
            .reason
            .contains("multiple eligible")
    );
    task.abort();
}
