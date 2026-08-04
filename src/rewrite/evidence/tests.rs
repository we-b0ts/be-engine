use super::*;
use crate::rewrite::inventory;
use crate::rewrite::model::{RewriteAttemptDelta, RewriteIssueOwner, RewritePhase};
use crate::{
    E2eDependencyDifference, E2eDependencyEndpoint, E2eDependencyObservation,
    E2eDependencyRepresentative, E2eDirtyCluster, E2eDirtyCounts, E2eRepresentativeDifference,
    E2eSourcePreReadiness, ResponseDifferenceKind,
};

#[test]
fn parked_api_evidence_survives_unrelated_api_revisions() {
    let target_root = Path::new("/target");
    let mut state = crate::rewrite::test_state();
    inventory::install(
        &mut state,
        vec!["GET /a".to_string(), "POST /b".to_string()],
    )
    .unwrap();
    state.phase = RewritePhase::ImplementationRequired;
    state.target_fingerprint = Some("target-a".to_string());
    state.attempt_delta = Some(RewriteAttemptDelta {
        previous_attempt: 0,
        current_attempt: 1,
        response_passed_delta: 1,
        response_nonpassing_delta: -1,
        improved: true,
        regressed: false,
    });
    state.active_issue = Some(RewriteIssue {
        id: "issue-api-a".to_string(),
        kind: RewriteIssueKind::Response,
        owner: RewriteIssueOwner::TargetCode,
        summary: "response mismatch".to_string(),
        pointer_pattern: None,
        representative: None,
        possible_causes: Vec::new(),
        observed_target_fingerprint: "target-a".to_string(),
        attempt: 1,
        comparison_observation: None,
    });
    let evidence_command = commands(target_root, &state)
        .into_iter()
        .find(|command| command.query_id.contains("attempt-delta"))
        .unwrap();
    let evidence = query(target_root, &state, &evidence_command.query_id).unwrap();
    let original_revision = state.revision;
    crate::rewrite::worker::confirm_current_for_test(&mut state);

    inventory::activate_requested(
        &mut state,
        Some(&"POST /b".parse::<crate::RecordingApi>().unwrap()),
    )
    .unwrap();

    assert!(state.revision > original_revision);
    assert_eq!(
        inventory::api_for_evidence_query(target_root, &state, &evidence_command.query_id)
            .as_deref(),
        Some("GET /a")
    );
    assert_eq!(
        inventory::api_for_evidence_id(target_root, &state, &evidence.evidence_id).as_deref(),
        Some("GET /a")
    );

    state
        .parked_slices
        .get_mut("GET /a")
        .unwrap()
        .active_issue
        .as_mut()
        .unwrap()
        .attempt += 1;
    assert!(
        inventory::api_for_evidence_query(target_root, &state, &evidence_command.query_id)
            .is_none()
    );
    assert!(inventory::api_for_evidence_id(target_root, &state, &evidence.evidence_id).is_none());
}

#[test]
fn representatives_return_the_exact_recorded_case_directory_and_response_difference() {
    let target = tempfile::tempdir().unwrap();
    let case_source = target.path().join("recording");
    let case_dir = case_source.join("case-status-mismatch");
    std::fs::create_dir_all(&case_dir).unwrap();
    std::fs::write(
        case_dir.join("request.json"),
        r#"{"method":"GET","uri":"/api/widgets?source=1&ids=2"}"#,
    )
    .unwrap();
    std::fs::write(
        case_dir.join("expected-response.json"),
        r#"{"status":403,"body":{"encoding":"utf8","data":"forbidden"}}"#,
    )
    .unwrap();
    let case_dir = std::fs::canonicalize(case_dir).unwrap();

    let mut state = crate::rewrite::test_state();
    state.phase = RewritePhase::ImplementationRequired;
    state.case_source = Some(case_source);
    state.active_issue = Some(RewriteIssue {
        id: "issue-status".to_string(),
        kind: RewriteIssueKind::Response,
        owner: RewriteIssueOwner::TargetCode,
        summary: "response mismatch".to_string(),
        pointer_pattern: Some("$status".to_string()),
        representative: Some(E2eRepresentativeDifference {
            case_id: "case-status-mismatch".to_string(),
            pointer: "$status".to_string(),
            difference_kind: ResponseDifferenceKind::StatusMismatch,
            expected: E2eValueObservation {
                presence: E2eValuePresence::Present,
                value: Some(Value::from(403)),
            },
            actual: E2eValueObservation {
                presence: E2eValuePresence::Present,
                value: Some(Value::from(200)),
            },
        }),
        possible_causes: Vec::new(),
        observed_target_fingerprint: "target".to_string(),
        attempt: 1,
        comparison_observation: None,
    });
    let command = commands(target.path(), &state)
        .into_iter()
        .find(|command| command.query_id.contains("representatives"))
        .unwrap();

    let report = query(target.path(), &state, &command.query_id).unwrap();

    assert_eq!(report.query, QUERY_REPRESENTATIVES);
    assert_eq!(report.facts["pointer_scope"], "response_status");
    assert_eq!(
        report.facts["representative"]["case_dir"],
        serde_json::json!(case_dir)
    );
    assert_eq!(
        report.facts["representative"]["response_difference"],
        serde_json::json!({
            "pointer": "$status",
            "kind": "status_mismatch",
            "expected": {"presence": "present", "value": 403},
            "actual": {"presence": "present", "value": 200},
        })
    );
    assert!(report.facts["representative"].get("response").is_none());
    assert!(
        report.facts["representative"]
            .get("replay_result_dir")
            .is_none()
    );
}

#[test]
fn comparison_representatives_link_the_comparison_case_and_three_way_difference() {
    let target = tempfile::tempdir().unwrap();
    let run_id = "20260802120000";
    let case_dir = target
        .path()
        .join(".traffic-e2e/local/artifacts/comparison-recordings")
        .join(run_id)
        .join("record-api")
        .join("case-comparison");
    std::fs::create_dir_all(&case_dir).unwrap();
    std::fs::write(
        case_dir.join("case-kind.json"),
        r#"{"version":1,"kind":"comparison_recording"}"#,
    )
    .unwrap();
    let case_dir = std::fs::canonicalize(case_dir).unwrap();

    let mut state = crate::rewrite::test_state();
    state.phase = RewritePhase::ImplementationRequired;
    state.comparison_run_id = Some(run_id.to_string());
    state.active_issue = Some(RewriteIssue {
        id: "issue-comparison".to_string(),
        kind: RewriteIssueKind::Comparison,
        owner: RewriteIssueOwner::TargetCode,
        summary: "comparison mismatch".to_string(),
        pointer_pattern: Some("/users/0/name".to_string()),
        representative: None,
        possible_causes: Vec::new(),
        observed_target_fingerprint: "target".to_string(),
        attempt: 1,
        comparison_observation: Some(serde_json::json!({
            "api": "GET /api/widgets",
            "case_id": "case-comparison",
            "classification": "candidate_difference",
            "pointer": "/users/0/name",
            "difference_kind": "value_mismatch",
            "source_before": "source",
            "candidate": "target",
            "source_after": "source",
        })),
    });
    let command = commands(target.path(), &state)
        .into_iter()
        .find(|command| command.query_id.contains("representatives"))
        .unwrap();

    let report = query(target.path(), &state, &command.query_id).unwrap();

    assert_eq!(report.facts["pointer_scope"], "decoded_response_body_json");
    assert_eq!(
        report.facts["representative"],
        serde_json::json!({
            "case_id": "case-comparison",
            "case_dir": case_dir,
            "response_difference": {
                "pointer": "/users/0/name",
                "kind": "value_mismatch",
                "source_before": "source",
                "candidate": "target",
                "source_after": "source",
            },
        })
    );
}

#[test]
fn dependency_representative_returns_case_entrypoint_and_bounded_difference() {
    let cluster = E2eDirtyCluster {
        cluster_id: "dirty-stable".to_string(),
        protocol: "memcached".to_string(),
        endpoint: Some(E2eDependencyEndpoint {
            host: "cache.internal".to_string(),
            port: 11211,
        }),
        scope: "case".to_string(),
        reason: "unused_recorded".to_string(),
        count: 16,
        case_count: 1,
        case_ids: vec!["case-a".to_string()],
        omitted_case_ids: 0,
        operations: std::collections::BTreeMap::from([("get".to_string(), 16)]),
        omitted_operations: 0,
        source_pre_readiness_interactions: 64,
        representative: Some(E2eDependencyRepresentative {
            case_id: "case-a".to_string(),
            case_dir: std::path::PathBuf::from("/recording/case-a"),
            difference: E2eDependencyDifference {
                kind: "unused_recorded".to_string(),
                expected: E2eDependencyObservation {
                    presence: "present".to_string(),
                    signature: Some(serde_json::json!({"command":"get"})),
                },
                actual: E2eDependencyObservation {
                    presence: "missing".to_string(),
                    signature: None,
                },
            },
        }),
    };

    let target = tempfile::tempdir().unwrap();
    let representative = dependency_representative(target.path(), &cluster);

    assert_eq!(representative["cluster_id"], "dirty-stable");
    assert_eq!(representative["scope"], "case");
    assert_eq!(representative["case_id"], "case-a");
    assert_eq!(representative["case_dir"], "/recording/case-a");
    assert_eq!(
        representative["dependency_difference"]["kind"],
        "unused_recorded"
    );
    assert_eq!(representative["source_pre_readiness_interactions"], 64);
    assert_eq!(
        representative["source_pre_readiness_role"],
        "reference_only"
    );
    assert_eq!(
        representative["dependencies_command"]["argv"],
        serde_json::json!([
            "backend-rewrite",
            "--target-root",
            target.path(),
            "case",
            "dependencies",
            "/recording/case-a"
        ])
    );
    assert!(representative.get("response").is_none());
}

#[test]
fn dirty_cluster_facts_omit_the_duplicate_full_startup_summary() {
    let target = tempfile::tempdir().unwrap();
    let facts = dirty_cluster_facts(
        target.path(),
        E2eDirtyCounts {
            complete: true,
            dirty: false,
            case_event_counts: Default::default(),
            clusters: Vec::new(),
            omitted_clusters: 0,
            source_pre_readiness: Some(E2eSourcePreReadiness {
                phase: "source_pre_readiness".to_string(),
                role: "reference_only".to_string(),
                interaction_count: 128,
                endpoints: Vec::new(),
                unresolved_interactions: 0,
                omitted_interactions: 0,
                truncated: false,
            }),
        },
    );

    assert!(facts.get("source_pre_readiness").is_none());
    assert_eq!(facts["clusters"], serde_json::json!([]));
    assert_eq!(facts["complete"], true);
    assert!(facts["representative_dependencies_command"].is_null());
}

#[test]
fn dirty_cluster_evidence_returns_only_protocol_specific_rule_planners() {
    let target = tempfile::tempdir().unwrap();
    let planners = applicable_rule_planners(
        target.path(),
        RewriteIssueKind::Dependency,
        QUERY_DIRTY_CLUSTERS,
        &serde_json::json!({
            "clusters": [
                {"protocol": "memcached"},
                {"protocol": "http"},
                {"protocol": "memcached"},
                {"protocol": "redis", "operations": {"SCARD": 29, "HGETALL": 1}},
                {"protocol": "mysql"}
            ]
        }),
        "evidence-current",
    );

    assert_eq!(planners.len(), 3);
    assert_eq!(planners[0].protocol, "http");
    assert_eq!(planners[1].protocol, "memcached");
    assert_eq!(planners[2].protocol, "redis");
    assert_eq!(planners[1].evidence_id, "evidence-current");
    assert_eq!(planners[1].command.cwd, target.path());
    assert_eq!(
        planners[1].command.argv,
        [
            "backend-rewrite",
            "--target-root",
            target.path().to_str().unwrap(),
            "dependency-rule",
            "plan",
            "memcached",
            "--help",
        ]
    );
    assert_eq!(
        planners[2].command.argv,
        [
            "backend-rewrite",
            "--target-root",
            target.path().to_str().unwrap(),
            "dependency-rule",
            "plan",
            "redis",
            "--help",
        ]
    );
}

#[test]
fn non_dependency_evidence_does_not_offer_background_rule_planners() {
    let target = tempfile::tempdir().unwrap();
    let planners = applicable_rule_planners(
        target.path(),
        RewriteIssueKind::Replay,
        QUERY_DIRTY_CLUSTERS,
        &serde_json::json!({"clusters": [{"protocol": "http"}]}),
        "evidence-current",
    );

    assert!(planners.is_empty());
}

#[test]
fn pre_readiness_query_returns_only_data_interaction_endpoint_counts() {
    let target = tempfile::tempdir().unwrap();
    let case_source = target.path().join("recording");
    std::fs::create_dir(&case_source).unwrap();
    std::fs::write(
        case_source.join("global-dependencies.jsonl"),
        r#"{"event_type":"redis_connection","global_dependency_phase":"bootstrap","target_host":"cache.internal","target_port":6379}
{"event_type":"redis_exchange","global_dependency_phase":"bootstrap","target_host":"cache.internal","target_port":6379,"command":"PING"}
{"event_type":"redis_exchange","global_dependency_phase":"bootstrap","target_host":"cache.internal","target_port":6379,"command":"GET"}
{"event_type":"redis_exchange","global_dependency_phase":"bootstrap","target_host":"cache.internal","target_port":6379,"command":"GET"}"#,
    )
    .unwrap();
    let mut state = crate::rewrite::test_state();
    state.phase = RewritePhase::ImplementationRequired;
    state.case_source = Some(case_source);
    state.active_issue = Some(RewriteIssue {
        id: "issue-test".to_string(),
        kind: RewriteIssueKind::Response,
        owner: RewriteIssueOwner::TargetCode,
        summary: "response mismatch".to_string(),
        pointer_pattern: None,
        representative: None,
        possible_causes: Vec::new(),
        observed_target_fingerprint: "target".to_string(),
        attempt: 1,
        comparison_observation: None,
    });
    let command = commands(target.path(), &state)
        .into_iter()
        .find(|command| command.query_id.contains("pre-readiness-traffic"))
        .unwrap();

    let report = query(target.path(), &state, &command.query_id).unwrap();

    assert_eq!(report.query, QUERY_PRE_READINESS_TRAFFIC);
    assert_eq!(report.facts["available"], true);
    assert_eq!(report.facts["interaction_count"], 2);
    assert_eq!(report.facts["endpoint_counts"]["cache.internal:6379"], 2);
    assert_eq!(report.facts["excluded_non_data_events"], 2);
    assert!(!report.facts.to_string().contains("PING"));
}
