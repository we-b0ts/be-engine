use super::*;
use crate::rewrite::inventory;
use crate::rewrite::model::{RewriteAttemptDelta, RewriteIssueOwner, RewritePhase};
use crate::{
    E2eDependencyDifference, E2eDependencyEndpoint, E2eDependencyObservation,
    E2eDependencyRepresentative, E2eDirtyCluster, E2eDirtyCounts, E2eRepresentativeDifference,
    E2eSourcePreReadiness, ResponseDifferenceKind,
};

#[test]
fn target_runtime_evidence_starts_with_container_diagnostics() {
    let target = tempfile::tempdir().unwrap();
    let mut state = crate::rewrite::test_state();
    state.phase = RewritePhase::ImplementationRequired;
    state.active_issue = Some(RewriteIssue {
        id: "issue-target-runtime".to_string(),
        kind: RewriteIssueKind::TargetRuntime,
        owner: RewriteIssueOwner::TargetRuntime,
        summary: "target did not become ready".to_string(),
        pointer_pattern: None,
        representative: None,
        response_diagnosis: None,
        possible_causes: Vec::new(),
        observed_target_fingerprint: "target".to_string(),
        attempt: 2,
        comparison_observation: None,
    });

    let commands = commands(target.path(), &state);

    assert!(commands[0].query_id.ends_with("target-runtime-diagnostics"));
    assert!(commands[0].purpose.contains("target stdout"));
    assert!(
        commands
            .iter()
            .all(|command| !command.query_id.ends_with("source-process-traffic"))
    );
}

#[test]
fn startup_runtime_issue_advertises_source_process_evidence() {
    let target = tempfile::tempdir().unwrap();
    let mut state = crate::rewrite::test_state();
    state.phase = RewritePhase::ImplementationRequired;
    state.active_issue = Some(RewriteIssue {
        id: "issue-target-startup".to_string(),
        kind: RewriteIssueKind::TargetRuntime,
        owner: RewriteIssueOwner::TargetRuntime,
        summary: "target did not become ready".to_string(),
        pointer_pattern: None,
        representative: None,
        response_diagnosis: None,
        possible_causes: vec!["source_compatible_configuration".to_string()],
        observed_target_fingerprint: "target".to_string(),
        attempt: 1,
        comparison_observation: None,
    });

    let command = commands(target.path(), &state)
        .into_iter()
        .find(|command| command.query_id.ends_with("source-process-traffic"))
        .unwrap();

    assert!(command.purpose.contains("startup or readiness"));
}

#[test]
fn dependency_issue_leads_with_dirty_then_source_process_evidence() {
    let target = tempfile::tempdir().unwrap();
    let mut state = crate::rewrite::test_state();
    state.phase = RewritePhase::ImplementationRequired;
    state.active_issue = Some(RewriteIssue {
        id: "issue-dependency".to_string(),
        kind: RewriteIssueKind::Dependency,
        owner: RewriteIssueOwner::SourceInvestigation,
        summary: "dependency evidence is dirty".to_string(),
        pointer_pattern: None,
        representative: None,
        response_diagnosis: None,
        possible_causes: Vec::new(),
        observed_target_fingerprint: "target".to_string(),
        attempt: 1,
        comparison_observation: None,
    });

    let commands = commands(target.path(), &state);

    assert!(commands[0].query_id.ends_with("dirty-clusters"));
    assert!(commands[1].query_id.ends_with("source-process-traffic"));
    assert!(
        commands[1]
            .purpose
            .contains("request-owned or process-owned")
    );
}

#[test]
fn response_evidence_starts_with_paged_case_differences_and_rejects_stale_pages() {
    let target = tempfile::tempdir().unwrap();
    let mut state = crate::rewrite::test_state();
    state.phase = RewritePhase::ImplementationRequired;
    state.active_issue = Some(RewriteIssue {
        id: "issue-response".to_string(),
        kind: RewriteIssueKind::Response,
        owner: RewriteIssueOwner::TargetCode,
        summary: "response mismatch".to_string(),
        pointer_pattern: Some("/items/*/value".to_string()),
        representative: Some(E2eRepresentativeDifference {
            case_id: "case-1".to_string(),
            pointer: "/items/0/value".to_string(),
            difference_kind: ResponseDifferenceKind::MissingActual,
            gateway_protocol: Some(crate::ResponseGatewayProtocol::Http),
            body_codec: Some(crate::ResponseBodyCodec::Json),
            body_diagnosis: None,
            unavailable_reason: None,
            expected: E2eValueObservation {
                presence: E2eValuePresence::Present,
                value: Some(Value::from(1)),
            },
            actual: E2eValueObservation {
                presence: E2eValuePresence::Missing,
                value: None,
            },
        }),
        response_diagnosis: None,
        possible_causes: Vec::new(),
        observed_target_fingerprint: "target".to_string(),
        attempt: 2,
        comparison_observation: None,
    });

    let commands = commands(target.path(), &state);

    assert_eq!(
        commands[0].purpose,
        "Inspect all response differences in the representative case before implementation"
    );
    assert!(
        commands[0]
            .query_id
            .contains("case-response-differences-case-")
    );
    assert!(commands[0].query_id.ends_with("-page-0"));
    assert_eq!(commands[0].command.argv[3], "evidence");
    assert_eq!(commands[0].command.argv[4], commands[0].query_id);
    let next_page =
        case_response_difference_query_id(&state, state.active_issue.as_ref().unwrap(), 20);
    assert_eq!(
        case_response_difference_offset(&state, state.active_issue.as_ref().unwrap(), &next_page,),
        Some(20)
    );
    state.active_issue.as_mut().unwrap().attempt += 1;
    assert_eq!(
        case_response_difference_offset(&state, state.active_issue.as_ref().unwrap(), &next_page,),
        None
    );
}

#[test]
fn unavailable_response_evidence_omits_value_and_policy_queries() {
    let target = tempfile::tempdir().unwrap();
    let mut state = crate::rewrite::test_state();
    state.phase = RewritePhase::ImplementationRequired;
    state.active_issue = Some(RewriteIssue {
        id: "issue-response-unavailable".to_string(),
        kind: RewriteIssueKind::Response,
        owner: RewriteIssueOwner::TargetCode,
        summary: "response unavailable".to_string(),
        pointer_pattern: Some("$response".to_string()),
        representative: Some(E2eRepresentativeDifference {
            case_id: "case-1".to_string(),
            pointer: "$response".to_string(),
            difference_kind: ResponseDifferenceKind::ResponseUnavailable,
            gateway_protocol: None,
            body_codec: None,
            body_diagnosis: None,
            unavailable_reason: Some(crate::E2eResponseUnavailableReason::TargetConnectionClosed),
            expected: E2eValueObservation {
                presence: E2eValuePresence::Present,
                value: None,
            },
            actual: E2eValueObservation {
                presence: E2eValuePresence::Unavailable,
                value: None,
            },
        }),
        response_diagnosis: None,
        possible_causes: Vec::new(),
        observed_target_fingerprint: "target".to_string(),
        attempt: 2,
        comparison_observation: None,
    });

    let purposes = commands(target.path(), &state)
        .into_iter()
        .map(|command| command.purpose)
        .collect::<Vec<_>>();

    assert!(
        purposes
            .iter()
            .any(|purpose| purpose.contains("all response differences"))
    );
    assert!(
        purposes
            .iter()
            .any(|purpose| purpose.contains("dependency cleanliness"))
    );
    assert!(
        !purposes
            .iter()
            .any(|purpose| purpose.contains("source value"))
    );
    assert!(!purposes.iter().any(|purpose| purpose.contains("multisets")));
    assert!(
        !purposes
            .iter()
            .any(|purpose| purpose.contains("rule applicability"))
    );
}

#[test]
fn response_source_process_evidence_exposes_bootstrap_redis_planner() {
    let planners = applicable_rule_planners(
        Path::new("/target"),
        RewriteIssueKind::Response,
        QUERY_SOURCE_PROCESS_TRAFFIC,
        &serde_json::json!({
            "available": true,
            "bootstrap": {
                "protocols": ["redis"]
            }
        }),
        "evidence-bootstrap",
    );

    let planner = planners
        .iter()
        .find(|planner| planner.capability == "redis_bootstrap")
        .unwrap();
    assert_eq!(planner.kind, "dependency_ownership");
    assert_eq!(planner.evidence_id, "evidence-bootstrap");
    assert!(planner.command.argv.iter().any(|arg| arg == "redis"));
}

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
        response_diagnosis: None,
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
            gateway_protocol: Some(crate::ResponseGatewayProtocol::Http),
            body_codec: Some(crate::ResponseBodyCodec::Json),
            body_diagnosis: None,
            unavailable_reason: None,
            expected: E2eValueObservation {
                presence: E2eValuePresence::Present,
                value: Some(Value::from(403)),
            },
            actual: E2eValueObservation {
                presence: E2eValuePresence::Present,
                value: Some(Value::from(200)),
            },
        }),
        response_diagnosis: None,
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
            "gateway_protocol": "http",
            "body_codec": "json",
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
    assert!(report.applicable_rule_planners.is_empty());
}

#[test]
fn comparison_representatives_link_the_comparison_case_and_three_way_difference() {
    let target = tempfile::tempdir().unwrap();
    let run_id = "20260802120000";
    let case_dir = target
        .path()
        .join(".traffic-e2e/local/artifacts/comparison-recordings")
        .join(run_id)
        .join("apis/api-comparison")
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
        response_diagnosis: None,
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
fn motan_dirty_cluster_guidance_rules_out_business_argument_mismatch() {
    let limitations = dirty_cluster_limitations(&serde_json::json!({
        "clusters": [{"protocol": "motan", "reason": "unmatched_target"}]
    }));

    assert_eq!(
        limitations,
        [
            "dirty event counts do not prove process ownership",
            "they do not prove response causality",
            "Motan dirty evidence does not indicate a business-argument mismatch",
        ]
    );
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

    assert_eq!(planners.len(), 4);
    assert_eq!(planners[0].capability, "http");
    assert_eq!(planners[1].capability, "memcached");
    assert_eq!(planners[2].capability, "mysql");
    assert_eq!(planners[3].capability, "redis");
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
            "mysql",
            "--help",
        ]
    );
}

#[test]
fn memcached_dirty_clusters_expose_the_value_rule_help_without_claiming_applicability() {
    let target = tempfile::tempdir().unwrap();
    let rules = rule_hints(
        target.path(),
        QUERY_DIRTY_CLUSTERS,
        &serde_json::json!({
            "clusters": [
                {"protocol": "memcached", "reason": "unmatched_actual"},
                {"protocol": "memcached", "reason": "unused_recorded"}
            ]
        }),
    );

    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].capability, "memcached");
    assert_eq!(rules[0].rule, "protobuf-timestamp");
    assert!(rules[0].hint.contains("Memcached SET value"));
    assert!(rules[0].hint.starts_with("Investigate"));
    assert_eq!(
        rules[0].help.argv,
        [
            "backend-rewrite",
            "--target-root",
            target.path().to_str().unwrap(),
            "dependency-rule",
            "plan",
            "memcached",
            "protobuf-timestamp",
            "--help",
        ]
    );
}

#[test]
fn focused_response_body_candidate_offers_the_unified_response_rule_planner() {
    let target = tempfile::tempdir().unwrap();
    let facts = serde_json::json!({
        "representative": {
            "response_difference": {
                "pointer": "$body",
                "body_diagnosis": {
                    "codec": "protobuf",
                    "codec_candidates": ["protobuf"],
                    "configured": false,
                    "unordered_path_candidates": [{"field_path": [3, 3]}]
                }
            }
        }
    });

    let hints = rule_hints(target.path(), QUERY_REPRESENTATIVES, &facts);
    let planners = applicable_rule_planners(
        target.path(),
        RewriteIssueKind::Response,
        QUERY_REPRESENTATIVES,
        &facts,
        "evidence-current",
    );

    assert_eq!(hints.len(), 1);
    assert_eq!(hints[0].rule, "response_body");
    assert_eq!(hints[0].capability, "protobuf");
    assert!(hints[0].hint.contains("focused-E2E or comparison"));
    assert_eq!(planners.len(), 1);
    assert_eq!(planners[0].kind, "response_body");
    assert_eq!(planners[0].capability, "protobuf");
    assert!(
        planners[0]
            .command
            .argv
            .ends_with(&["--body-codec".to_string(), "protobuf".to_string(),])
    );
}

#[test]
fn configured_response_body_candidate_offers_selector_help() {
    let target = tempfile::tempdir().unwrap();
    let facts = serde_json::json!({
        "comparison_observation": {
            "pointer": "$body",
            "body_diagnosis": {
                "codec": "hessian2",
                "codec_candidates": ["hessian2"],
                "configured": true,
                "unordered_path_candidates": [{"value_path": []}]
            }
        }
    });

    let hints = rule_hints(target.path(), QUERY_REPRESENTATIVES, &facts);
    let planners = applicable_rule_planners(
        target.path(),
        RewriteIssueKind::Comparison,
        QUERY_REPRESENTATIVES,
        &facts,
        "evidence-current",
    );

    assert_eq!(hints.len(), 1);
    assert!(hints[0].hint.contains("source-proven"));
    assert_eq!(planners.len(), 1);
    assert_eq!(planners[0].capability, "hessian2");
    assert_eq!(planners[0].command.argv.last().unwrap(), "--help");
}

#[test]
fn response_issues_can_query_dirty_clusters_for_protocol_rule_discovery() {
    let mut state = crate::rewrite::test_state();
    state.active_issue = Some(RewriteIssue {
        id: "issue-response-with-dirty-dependency".to_string(),
        kind: RewriteIssueKind::Response,
        owner: RewriteIssueOwner::TargetCode,
        summary: "response and dependency differ".to_string(),
        pointer_pattern: None,
        representative: None,
        response_diagnosis: None,
        possible_causes: Vec::new(),
        observed_target_fingerprint: "target".to_string(),
        attempt: 1,
        comparison_observation: None,
    });

    assert!(
        query_kinds(&state, state.active_issue.as_ref().unwrap())
            .iter()
            .any(|(query, _)| *query == QUERY_DIRTY_CLUSTERS)
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
fn source_process_query_returns_bounded_bootstrap_and_process_owned_evidence() {
    let target = tempfile::tempdir().unwrap();
    let case_source = target.path().join("recording");
    std::fs::create_dir(&case_source).unwrap();
    std::fs::write(
        case_source.join("source-process-traffic-summary.json"),
        r#"{
  "version": 1,
  "source": "recorder_events",
  "bootstrap": {
    "events": 3,
    "data_interactions": 2,
    "excluded_events": 1,
    "unresolved_interactions": 0,
    "observations": [{"protocol":"redis","endpoint":"cache.internal:6379","operation":"GET","interactions":2}],
    "omitted_interactions": 0,
    "truncated": false
  },
  "background": {
    "events": 2,
    "data_interactions": 2,
    "excluded_events": 0,
    "unresolved_interactions": 0,
    "rules": [{
      "name": "startup-cache-warm",
      "interactions": 2,
      "bootstrap_interactions": 1,
      "runtime_interactions": 1,
      "other_phase_interactions": 0,
      "unresolved_interactions": 0,
      "observations": [{"protocol":"redis","endpoint":"cache.internal:6379","operation":"HGET","interactions":2}],
      "omitted_interactions": 0,
      "truncated": false,
      "redis_snapshot": {
        "seeds":1,
        "reuses":1,
        "fill_failures":0,
        "endpoints":[{"endpoint":"cache.internal:6379","seeds":1,"reuses":1,"fill_failures":0}],
        "omitted_interactions":0,
        "truncated":false
      }
    }],
    "omitted_interactions": 0,
    "truncated": false
  },
  "interpretation": "triage only"
}"#,
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
        response_diagnosis: None,
        possible_causes: Vec::new(),
        observed_target_fingerprint: "target".to_string(),
        attempt: 1,
        comparison_observation: None,
    });
    let command = commands(target.path(), &state)
        .into_iter()
        .find(|command| command.query_id.contains("source-process-traffic"))
        .unwrap();

    let report = query(target.path(), &state, &command.query_id).unwrap();

    assert_eq!(report.query, QUERY_SOURCE_PROCESS_TRAFFIC);
    assert_eq!(report.facts["available"], true);
    assert_eq!(report.facts["scope"], "recording_global");
    assert_eq!(report.facts["bootstrap"]["data_interactions"], 2);
    assert_eq!(report.facts["bootstrap"]["protocols"][0], "redis");
    assert_eq!(
        report.facts["bootstrap"]["observations"][0]["operation"],
        "GET"
    );
    assert_eq!(
        report.facts["process_owned"]["rules"][0]["redis_snapshot"]["reuses"],
        1
    );
    assert!(
        report
            .applicable_rule_planners
            .iter()
            .any(|planner| planner.capability == "redis_bootstrap")
    );
}
