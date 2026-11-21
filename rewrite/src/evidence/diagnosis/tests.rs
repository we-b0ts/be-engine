use super::*;

fn issue(kind: RewriteIssueKind) -> RewriteIssue {
    serde_json::from_value(json!({"id":"issue","kind":kind,"owner":"target_code",
        "summary":"failed attempt","observed_target_fingerprint":"target","attempt":3}))
    .unwrap()
}

fn diagnose(kind: RewriteIssueKind, facts: &Value) -> Value {
    let mut state = crate::test_state();
    let issue = issue(kind);
    state.active_issue = Some(issue.clone());
    overview(
        &state,
        &issue,
        facts,
        &commands(Path::new("/target"), &state),
    )
}

#[test]
fn rejected_requests_prioritize_native_evidence_and_keep_case_bound_locations() {
    let facts = json!({"execution_failures":[
        {"case_id":"first","failures":[{"kind":"unmatched","protocol":"redis","command":"EVALSHA",
            "reason":"arguments or session differ","target_event_index":4,
            "diagnostic":{"kind":"lane_blocked","blocked_by":{"command":"GET"}}}]},
        {"case_id":"second","failures":[{"kind":"unmatched","protocol":"redis","command":"EVALSHA",
            "reason":"arguments or session differ","target_event_index":12}]}
    ],"execution_failures_summary":{"total":9,"returned":2,"omitted":7}});
    let result = diagnose(RewriteIssueKind::Response, &facts);
    assert_eq!(result["focus"], "dependency_request");
    let group = &result["mismatches"]["groups"][0];
    assert_eq!(group["occurrences_in_overview"], 1);
    assert_eq!(
        result["mismatches"]["groups"].as_array().unwrap().len(),
        2,
        "different native constraints must not share a representative"
    );
    let pointer = group["representative"]["evidence_pointer"]
        .as_str()
        .unwrap()
        .trim_start_matches("/facts");
    assert_eq!(facts.pointer(pointer).unwrap()["target_event_index"], 4);
    assert_eq!(group["representative"]["case_id"], "first");
    assert_eq!(result["execution_coverage"]["omitted"], 7);
    assert!(
        result["next_queries"][0]["query_id"]
            .as_str()
            .unwrap()
            .ends_with("dirty-clusters")
    );
    assert!(
        result["next_queries"][1]["query_id"]
            .as_str()
            .unwrap()
            .ends_with("execution-failures")
    );
    let strategies = result["strategies"].as_array().unwrap();
    assert!(
        strategies
            .iter()
            .any(|strategy| strategy["strategy"] == "native_request_order")
    );
    assert!(
        !strategies
            .iter()
            .any(|strategy| strategy["strategy"] == "source_dependency_ownership")
    );
    let candidate = strategies
        .iter()
        .find(|strategy| strategy["kind"] == "policy_candidate")
        .unwrap();
    assert_eq!(candidate["status"], "requires_difference_and_source_proof");
    assert!(candidate.get("plan_command").is_none());
}

#[test]
fn pending_calls_do_not_become_rejected_requests_or_value_rule_candidates() {
    let facts = json!({"execution_failures":[{
        "case_id":"waiting","kind":"case_no_progress","failures":[{"kind":"case_no_progress",
            "waiting":{"pending_source_dependencies":5}}]}]});
    let response_issue = diagnose(RewriteIssueKind::Response, &facts);
    assert!(
        response_issue["strategies"]
            .as_array()
            .unwrap()
            .iter()
            .all(|strategy| strategy["kind"] != "policy_candidate")
    );
    let result = diagnose(
        RewriteIssueKind::Dependency,
        &json!({"execution_failures":[{
        "case_id":"waiting","kind":"case_no_progress","failures":[{"kind":"case_no_progress",
            "waiting":{"pending_source_dependencies":5}}]}]}),
    );
    assert_eq!(result["focus"], "unconsumed_dependencies");
    assert!(
        result["strategies"]
            .as_array()
            .unwrap()
            .iter()
            .all(|strategy| strategy["kind"] != "policy_candidate")
    );
    let mixed = diagnose(
        RewriteIssueKind::Dependency,
        &json!({"execution_failures":[{
        "case_id":"mixed","failures":[{"kind":"case_no_progress"},{"kind":"unmatched","protocol":"mysql"}]}]}),
    );
    assert_eq!(mixed["focus"], "dependency_execution");
}

#[test]
fn absent_response_observations_do_not_suggest_value_rules() {
    let result = diagnose(
        RewriteIssueKind::Response,
        &json!({"execution_evidence":{"available":false}}),
    );
    assert!(
        result["strategies"]
            .as_array()
            .unwrap()
            .iter()
            .all(|strategy| strategy["kind"] != "policy_candidate")
    );
}

#[test]
fn runtime_interruptions_and_quality_work_do_not_offer_value_policies() {
    for (kind, facts, expected) in [
        (
            RewriteIssueKind::Response,
            json!({"primary_failure":{"kind":"replay_interrupted"}}),
            "target_runtime",
        ),
        (RewriteIssueKind::TargetQuality, json!({}), "target_quality"),
    ] {
        let result = diagnose(kind, &facts);
        assert_eq!(result["focus"], expected);
        assert!(
            result["strategies"]
                .as_array()
                .unwrap()
                .iter()
                .all(|strategy| strategy["kind"] != "policy_candidate")
        );
    }
}

#[test]
fn diagnosis_bounds_groups_and_never_translates_preview_counts_to_api_totals() {
    let failures = (0..20).map(|index| json!({"case_id":format!("case-{index}"),
        "failures":[{"protocol":"redis","command":format!("operation-{index}"),"kind":"unmatched"}]})).collect::<Vec<_>>();
    let result = diagnose(
        RewriteIssueKind::Dependency,
        &json!({"execution_failures":failures}),
    );
    assert_eq!(
        result["mismatches"]["groups"].as_array().unwrap().len(),
        GROUP_LIMIT
    );
    assert_eq!(result["mismatches"]["omitted_groups"], 20 - GROUP_LIMIT);
    assert!(
        result["mismatches"]["coverage"]
            .as_str()
            .unwrap()
            .contains("not whole API totals")
    );
}
