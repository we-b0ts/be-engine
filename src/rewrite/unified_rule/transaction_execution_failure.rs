//! Retained response issues still expose the cause of interrupted execution.
use super::*;

#[test]
fn overview_prioritizes_dependency_cause_without_replacing_the_retained_issue() {
    let fixture = Fixture::new();
    fixture.confirm();
    let original = fixture.state();
    let state_path = fixture
        .paths
        .replay
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("state.yaml");
    let mut focused: serde_json::Value =
        serde_yaml::from_str(&fs::read_to_string(&state_path).unwrap()).unwrap();
    focused["cases"][0]["execution_failure"] = json!({
        "kind":"dependency_unmatched","case_id":"00000000-0000-4000-8000-000000000001","request_completed":false,
        "failures":[{"protocol":"redis","command":"SET","target_event_index":1}]
    });
    fs::write(&state_path, serde_yaml::to_string(&focused).unwrap()).unwrap();
    let scope = RewriteWorkScope::Api { api: "/api".into() };
    let overview = query_rewrite_evidence_for_scope(fixture.context(), &scope).unwrap();
    assert_eq!(
        overview.facts["primary_failure"]["kind"],
        "dependency_unmatched"
    );
    assert_eq!(
        overview.facts["execution_failures"][0]["failures"][0]["command"],
        "SET"
    );
    assert!(overview.queries[0].query_id.ends_with("-dirty-clusters"));
    assert_eq!(
        overview.facts["dependency_diagnosis"]["query_id"],
        overview.queries[0].query_id
    );
    assert!(
        overview
            .next_step
            .contains("Other cases may have independent response failures")
    );
    assert_eq!(
        overview.facts["issue"],
        serde_json::to_value(original.active_issue.as_ref().unwrap()).unwrap()
    );
    assert_eq!(
        serde_json::to_value(fixture.state()).unwrap(),
        serde_json::to_value(&original).unwrap()
    );

    // Historical no-progress evidence retains its waiting details while leading with unused calls.
    focused["cases"][0]["execution_failure"] = json!({
        "kind":"case_no_progress","case_id":"00000000-0000-4000-8000-000000000001","request_completed":false,
        "failures":[{"kind":"case_no_progress","waiting":{
            "no_progress_timeout_ms":5000,"pending_source_dependencies":7,
            "references":[{"reference":{"protocol":"mysql","sequence":1127},"state":"Available"}]
        }}]
    });
    fs::write(&state_path, serde_yaml::to_string(&focused).unwrap()).unwrap();
    let unconsumed = query_rewrite_evidence_for_scope(fixture.context(), &scope).unwrap();
    assert_eq!(
        unconsumed.facts["primary_failure"]["kind"],
        "case_execution_incomplete"
    );
    assert!(
        unconsumed
            .next_step
            .starts_with("Recorded Case dependencies remain unconsumed")
    );
    assert!(unconsumed.next_step.contains("corresponding Target calls"));
    assert!(!unconsumed.next_step.contains("did not match"));
    assert_eq!(
        unconsumed.facts["execution_failures"][0]["failures"][0]["waiting"]["no_progress_timeout_ms"],
        5000
    );
    assert_eq!(
        unconsumed.facts["issue"],
        serde_json::to_value(original.active_issue.as_ref().unwrap()).unwrap()
    );

    // A runtime interruption supersedes case failures without replacing the
    // retained issue; the diagnostic query remains available without aggregates.
    focused["status"] = json!("interrupted");
    focused["replay_finalized"] = json!(false);
    focused["cases"][0]["assertion_passed"] = json!(false);
    focused["errors"] = json!([
        "old case dirty",
        "last case dirty",
        "control disconnected",
        "control read reset"
    ]);
    fs::write(&state_path, serde_yaml::to_string(&focused).unwrap()).unwrap();
    let interrupted = query_rewrite_evidence_for_scope(fixture.context(), &scope).unwrap();
    assert_eq!(
        interrupted.facts["primary_failure"]["kind"],
        "replay_interrupted"
    );
    assert!(
        interrupted.queries[0]
            .query_id
            .ends_with("-target-runtime-diagnostics")
    );
    assert_eq!(
        interrupted.facts["runtime_diagnosis"]["query_id"],
        interrupted.queries[0].query_id
    );
    assert_eq!(
        interrupted.facts["execution_context"]["lifecycle_errors"],
        json!([
            "last case dirty",
            "control disconnected",
            "control read reset"
        ])
    );
    assert!(
        interrupted
            .next_step
            .contains("overview ID is not a route diagnostic")
    );

    // A later attempt cannot supply the cause of an older retained issue.
    focused["sequence"] = json!(focused["sequence"].as_u64().unwrap() + 1);
    fs::write(&state_path, serde_yaml::to_string(&focused).unwrap()).unwrap();
    let stale = query_rewrite_evidence_for_scope(fixture.context(), &scope).unwrap();
    assert!(stale.facts.get("execution_failures").is_none());
}
