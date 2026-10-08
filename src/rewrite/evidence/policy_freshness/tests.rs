use super::super::rule_guidance::{applicable_rule_planners, rule_hints};
use super::*;

fn state() -> RewriteState {
    let mut state = crate::rewrite::test_state();
    state.api = "POST /api/subscriptions".into();
    state.recording_run_id = "20261007070123".into();
    state
}

#[test]
fn policy_freshness_stale_or_missing_identity_disables_planners_but_keeps_diagnosis() {
    let root = Path::new("/target");
    let state = state();
    for evidence in [Some("old"), None] {
        for query in [QUERY_DIRTY_CLUSTERS, QUERY_REPRESENTATIVES] {
            let mut facts = json!({
                "clusters":[{"protocol":"mysql","reason":"unmatched_target"}],
                "representative":{"pointer":"$headers/content-disposition"}
            });
            let original = facts.clone();
            let freshness = ReplayEvidencePolicyFreshness::new(evidence, "current");
            let next = project(root, &state, &mut facts, &freshness)
                .unwrap()
                .unwrap();
            assert_eq!(facts["clusters"], original["clusters"]);
            assert_eq!(facts["representative"], original["representative"]);
            assert!(next.contains("existing recording"));
            assert_eq!(facts["policy_freshness"]["requires_fresh_replay"], true);
            assert_eq!(
                facts["policy_freshness"]["recording_run_id"],
                "20261007070123"
            );
            let argv = facts["policy_freshness"]["refresh_command"]["argv"]
                .as_array()
                .unwrap();
            assert!(
                argv.windows(3).any(
                    |args| args == [json!("next"), json!("--api"), json!("/api/subscriptions")]
                )
            );
            assert!(
                applicable_rule_planners(
                    root,
                    RewriteIssueKind::Response,
                    query,
                    &facts,
                    "evidence"
                )
                .is_empty()
            );
            let hints = rule_hints(root, query, &facts);
            assert_eq!(hints.len(), 1);
            assert_eq!(hints[0].capability, "fresh_replay");
            assert_eq!(
                serde_json::to_value(&hints[0].help).unwrap(),
                facts["policy_freshness"]["refresh_command"]
            );
        }
    }
}

#[test]
fn policy_freshness_current_identity_restores_generated_value_planners() {
    let root = Path::new("/target");
    let state = state();
    for (query, capability) in [
        (QUERY_DIRTY_CLUSTERS, "dynamic_value"),
        (QUERY_REPRESENTATIVES, "response_header_date"),
    ] {
        let mut facts = json!({"clusters":[{"protocol":"mysql","reason":"unmatched_target"}],"representative":{"pointer":"$headers/content-disposition"}});
        let current = ReplayEvidencePolicyFreshness::new(Some("current"), "current");
        assert!(
            project(root, &state, &mut facts, &current)
                .unwrap()
                .is_none()
        );
        assert_eq!(facts["policy_freshness"]["status"], "current");
        assert!(facts["policy_freshness"].get("refresh_command").is_none());
        assert!(
            applicable_rule_planners(
                root,
                RewriteIssueKind::Response,
                query,
                &facts,
                "new-evidence"
            )
            .iter()
            .any(|planner| planner.capability == capability)
        );
    }
}

#[test]
fn policy_freshness_checks_comparison_policy_changes_without_changing_artifacts() {
    use crate::rewrite::model::RewriteIssueOwner;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let path = root.join(".traffic-e2e/verification.yaml");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let original = "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n";
    std::fs::write(&path, original).unwrap();
    let fingerprint = crate::validate_replay_policy(&path).unwrap().fingerprint;
    let mut state = state();
    state.comparison_run_id = Some("comparison".into());
    let report = root
        .join(crate::repository::LOCAL_ARTIFACTS_ROOT)
        .join("comparison-recordings/comparison/comparison-report.json");
    std::fs::create_dir_all(report.parent().unwrap()).unwrap();
    let bytes = serde_json::to_vec(&json!({"policy_fingerprint":fingerprint})).unwrap();
    std::fs::write(&report, &bytes).unwrap();
    let issue = RewriteIssue {
        id: "comparison".into(),
        kind: RewriteIssueKind::Comparison,
        owner: RewriteIssueOwner::SourceInvestigation,
        summary: "header difference".into(),
        pointer_pattern: None,
        representative: None,
        egress_rejections: None,
        recorder_capture_diagnosis: None,
        response_diagnosis: None,
        possible_causes: Vec::new(),
        observed_target_fingerprint: "target".into(),
        attempt: 1,
        comparison_observation: None,
    };
    let mut facts = json!({"representative":{"pointer":"$headers/content-disposition"}});
    assert!(
        attach(root, &state, &issue, QUERY_REPRESENTATIVES, &mut facts)
            .unwrap()
            .is_none()
    );
    std::fs::write(&path, format!("{original}# policy changed\n")).unwrap();
    assert!(
        attach(root, &state, &issue, QUERY_REPRESENTATIVES, &mut facts)
            .unwrap()
            .is_some()
    );
    assert_eq!(facts["policy_freshness"]["status"], "stale");
    assert_eq!(std::fs::read(&report).unwrap(), bytes);
    std::fs::remove_file(report).unwrap();
    let original_fact = facts["representative"].clone();
    assert!(
        attach(root, &state, &issue, QUERY_REPRESENTATIVES, &mut facts)
            .unwrap()
            .is_some()
    );
    assert_eq!(facts["policy_freshness"]["status"], "unavailable");
    assert!(facts["policy_freshness"]["unavailable_reason"].is_string());
    assert_eq!(facts["representative"], original_fact);
}
