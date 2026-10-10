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
