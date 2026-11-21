#[cfg(test)]
use super::*;
pub(crate) use traffic_rewrite_evidence::evidence::execution::*;
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unconsumed_guidance_preserves_old_and_current_wait_details_without_claiming_rejection() {
        for timeout in [2000, 5000] {
            let failures = [json!({"kind":"case_no_progress","case_id":"case",
                "failures":[{"kind":"case_no_progress","reason":"historical reason",
                    "waiting":{"no_progress_timeout_ms":timeout,"pending_source_dependencies":7}}]})];
            let text = guidance(&failures);
            assert!(text.starts_with("Recorded Case dependencies remain unconsumed"));
            assert!(text.contains("corresponding Target calls"));
            assert!(text.contains("idle duration records when Replay ended this wait"));
            assert!(!text.contains("did not match"));
            assert!(!text.contains("engine timeout"));
        }
        let historical = [json!({"failures":[{"kind":"case_no_progress"}]})];
        assert!(has_unconsumed_dependencies(&historical));
        assert!(!has_rejected_dependencies(&historical));
    }

    #[test]
    fn rejected_and_mixed_guidance_preserve_the_actual_target_rejection() {
        for failure in [
            json!({"kind":"dependency_unmatched"}),
            json!({"failures":[{"protocol":"redis","target_event_index":1}]}),
        ] {
            let text = guidance(std::slice::from_ref(&failure));
            assert!(text.starts_with("Replay rejected a Target dependency request"));
            assert!(!text.contains("remain unconsumed"));
            let text = guidance(&[json!({"kind":"case_no_progress"}), failure]);
            assert!(text.starts_with("Recorded Case dependencies remain unconsumed"));
            assert!(text.contains("Other execution_failures include rejected Target requests"));
        }
    }

    #[test]
    fn one_case_can_retain_both_unconsumed_dependencies_and_rejected_target_calls() {
        for kind in [None, Some("case_no_progress"), Some("dependency_unmatched")] {
            let mut failure = json!({"case_id":"mixed","failures":[
                {"kind":"case_no_progress","waiting":{"pending_source_dependencies":7}},
                {"kind":"unmatched","protocol":"redis","target_event_index":1}
            ]});
            if let Some(kind) = kind {
                failure["kind"] = kind.into();
            }
            let failures = [failure];
            assert!(has_unconsumed_dependencies(&failures));
            assert!(has_rejected_dependencies(&failures));
            assert!(guidance(&failures).contains("rejected Target requests"));
        }
        let explicit_rejection = [json!({"kind":"dependency_unmatched",
            "failures":[{"kind":"case_no_progress"}]})];
        assert!(has_rejected_dependencies(&explicit_rejection));
        let legacy_idle_only = [json!({"failures":[{"kind":"case_no_progress"}]})];
        assert!(!has_rejected_dependencies(&legacy_idle_only));
    }

    #[test]
    fn execution_failure_pages_retain_issue_attempt_api_and_inventory_identity() {
        let mut state = crate::test_state();
        let issue = RewriteIssue {
            id: "issue".into(),
            kind: RewriteIssueKind::Dependency,
            owner: crate::RewriteIssueOwner::TargetCode,
            summary: "unmatched GET".into(),
            pointer_pattern: None,
            representative: None,
            egress_rejections: None,
            recorder_capture_diagnosis: None,
            response_diagnosis: None,
            possible_causes: vec![],
            observed_target_fingerprint: "target".into(),
            attempt: 11,
        };
        let page = id(&state, &issue, 8);
        assert_eq!(parse(&state, &issue, &page), Some(8));
        assert_ne!(page, id(&state, &issue, 0));
        state.revision += 1;
        assert_eq!(parse(&state, &issue, &page), Some(8));
        let original_inventory = state.case_inventory_id.clone();
        state.case_inventory_id = Some("other-inventory".into());
        assert_eq!(parse(&state, &issue, &page), None);
        state.case_inventory_id = original_inventory;
        let mut changed = issue.clone();
        changed.attempt += 1;
        assert_eq!(parse(&state, &changed, &page), None);
        changed = issue.clone();
        changed.kind = RewriteIssueKind::TargetQuality;
        assert_eq!(parse(&state, &changed, &id(&state, &changed, 8)), None);
        state.api = "POST /another".into();
        assert_eq!(parse(&state, &issue, &page), None);
        assert_eq!(
            parse(&state, &issue, "evq-fake-execution-failures-page-8"),
            None
        );
    }
}
