use super::*;

#[test]
fn nested_body_pages_are_issue_and_report_bound() {
    let mut state = crate::rewrite::test_state();
    state.active_issue = Some(RewriteIssue {
        id: "issue-http".into(),
        kind: RewriteIssueKind::Dependency,
        owner: crate::rewrite::model::RewriteIssueOwner::SourceInvestigation,
        summary: "HTTP request mismatch".into(),
        pointer_pattern: None,
        representative: None,
        egress_rejections: None,
        recorder_capture_diagnosis: None,
        response_diagnosis: None,
        possible_causes: Vec::new(),
        observed_target_fingerprint: "target".into(),
        attempt: 1,
    });
    let issue = state.active_issue.as_ref().unwrap();
    let query = Query::Body {
        failure: 2,
        candidate: 1,
        side: http_request_diagnosis::Side::Target,
        offset: 16384,
    };
    let mut facts = json!({"target_body_query":query});
    let binding = format!("sha256:{}", "a".repeat(64));
    attach_commands(Path::new("/target"), &state, issue, &binding, &mut facts).unwrap();
    let id = facts["target_body_query"]["query_id"].as_str().unwrap();
    assert_eq!(parse(&state, issue, id), Some((query, Some(binding))));
    assert!(super::super::accepts_query(&state, id));
    let mut stale = issue.clone();
    stale.attempt += 1;
    assert!(parse(&state, &stale, id).is_none());
    assert!(
        parse(
            &state,
            issue,
            &format!("{}-garbage", query_id(&state, issue, QUERY_HTTP_REQUESTS))
        )
        .is_none()
    );
}
