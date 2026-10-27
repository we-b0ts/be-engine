//! Issue-bound pages retain per-Case rejection evidence beyond the overview limit.
use super::*;

pub(super) const KIND: &str = "execution_failures";

pub(super) fn id(state: &RewriteState, issue: &RewriteIssue, offset: usize) -> String {
    if offset == 0 {
        super::query_id(state, issue, KIND)
    } else {
        super::query_id(state, issue, &format!("{KIND}_page_{offset}"))
    }
}

pub(super) fn parse(state: &RewriteState, issue: &RewriteIssue, query: &str) -> Option<usize> {
    if !matches!(
        issue.kind,
        RewriteIssueKind::Response | RewriteIssueKind::Dependency | RewriteIssueKind::Replay
    ) {
        return None;
    }
    if query == id(state, issue, 0) {
        return Some(0);
    }
    let offset = query.rsplit_once("-page-")?.1.parse::<usize>().ok()?;
    (id(state, issue, offset) == query).then_some(offset)
}

fn command(root: &Path, state: &RewriteState, issue: &RewriteIssue, offset: usize) -> Value {
    json!(super::super::action::command(
        root,
        vec!["evidence".into(), id(state, issue, offset)],
        vec![]
    ))
}

pub(super) fn attach(
    root: &Path,
    state: &RewriteState,
    issue: &RewriteIssue,
    execution: &Value,
    facts: &mut Value,
) {
    facts["execution_failures"] = execution["execution_failures"].clone();
    facts["execution_failures_summary"] = execution["execution_failures_summary"].clone();
    facts["execution_failures_query"] = command(root, state, issue, 0);
}

pub(super) fn facts(
    root: &Path,
    state: &RewriteState,
    issue: &RewriteIssue,
    offset: usize,
) -> Result<Value> {
    let mut facts = crate::e2e_run::query_execution_failure_page(
        super::e2e_context(root, state)?,
        super::group_id(state)?,
        issue.attempt,
        offset,
    )?;
    if let Some(next) = facts["pagination"]["next_offset"].as_u64() {
        facts["pagination"]["next_page"] = command(root, state, issue, usize::try_from(next)?);
    }
    Ok(facts)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn execution_failure_pages_retain_issue_attempt_api_and_inventory_identity() {
        let mut state = crate::rewrite::test_state();
        let issue = RewriteIssue {
            id: "issue".into(),
            kind: RewriteIssueKind::Dependency,
            owner: crate::rewrite::RewriteIssueOwner::TargetCode,
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
