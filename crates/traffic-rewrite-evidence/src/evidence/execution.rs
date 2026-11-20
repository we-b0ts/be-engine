//! Issue-bound execution evidence and guidance distinguish unused calls from rejections.
use super::*;

pub const KIND: &str = "execution_failures";

pub fn is_unconsumed(failure: &Value) -> bool {
    failure["kind"] == "case_no_progress"
        || failure["failures"]
            .as_array()
            .is_some_and(|rows| rows.iter().any(|row| row["kind"] == "case_no_progress"))
}

pub fn has_unconsumed_dependencies(failures: &[Value]) -> bool {
    failures.iter().any(is_unconsumed)
}

pub fn has_rejected_dependencies(failures: &[Value]) -> bool {
    failures.iter().any(|failure| {
        failure["kind"] == "dependency_unmatched"
            || !is_unconsumed(failure)
            || failure["failures"]
                .as_array()
                .is_some_and(|rows| rows.iter().any(|row| row["kind"] != "case_no_progress"))
    })
}

pub fn guidance(failures: &[Value]) -> String {
    let unconsumed = has_unconsumed_dependencies(failures);
    let rejected = has_rejected_dependencies(failures);
    let cause = if unconsumed {
        "Recorded Case dependencies remain unconsumed. Inspect execution_failures[].failures[].waiting.references and pending_source_dependencies, then implement or correct the corresponding Target calls and asynchronous continuation against Source behavior. The idle duration records when Replay ended this wait."
    } else {
        "Replay rejected a Target dependency request that did not match recorded evidence. Inspect execution_failures[].failures and target_event_index, then correct the corresponding Target request or prove its Source-compatible contract."
    };
    let mixed = if unconsumed && rejected {
        " Other execution_failures include rejected Target requests; inspect their target_event_index separately."
    } else {
        ""
    };
    format!(
        "{cause}{mixed} Follow execution_failures_query for omitted cases and dependency_diagnosis.command for dependency evidence. An observed primary HTTP status does not certify asynchronous completion. Other cases may have independent response failures."
    )
}

pub fn id(state: &RewriteState, issue: &RewriteIssue, offset: usize) -> String {
    if offset == 0 {
        super::query_id(state, issue, KIND)
    } else {
        super::query_id(state, issue, &format!("{KIND}_page_{offset}"))
    }
}

pub fn parse(state: &RewriteState, issue: &RewriteIssue, query: &str) -> Option<usize> {
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

pub fn command(root: &Path, state: &RewriteState, issue: &RewriteIssue, offset: usize) -> Value {
    json!(super::super::action::command(
        root,
        vec!["evidence-detail".into(), id(state, issue, offset)],
        vec![]
    ))
}

pub fn attach(
    root: &Path,
    state: &RewriteState,
    issue: &RewriteIssue,
    execution: &Value,
    facts: &mut Value,
) {
    facts["execution_failures"] = execution["execution_failures"].clone();
    facts["execution_failures_summary"] = execution["execution_failures_summary"].clone();
    facts["execution_failures_query"] = command(root, state, issue, 0);
    facts["case_selection"] = execution["case_selection"].clone();
}

pub fn facts(
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
