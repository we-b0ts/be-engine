//! Diagnostic envelopes preserve assignment identity without building unrelated facts.
use super::*;
use crate::rewrite::evidence_model::RewriteEvidenceContext;

pub(super) fn context(
    root: &Path,
    state: &RewriteState,
    scope: &RewriteWorkScope,
) -> Box<RewriteEvidenceContext> {
    let scope = super::super::api_selector::canonical_scope(state, scope);
    Box::new(RewriteEvidenceContext {
        target_root: root.into(),
        workflow_id: state.workflow_id.clone(),
        revision: state.revision,
        recording_run_id: state.recording_run_id.clone(),
        delivery: crate::rewrite::review::context(root, state, &scope),
        worker: super::super::worker::dispatch_view(state, scope, None),
    })
}

/// Callers retain assignment, attempt, native identity and payload authentication.
/// This constructor only wraps their already selected diagnostic facts.
pub(super) fn selected(
    root: &Path,
    state: &RewriteState,
    scope: &RewriteWorkScope,
    issue: &RewriteIssue,
    query: &str,
    facts: Value,
) -> Result<RewriteEvidenceReport> {
    Ok(RewriteEvidenceReport {
        schema_version: 4,
        context: Some(context(root, state, scope)),
        evidence_id: format!(
            "evidence-{}",
            fingerprint::id(&[&issue.id, &serde_json::to_string(&facts)?])
                .trim_start_matches("fnv1a64:")
        ),
        issue_id: issue.id.clone(),
        query: query.into(),
        facts,
        queries: Vec::new(),
        rule_hints: Vec::new(),
        applicable_rule_planners: Vec::new(),
        does_not_prove: Vec::new(),
        next_step: String::new(),
    })
}
