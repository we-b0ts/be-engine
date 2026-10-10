use std::path::Path;

use anyhow::Result;
use serde_json::json;

use super::super::model::{RewriteIssue, RewriteState};
use super::super::work_scope::RewriteWorkScope;
use super::super::{fingerprint, worker};
use super::RewriteEvidenceReport;

const QUERY_OVERVIEW: &str = "overview";

pub(super) fn query_id(
    state: &RewriteState,
    scope: &RewriteWorkScope,
    issue: &RewriteIssue,
) -> String {
    match scope {
        RewriteWorkScope::Api { .. } => super::query_id(state, issue, QUERY_OVERVIEW),
    }
}

pub(super) fn api_query_id(state: &RewriteState, issue: &RewriteIssue) -> String {
    super::query_id(state, issue, QUERY_OVERVIEW)
}

pub(super) fn report(
    target_root: &Path,
    state: &RewriteState,
    scope: RewriteWorkScope,
    issue: &RewriteIssue,
    requested_id: &str,
) -> Result<RewriteEvidenceReport> {
    let scope = super::super::api_selector::canonical_scope(state, &scope);
    let mut queries = match &scope {
        RewriteWorkScope::Api { .. }
            if issue.kind != crate::rewrite::RewriteIssueKind::TargetQuality =>
        {
            super::commands(target_root, state)
        }
        RewriteWorkScope::Api { .. } => Vec::new(),
    };
    let methods = match &scope {
        RewriteWorkScope::Api { api } => super::super::api_selector::members(state, &api.parse()?),
    };
    let mut method_issues = Vec::new();
    for api in &methods {
        let Ok(selected) = super::super::inventory::scoped(state, Some(&api.parse()?)) else {
            // Awaiting refresh/system-repair inventory may lack a retained AI
            // slice. Its method contract is still present in method_apis.
            continue;
        };
        if let Some(method_issue) = selected.active_issue.as_ref() {
            let method_queries =
                if method_issue.kind != crate::rewrite::RewriteIssueKind::TargetQuality {
                    super::commands(target_root, &selected)
                } else {
                    Vec::new()
                };
            if api != &state.api {
                queries.extend(method_queries.clone());
            }
            method_issues
                .push(json!({"api": api, "issue": method_issue, "queries": method_queries}));
        }
    }
    let facts = json!({ "work_scope": scope, "issue": issue, "method_apis": methods,
        "method_issues": method_issues });
    let evidence_id = format!(
        "evidence-{}",
        fingerprint::id(&[requested_id, &serde_json::to_string(&facts)?])
            .trim_start_matches("fnv1a64:")
    );
    Ok(RewriteEvidenceReport {
        schema_version: 4,
        context: Some(Box::new(super::super::evidence_model::RewriteEvidenceContext {
            target_root: target_root.to_path_buf(),
            workflow_id: state.workflow_id.clone(),
            revision: state.revision,
            recording_run_id: state.recording_run_id.clone(),
            review: crate::rewrite::review::context(target_root, state, &scope),
            worker: worker::dispatch_view(state, scope.clone(), None),
        })),
        evidence_id,
        issue_id: issue.id.clone(),
        query: QUERY_OVERVIEW.to_string(),
        facts,
        queries,
        applicable_rule_planners: Vec::new(),
        rule_hints: Vec::new(),
        does_not_prove: vec![
            "Issue ownership and possible causes are investigation guidance, not a proven root cause."
                .to_string(),
        ],
        next_step: if issue.kind == crate::rewrite::RewriteIssueKind::TargetQuality {
            "Read context.review.integrated_findings, fix the assigned quality finding, then run context.review.check for this dispatch before handoff.".to_string()
        } else { match scope {
            RewriteWorkScope::Api { .. } =>
                "Inspect this issue and execute the relevant returned queries before tracing source and target behavior.",
        }.to_string() },
    })
}

#[cfg(test)]
mod tests;
