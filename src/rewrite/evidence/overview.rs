use std::path::Path;

use anyhow::Result;
use serde_json::json;

use super::super::model::{RewriteCommandSpec, RewriteIssue, RewriteState};
use super::super::process_output_model::RewriteWorkScope;
use super::super::{action, fingerprint, worker};
use super::RewriteEvidenceReport;

const QUERY_OVERVIEW: &str = "overview";

pub(in crate::rewrite) fn command(
    target_root: &Path,
    state: &RewriteState,
    scope: &RewriteWorkScope,
    issue: &RewriteIssue,
) -> RewriteCommandSpec {
    action::command(
        target_root,
        vec!["evidence".to_string(), query_id(state, scope, issue)],
        Vec::new(),
    )
}

pub(super) fn query_id(
    state: &RewriteState,
    scope: &RewriteWorkScope,
    issue: &RewriteIssue,
) -> String {
    match scope {
        RewriteWorkScope::Api { .. } => super::query_id(state, issue, QUERY_OVERVIEW),
        RewriteWorkScope::ProcessOutput { .. } => format!(
            "evq-{}-overview",
            fingerprint::id(&[
                "rewrite-process-output-evidence-v1",
                &state.workflow_id,
                &state.recording_run_id,
                &scope.binding_key(),
                &serde_json::to_string(issue).expect("rewrite issue is serializable"),
            ])
            .trim_start_matches("fnv1a64:")
        ),
    }
}

pub(super) fn api_query_id(state: &RewriteState, issue: &RewriteIssue) -> String {
    super::query_id(state, issue, QUERY_OVERVIEW)
}

pub(super) fn query_process_output(
    target_root: &Path,
    state: &RewriteState,
    requested_id: &str,
) -> Result<Option<RewriteEvidenceReport>> {
    for item in &state.process_outputs.inventory {
        let Some(issue) = &item.issue else { continue };
        let scope = RewriteWorkScope::ProcessOutput {
            id: item.id.clone(),
        };
        if query_id(state, &scope, issue) == requested_id {
            worker::ensure_scope_confirmed(state, &scope, "querying evidence")?;
            return report(target_root, state, scope, issue, requested_id).map(Some);
        }
    }
    Ok(None)
}

pub(super) fn report(
    target_root: &Path,
    state: &RewriteState,
    scope: RewriteWorkScope,
    issue: &RewriteIssue,
    requested_id: &str,
) -> Result<RewriteEvidenceReport> {
    let queries = match &scope {
        RewriteWorkScope::Api { .. } => super::commands(target_root, state),
        RewriteWorkScope::ProcessOutput { .. } => Vec::new(),
    };
    let facts = json!({ "work_scope": scope, "issue": issue });
    let evidence_id = format!(
        "evidence-{}",
        fingerprint::id(&[requested_id, &serde_json::to_string(&facts)?])
            .trim_start_matches("fnv1a64:")
    );
    Ok(RewriteEvidenceReport {
        schema_version: 3,
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
        next_step: match scope {
            RewriteWorkScope::Api { .. } =>
                "Inspect this issue and execute the relevant returned queries before tracing source and target behavior.",
            RewriteWorkScope::ProcessOutput { .. } =>
                "Inspect facts.issue.comparison_observation and trace the source and target startup/output path; no API evidence queries apply.",
        }.to_string(),
    })
}

#[cfg(test)]
mod tests;
