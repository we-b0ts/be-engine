//! Bounded on-demand values from authenticated, issue-bound dependency witnesses.
use super::*;
use crate::{RewriteContext, store::RewriteStore};

pub fn query_rewrite_witness_for_scope(
    context: RewriteContext,
    scope: &RewriteWorkScope,
    witness_id: &str,
    pointer: &str,
    value_index: usize,
) -> Result<RewriteEvidenceReport> {
    let selection = traffic_rewrite_evidence::evidence::witness::WitnessQuery::new(
        witness_id,
        pointer,
        value_index,
    )?;
    let root = crate::e2e_run::resolve_project(&context.target_root)?.0;
    let state = RewriteStore::new(&root)?
        .load()?
        .context("rewrite workflow has not been initialized")?;
    let RewriteWorkScope::Api { api } = scope;
    let state = super::super::api_selector::scoped(&state, api)?;
    let scope = super::super::api_selector::work_scope(&state, api);
    let issue = state
        .active_issue
        .as_ref()
        .context("API has no current issue")?;
    super::super::worker::ensure_scope_confirmed(&state, &scope, "querying protected witness")?;
    let facts = traffic_rewrite_evidence::evidence::witness::read(&root, &state, selection)?;
    let mut report =
        super::report::selected(&root, &state, &scope, issue, "dependency_witness", facts)?;
    report.does_not_prove = vec!["A retained candidate proves observed bytes, not a successful dependency match or authorization for a rule.".into()];
    report.next_step = "Trace the selected observed difference through Source and Target code. Recorded request header names come from authenticated input; public encrypted-header placeholders do not establish absence. Use narrower pointers for unavailable large values.".into();
    Ok(report)
}
