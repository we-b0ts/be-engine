//! Exact selected arguments from independent unmatched requests need no invented Source pair.
use super::*;
use crate::{RewriteContext, store::RewriteStore};

pub fn query_rewrite_redis_argument_for_scope(
    context: RewriteContext,
    scope: &RewriteWorkScope,
    case_id: &str,
    event_index: usize,
    argument_index: usize,
    pointer: Option<&str>,
) -> Result<RewriteEvidenceReport> {
    let selection = traffic_rewrite_evidence::evidence::redis_argument::RedisArgumentQuery::new(
        case_id,
        event_index,
        argument_index,
        pointer,
    )?;
    let root = crate::e2e_run::resolve_project(&context.target_root)?.0;
    let state = RewriteStore::new(&root)?
        .load()?
        .context("rewrite workflow has not been initialized")?;
    let RewriteWorkScope::Api { api } = scope;
    let state = super::super::api_selector::scoped(&state, api)?;
    let scope = super::super::api_selector::work_scope(&state, api);
    super::super::worker::ensure_scope_confirmed(
        &state,
        &scope,
        "querying protected Redis argument",
    )?;
    let issue = state
        .active_issue
        .as_ref()
        .context("API has no current issue")?;
    let facts = traffic_rewrite_evidence::evidence::redis_argument::read(&root, &state, selection)?;
    let mut report =
        super::report::selected(&root, &state, &scope, issue, "redis_target_argument", facts)?;
    report.does_not_prove=vec!["Observed Target bytes do not prove a Source counterpart, a successful match, task origin or permission for a rule.".into()];
    report.next_step="Trace the selected argument through Target and Source code. Select one argument and a narrower JSON pointer when a value exceeds 4096 bytes; no plaintext payload is written to artifacts.".into();
    Ok(report)
}
