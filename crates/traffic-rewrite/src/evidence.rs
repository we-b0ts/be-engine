use std::path::Path;

use anyhow::{Context, Result};
use serde_json::Value;
#[cfg(test)]
use serde_json::json;

use super::evidence_model::RewriteEvidenceReport;
use super::fingerprint;
use super::model::{RewriteIssue, RewritePhase, RewriteState};
use super::work_scope::RewriteWorkScope;
#[cfg(test)]
use crate::{E2eValueObservation, E2eValuePresence, RewriteIssueKind};

pub(crate) use traffic_rewrite_evidence::evidence::*;
mod access;
mod diagnosis;
pub(crate) mod execution;
#[cfg(test)]
mod http_requests;
mod overview;
pub(crate) mod policy_freshness;
mod redis_argument;
mod report;
mod witness;
pub use access::{query_rewrite_evidence, query_rewrite_evidence_for_scope};
pub use redis_argument::query_rewrite_redis_argument_for_scope;
pub use witness::query_rewrite_witness_for_scope;

pub(crate) fn accepts_query(state: &RewriteState, requested_id: &str) -> bool {
    state
        .active_issue
        .as_ref()
        .is_some_and(|issue| requested_id == overview::api_query_id(state, issue))
        || traffic_rewrite_evidence::evidence::accepts_query(state, requested_id)
}

pub(crate) fn query(
    root: &Path,
    state: &RewriteState,
    requested_id: &str,
) -> Result<RewriteEvidenceReport> {
    if let Some(issue) = state.active_issue.as_ref()
        && requested_id == overview::api_query_id(state, issue)
    {
        return overview::report(
            root,
            state,
            RewriteWorkScope::Api {
                api: state.api.clone(),
            },
            issue,
            requested_id,
        );
    }
    traffic_rewrite_evidence::evidence::query(
        root,
        state,
        requested_id,
        super::dependency_review::api_information,
    )
}

pub(crate) fn report_for_id(
    root: &Path,
    state: &RewriteState,
    evidence_id: &str,
) -> Option<RewriteEvidenceReport> {
    traffic_rewrite_evidence::evidence::report_for_id(
        root,
        state,
        evidence_id,
        super::dependency_review::api_information,
    )
}

/// Recognize a current overview without promoting it to planning authority.
pub(super) fn current_overview_matches(root: &Path, state: &RewriteState, id: &str) -> bool {
    // Excluded/externally repaired slices retain their issue for later recovery,
    // but have no current implementation dispatch to put in an overview.
    if state.phase != RewritePhase::ImplementationRequired
        || super::regression_scope::is_skipped(state, &state.api)
    {
        return false;
    }
    state.active_issue.as_ref().is_some_and(|issue| {
        query(root, state, &overview::api_query_id(state, issue))
            .is_ok_and(|report| report.evidence_id == id)
    })
}

#[cfg(test)]
#[path = "evidence/response_body_tests.rs"]
mod response_body_tests;
#[cfg(test)]
#[path = "evidence/tests.rs"]
mod tests;

#[cfg(test)]
use traffic_rewrite_evidence::evidence::query_catalog::query_kinds;
