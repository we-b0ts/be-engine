//! Source-proven acquisition rules share the recorder-capture refresh lifecycle.
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde_json::Value;
#[cfg(test)]
use serde_json::json;

#[cfg(test)]
use super::super::fingerprint;
use super::super::model::{RewriteHttpResponseCaptureReport, RewriteState};
use super::super::{RewriteContext, evidence, inventory, store::RewriteStore};
use crate::config::HttpResponseRewriteRuleConfig;

mod review;
pub(super) use traffic_rewrite_rules::rewrite::capture::{Plan, identity};
use traffic_rewrite_rules::rewrite::capture::{rules, validate_selection};

#[derive(Debug, Clone)]
pub struct RewriteHttpResponseCapturePlanOptions {
    pub evidence_id: String,
    pub case_id: String,
    pub response_id: String,
    pub rule: HttpResponseRewriteRuleConfig,
    pub source_evidence: String,
    pub pattern_checked: bool,
}

pub use traffic_rewrite_model::rewrite::recorder_capture::http_response::HttpResponseCaptureSpec;

pub fn plan_rewrite_http_response_capture(
    context: RewriteContext,
    options: RewriteHttpResponseCapturePlanOptions,
) -> Result<RewriteHttpResponseCaptureReport> {
    let (target_root, _) = crate::e2e_run::resolve_project(&context.target_root)?;
    let store = RewriteStore::new(&target_root)?;
    let _lock = store.lock()?;
    let mut state = store
        .load()?
        .context("rewrite workflow has not been initialized")?;
    inventory::initialize_legacy(&mut state);
    let api = inventory::api_for_evidence_id(&target_root, &state, &options.evidence_id)
        .context("HTTP response capture evidence is stale or belongs to no API")?;
    super::super::worker::ensure_api_confirmed(&state, &api, "planning HTTP response capture")?;
    let report =
        inventory::with_slice_mut(&mut state, &api, |state| plan(&target_root, state, options))?;
    store.save(&state)?;
    Ok(report)
}

pub(super) fn plan(
    target_root: &Path,
    state: &mut RewriteState,
    mut options: RewriteHttpResponseCapturePlanOptions,
) -> Result<RewriteHttpResponseCaptureReport> {
    let candidates = current_candidates(target_root, state, &options.evidence_id)?;
    ensure!(
        state
            .active_issue
            .as_ref()
            .and_then(|issue| issue.recorder_capture_diagnosis.as_ref())
            .is_some_and(|reported| reported["origin"] == "http-response"),
        "confirm the IP came from an HTTP response through route --cause unrecorded-ip --ip-origin http-response"
    );
    let digest = validate_selection(
        &candidates,
        &options.case_id,
        &options.response_id,
        &options.rule,
    )?;
    options.rule.name = options.rule.authorities[0].clone();
    options.rule.source_evidence = options.source_evidence.clone();
    if !options.pattern_checked {
        let report = review::report(target_root, state, &options, &candidates)?;
        // A fresh review must not leave an earlier HTTP plan available to apply.
        if state
            .recorder_capture_plan
            .as_ref()
            .is_some_and(|plan| plan.http_response.is_some())
        {
            state.recorder_capture_plan = None;
            state.bump();
        }
        return Ok(report);
    }
    let spec = HttpResponseCaptureSpec {
        case_id: options.case_id,
        response_id: options.response_id,
        response_digest: digest,
        rule: options.rule,
        pattern_checked: options.pattern_checked,
    };
    let plan = super::plan_with_capture_requirement(
        target_root,
        state,
        super::RewriteRecorderCapturePlanOptions {
            evidence_id: options.evidence_id,
            endpoint: spec.rule.authorities[0].clone(),
            source_evidence: options.source_evidence,
        },
        false,
        Some(spec),
    )?;
    Ok(RewriteHttpResponseCaptureReport::Planned { plan })
}

fn current_candidates(
    target_root: &Path,
    state: &RewriteState,
    evidence_id: &str,
) -> Result<Vec<Value>> {
    for command in evidence::commands(target_root, state) {
        let Ok(report) = evidence::query(target_root, state, &command.query_id) else {
            continue;
        };
        if report.evidence_id == evidence_id {
            return Ok(report
                .facts
                .get("http_response_url_candidates")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default());
        }
    }
    anyhow::bail!("HTTP response capture evidence changed; query ip_capture evidence again")
}

pub(super) fn revalidate(
    target_root: &Path,
    state: &RewriteState,
    spec: &HttpResponseCaptureSpec,
) -> Result<()> {
    let facts = super::super::response_url_evidence::facts(target_root, state)?;
    let candidates = facts
        .get("http_response_url_candidates")
        .and_then(Value::as_array)
        .context("HTTP response candidates missing")?;
    let digest = validate_selection(candidates, &spec.case_id, &spec.response_id, &spec.rule)?;
    ensure!(
        digest == spec.response_digest,
        "recorded upstream response changed after planning; rerun evidence and plan"
    );
    Ok(())
}

#[cfg(test)]
#[path = "http_response_tests.rs"]
mod tests;
