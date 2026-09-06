//! Source-proven acquisition rules share the recorder-capture refresh lifecycle.
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::super::model::{RewriteHttpResponseCaptureReport, RewriteState};
use super::super::{RewriteContext, evidence, fingerprint, inventory, store::RewriteStore};
use crate::config::HttpResponseRewriteRuleConfig;

mod review;
mod rules;

#[derive(Debug, Clone)]
pub struct RewriteHttpResponseCapturePlanOptions {
    pub evidence_id: String,
    pub case_id: String,
    pub response_id: String,
    pub rule: HttpResponseRewriteRuleConfig,
    pub source_evidence: String,
    pub pattern_checked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::rewrite) struct HttpResponseCaptureSpec {
    pub case_id: String,
    pub response_id: String,
    pub response_digest: String,
    pub rule: HttpResponseRewriteRuleConfig,
    #[serde(default)]
    pub pattern_checked: bool,
}

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

pub(super) fn validate_selection(
    candidates: &[Value],
    case_id: &str,
    response_id: &str,
    rule: &HttpResponseRewriteRuleConfig,
) -> Result<String> {
    ensure!(
        rule.plugin.is_none() && !rule.pointers.is_empty(),
        "HTTP response capture requires pointers without a plugin"
    );
    ensure!(
        rule.authorities.len() == 1 && rule.methods.len() == 1,
        "plan one source-proven HTTP authority and method at a time"
    );
    let pattern = rule
        .path_pattern
        .as_deref()
        .context("HTTP response capture requires path_pattern")?;
    let mut digest = None;
    for pointer in &rule.pointers {
        let candidate = candidates.iter().find(|candidate| {
            candidate["case_id"] == case_id && candidate["response_id"] == response_id
                && candidate["pointer"] == *pointer
                && candidate["authority"] == rule.authorities[0]
                && candidate["method"] == rule.methods[0]
                && candidate["path"].as_str().is_some_and(|path| crate::path_pattern::matches_path_pattern(pattern, path))
        }).context("each pointer must identify the reported IP endpoint in the exact recorded upstream JSON response; inspect ip_capture evidence")?;
        digest = candidate["response_digest"].as_str().map(str::to_string);
    }
    digest.context("recorded response evidence has no digest")
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

pub(super) struct Plan {
    path: std::path::PathBuf,
    before: String,
    after: String,
    pub report: Value,
}

impl Plan {
    pub(super) fn build(
        target_root: &Path,
        spec: &HttpResponseCaptureSpec,
        source_revision: &str,
        source_evidence: &str,
    ) -> Result<Self> {
        ensure!(
            spec.pattern_checked,
            "HTTP response capture requires path review; rerun plan-http-response, inspect source path construction and existing rules, then submit --pattern-checked with a brief --source-evidence note"
        );
        let project_path = super::project_config(target_root);
        let mut app = crate::AppConfig::load(&project_path)?;
        ensure!(
            app.http_response_rewrite.enabled,
            "HTTP response rewriting is explicitly disabled in the recorder configuration"
        );
        let path = super::source_traffic_policy_path(target_root);
        let before = std::fs::read_to_string(&path)?;
        let mut policy = crate::config::SourceTrafficPolicyConfig::parse(&before, &path)?;
        let convergence = rules::converge(&mut app, &mut policy, &spec.rule)?;
        let after = if convergence.changed {
            policy.render()?
        } else {
            before.clone()
        };
        let identity = format!(
            "http-response-url:{}",
            fingerprint::id(&[&serde_json::to_string(&convergence.rule)?])
        );
        let rule_document =
            crate::config::source_traffic_policy::http_response::Document::from_rule(
                &convergence.rule,
            )?;
        let requested_document =
            crate::config::source_traffic_policy::http_response::Document::from_rule(&spec.rule)?;
        let replaced_documents = convergence
            .replaced_rules
            .iter()
            .map(crate::config::source_traffic_policy::http_response::Document::from_rule)
            .collect::<Result<Vec<_>>>()?;
        let report = json!({
            "kind": "http_response_url", "resource_identity": identity,
            "rules": path, "rule": rule_document, "case_id": spec.case_id,
            "requested_rule": requested_document, "pattern_checked": true,
            "reused_existing": convergence.reused_existing,
            "replaced_rules": replaced_documents,
            "response_id": spec.response_id, "response_digest": spec.response_digest,
            "source_revision": source_revision, "source_evidence": source_evidence,
            "changed": before != after, "applied": false,
            "diff": crate::config::rule_document::whole_file_diff(&path, &before, &after),
            "effect": "On the next standard recording, replace selected IPv4 URL hosts with registered synthetic hostnames. Preserve URL scheme, port, path and query; capture subsequent HTTP(S) calls for replay.",
            "recording_refresh_required": true,
            "does_not_prove": "The engine checks selectors and path coverage. Target reviews source URL consumption and dynamic path segments; source_evidence is a brief note of that choice."
        });
        Ok(Self {
            path,
            before,
            after,
            report,
        })
    }

    pub(super) fn apply(mut self) -> Result<Value> {
        ensure!(
            std::fs::read_to_string(&self.path)? == self.before,
            "source traffic policy changed after planning"
        );
        if self.before != self.after {
            crate::config::edit::write_atomic(&self.path, self.after.as_bytes())?;
        }
        self.report["applied"] = json!(true);
        Ok(self.report)
    }
}

pub(super) fn identity(spec: &HttpResponseCaptureSpec) -> String {
    fingerprint::id(&[&serde_json::to_string(spec).unwrap_or_default()])
}

#[cfg(test)]
#[path = "http_response_tests.rs"]
mod tests;
