//! Build and apply Source-proven HTTP response capture rules.
use crate::{config::HttpResponseRewriteRuleConfig, execution_identity as fingerprint};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::path::Path;
use traffic_rewrite_model::rewrite::HttpResponseCaptureSpec;
pub mod rules;
pub fn validate_selection(
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

pub struct Plan {
    path: std::path::PathBuf,
    before: String,
    after: String,
    pub report: Value,
}

impl Plan {
    pub fn build(
        target_root: &Path,
        spec: &HttpResponseCaptureSpec,
        source_revision: &str,
        source_evidence: &str,
    ) -> Result<Self> {
        ensure!(
            spec.pattern_checked,
            "HTTP response capture requires path review; rerun plan-http-response, inspect source path construction and existing rules, then submit --pattern-checked with a brief --source-evidence note"
        );
        let project_path = target_root.join(".traffic-e2e/project.yaml");
        let mut app = crate::AppConfig::load(&project_path)?;
        ensure!(
            app.http_response_rewrite.enabled,
            "HTTP response rewriting is explicitly disabled in the recorder configuration"
        );
        let path = crate::config::resolve_unified_policy_path(&project_path)?;
        let before = std::fs::read_to_string(&path)?;
        let mut policy = crate::config::SourceTrafficPolicyConfig::parse(&before, &path)?;
        let convergence = rules::converge(&mut app, &mut policy, &spec.rule)?;
        let after = if convergence.changed {
            crate::config::native_policy::render_updated(
                &before,
                &policy,
                &crate::policy::Proof {
                    source: format!(
                        "Source response {} in case {} at {} (digest {})",
                        spec.response_id, spec.case_id, source_revision, spec.response_digest
                    ),
                    fact: source_evidence.into(),
                },
            )?
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

    pub fn apply(mut self) -> Result<Value> {
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

pub fn identity(spec: &HttpResponseCaptureSpec) -> String {
    fingerprint::id(&[&serde_json::to_string(spec).unwrap_or_default()])
}
